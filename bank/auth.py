"""
bank/auth.py -- Credential hashing, verification, lockout counters, and user account management.
"""

import secrets
import bcrypt

from bank import alerts, audit, db, security
from bank.config import BCRYPT_ROUNDS, MAX_FAILED_LOGINS

GENERIC_LOGIN_ERROR = "Invalid email or password."


def hash_password(plaintext: str) -> str:
    """
    Hash a password with bcrypt using a random per-password salt.
    """
    return bcrypt.hashpw(
        plaintext.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode()


# Used only to equalize the work performed for an unknown email during login.
# Generated at runtime from random bytes with BCRYPT_ROUNDS; never stored or accepted.
DUMMY_PASSWORD_HASH = bcrypt.hashpw(
    secrets.token_bytes(32), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
).decode()


def get_user_by_email(email: str):
    """Return the Users row for the given email, or None."""
    conn = db.get_connection()
    try:
        return conn.execute("SELECT * FROM Users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash (timing-safe, fail-closed).
    """
    try:
        return bcrypt.checkpw(plaintext.encode(), stored_hash.encode())
    except Exception:
        return False


def increment_failed_attempts(
    user_id: int, max_attempts: int = MAX_FAILED_LOGINS, conn=None
) -> int:
    """
    Atomically increment failed_attempts, lock the account when reaching
    max_attempts, and raise one high-severity Brute Force alert on lockout.
    Returns the updated failed_attempts count.
    """

    def _apply(active_conn) -> int:
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(active_conn) else ""
        row = active_conn.execute(
            "SELECT failed_attempts, is_locked FROM Users WHERE user_id = ?"
            + lock_clause,
            (user_id,),
        ).fetchone()
        if row is None:
            return 0

        was_locked = bool(row["is_locked"])
        new_attempts = int(row["failed_attempts"]) + 1
        now_locked = was_locked or (new_attempts >= max_attempts)

        active_conn.execute(
            "UPDATE Users SET failed_attempts = ?, is_locked = ? WHERE user_id = ?",
            (new_attempts, 1 if now_locked else 0, user_id),
        )
        if not was_locked and now_locked:
            alerts.raise_alert(
                user_id,
                "Brute Force",
                f"Account locked after {new_attempts} failed attempts",
                severity="high",
                conn=active_conn,
            )
        return new_attempts

    if conn is not None:
        return _apply(conn)

    own_conn = db.get_connection()
    try:
        db.begin_write_transaction(own_conn)
        attempts = _apply(own_conn)
        own_conn.execute("COMMIT")
        return attempts
    except Exception:
        db.safe_rollback(own_conn)
        raise
    finally:
        own_conn.close()


def reset_failed_attempts(user_id: int) -> None:
    """Clear the failed-attempts counter after a successful login."""
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE Users SET failed_attempts = 0 WHERE user_id = ?", (user_id,)
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_failed_attempts(user_id: int) -> int:
    """Return the current failed_attempts value for a user."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT failed_attempts FROM Users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row["failed_attempts"] if row else 0
    finally:
        conn.close()


def authenticate(email: str, password: str) -> tuple:
    """
    Authenticate a user with constant-work bcrypt verification and uniform error output.

    Always performs a bcrypt check (using DUMMY_PASSWORD_HASH for unknown emails
    and the stored password_hash for locked accounts) and returns
    (user_row, None) on success or (None, GENERIC_LOGIN_ERROR) on any failure.
    """
    if security.detect_sqli(email):
        audit.log_action(None, "SQL injection pattern detected during login")
        alerts.raise_alert(
            None,
            "SQL Injection Signal",
            "Suspicious login input pattern detected",
            severity="high",
        )

    user = get_user_by_email(email)

    if user is None:
        verify_password(password, DUMMY_PASSWORD_HASH)
        audit.log_action(None, "Failed login -- invalid credentials")
        return None, GENERIC_LOGIN_ERROR

    password_matches = verify_password(password, user["password_hash"])

    if user["is_locked"]:
        audit.log_action(user["user_id"], "Login attempt on locked account")
        return None, GENERIC_LOGIN_ERROR

    if password_matches:
        reset_failed_attempts(user["user_id"])
        audit.log_action(user["user_id"], "Successful login")
        return user, None

    conn = db.get_connection()
    try:
        db.begin_write_transaction(conn)
        attempts_now = increment_failed_attempts(
            user["user_id"], max_attempts=MAX_FAILED_LOGINS, conn=conn
        )
        audit.log_action(
            user["user_id"], f"Failed login attempt #{attempts_now}", conn=conn
        )
        conn.execute("COMMIT")
    except Exception:
        db.safe_rollback(conn)
        raise
    finally:
        conn.close()

    return None, GENERIC_LOGIN_ERROR


def change_password(
    user_id: int,
    old_password: str,
    new_password: str,
    actor_user_id: int = None,
) -> tuple:
    """
    Change a user's password with ownership check, old-password verification,
    complexity check, reuse prevention, atomic update, and audit logging.
    Returns (True, None) on success, (False, reason_string) on failure.
    """
    if actor_user_id is None or actor_user_id != user_id:
        raise PermissionError("Users may only change their own password.")

    conn = db.get_connection()
    try:
        user = conn.execute(
            "SELECT password_hash FROM Users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not user:
            return False, "User not found."

        if not verify_password(old_password, user["password_hash"]):
            audit.log_action(
                user_id, "Failed password change -- incorrect current password"
            )
            return False, "Current password is incorrect."

        ok, violations = security.password_meets_policy(new_password)
        if not ok:
            return False, "New password does not meet policy: " + "; ".join(violations)

        if verify_password(new_password, user["password_hash"]):
            return False, "New password must be different from the current password."

        new_hash = hash_password(new_password)
        db.begin_write_transaction(conn)
        try:
            conn.execute(
                "UPDATE Users SET password_hash = ? WHERE user_id = ?",
                (new_hash, user_id),
            )
            audit.log_action(user_id, "Password changed successfully", conn=conn)
            conn.execute("COMMIT")
        except Exception:
            db.safe_rollback(conn)
            raise

        return True, None
    finally:
        conn.close()


def unlock_user(user_id: int, admin_user_id: int = None) -> bool:
    """
    Admin unlock function for locked user accounts (ISO 27001 A.9.4.2 Corrective Control).
    Resets failed_attempts to 0, clears is_locked flag, and logs the action.
    """
    conn = db.get_connection()
    try:
        db.begin_write_transaction(conn)
        if not db._is_admin(conn, admin_user_id):
            db.safe_rollback(conn)
            return False
        user = conn.execute(
            "SELECT * FROM Users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not user:
            db.safe_rollback(conn)
            return False
        conn.execute(
            "UPDATE Users SET is_locked = 0, failed_attempts = 0 WHERE user_id = ?",
            (user_id,),
        )
        audit.log_action(
            admin_user_id,
            f"Admin unlocked account for user #{user_id} ({user['email']})",
            conn=conn,
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        db.safe_rollback(conn)
        raise
    finally:
        conn.close()


def get_locked_users(admin_user_id: int = None) -> list:
    """Return all currently locked user accounts. Admin use only."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        return conn.execute(
            "SELECT user_id, name, email, failed_attempts, created_at "
            "FROM Users WHERE is_locked = 1"
        ).fetchall()
    finally:
        conn.close()
