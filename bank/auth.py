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
# Generated randomly at startup; never accepted as a real credential or stored.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(32))


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
    user_id: int, max_attempts: int = MAX_FAILED_LOGINS
) -> None:
    """
    Increment failed_attempts and lock the account if the threshold is reached.
    Both UPDATEs are atomic inside one transaction.
    """
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE Users SET failed_attempts = failed_attempts + 1"
            " WHERE user_id = ?",
            (user_id,),
        )
        conn.execute(
            "UPDATE Users SET is_locked = 1"
            " WHERE user_id = ? AND failed_attempts >= ?",
            (user_id, max_attempts),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


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

    increment_failed_attempts(user["user_id"], max_attempts=MAX_FAILED_LOGINS)
    attempts_now = get_failed_attempts(user["user_id"])
    audit.log_action(user["user_id"], f"Failed login attempt #{attempts_now}")

    if attempts_now >= MAX_FAILED_LOGINS:
        alerts.raise_alert(
            user["user_id"],
            "Brute Force",
            f"Account locked after {attempts_now} failed attempts",
            severity="high",
        )

    return None, GENERIC_LOGIN_ERROR


def change_password(user_id: int, old_password: str, new_password: str) -> tuple:
    """
    Change a user's password with old-password verification, complexity check,
    reuse prevention, atomic update, and audit logging.
    Returns (True, None) on success, (False, reason_string) on failure.
    """
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
        conn.execute("BEGIN")
        try:
            conn.execute(
                "UPDATE Users SET password_hash = ? WHERE user_id = ?",
                (new_hash, user_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        audit.log_action(user_id, "Password changed successfully")
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
        conn.execute("BEGIN")
        if not db._is_admin(conn, admin_user_id):
            conn.execute("ROLLBACK")
            return False
        user = conn.execute(
            "SELECT * FROM Users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not user:
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Users SET is_locked = 0, failed_attempts = 0 WHERE user_id = ?",
            (user_id,),
        )
        conn.execute("COMMIT")
        audit.log_action(
            admin_user_id,
            f"Admin unlocked account for user #{user_id} ({user['email']})",
        )
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_locked_users() -> list:
    """Return all currently locked user accounts."""
    conn = db.get_connection()
    try:
        return conn.execute(
            "SELECT user_id, name, email, failed_attempts, created_at "
            "FROM Users WHERE is_locked = 1"
        ).fetchall()
    finally:
        conn.close()
