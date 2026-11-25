"""
bank/audit.py -- Tamper-evident audit logging with SHA-256 hash chaining.
"""

import hashlib
from datetime import datetime, timezone

from bank import db

GENESIS_HASH = "0" * 64


def compute_audit_hash(previous_hash: str, user_id, action: str, log_time: str) -> str:
    """
    Compute cryptographic SHA-256 hash for an audit log entry.
    Format: SHA-256(previous_hash || user_id || action || log_time).
    """
    payload = f"{previous_hash}|{user_id}|{action}|{log_time}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def log_action(user_id, action: str) -> None:
    """
    Insert a row into Audit_Log using cryptographic hash chaining.
    user_id may be None for pre-authentication events such as unknown-email
    login attempts.
    """
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        last_row = conn.execute(
            "SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1"
            + lock_clause
        ).fetchone()
        prev_hash = (
            last_row["entry_hash"]
            if last_row and last_row["entry_hash"]
            else GENESIS_HASH
        )
        log_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        entry_hash = compute_audit_hash(prev_hash, user_id, action, log_time)

        conn.execute(
            "INSERT INTO Audit_Log (user_id, action, log_time, previous_hash, entry_hash)"
            " VALUES (?, ?, ?, ?, ?)",
            (user_id, action, log_time, prev_hash, entry_hash),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def verify_audit_log_integrity(admin_user_id: int = None) -> tuple:
    """
    Verify the cryptographic integrity of the entire Audit_Log table. Admin use only.
    Returns (True, None) if intact, or (False, compromised_log_id) if tampering is detected.
    """
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            raise PermissionError("Only administrators may verify audit log integrity.")
        rows = conn.execute("SELECT * FROM Audit_Log ORDER BY log_id ASC").fetchall()
        expected_prev = GENESIS_HASH
        for row in rows:
            if not row["previous_hash"] or not row["entry_hash"]:
                return False, row["log_id"]
            if row["previous_hash"] != expected_prev:
                return False, row["log_id"]
            calc_hash = compute_audit_hash(
                row["previous_hash"], row["user_id"], row["action"], row["log_time"]
            )
            if row["entry_hash"] != calc_hash:
                return False, row["log_id"]
            expected_prev = row["entry_hash"]
        return True, None
    finally:
        conn.close()


def get_audit_log(admin_user_id: int = None, limit: int = 50) -> list:
    """Return the most recent audit log entries. Admin use only."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        return conn.execute(
            "SELECT * FROM Audit_Log ORDER BY log_id DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()

