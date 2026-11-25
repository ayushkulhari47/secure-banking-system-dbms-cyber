"""
bank/audit.py -- Tamper-evident, append-only audit logging with SHA-256 hash chaining.
"""

import hashlib
from datetime import datetime, timezone

from bank import db

GENESIS_HASH = "0" * 64


def _format_log_time(value) -> str:
    """Normalize a stored log_time value into deterministic UTC string format."""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def compute_audit_hash(previous_hash: str, user_id, action: str, log_time: str) -> str:
    """
    Compute cryptographic SHA-256 hash for an audit log entry.
    Format: SHA-256(previous_hash || user_id || action || log_time).
    """
    payload = f"{previous_hash}|{user_id}|{action}|{_format_log_time(log_time)}".encode(
        "utf-8"
    )
    return hashlib.sha256(payload).hexdigest()


def _append_audit_row(conn, user_id, action: str) -> None:
    """
    Append one hash-chained audit entry using an active database connection/transaction.
    Fails closed if the latest existing audit row has a missing or invalid hash.
    """
    lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
    last_row = conn.execute(
        "SELECT log_id, user_id, action, log_time, previous_hash, entry_hash "
        "FROM Audit_Log ORDER BY log_id DESC LIMIT 1" + lock_clause
    ).fetchone()

    if last_row is None:
        prev_hash = GENESIS_HASH
    else:
        if not last_row["previous_hash"] or not last_row["entry_hash"]:
            raise ValueError(
                f"Audit log entry #{last_row['log_id']} is missing hash chain fields."
            )
        expected_last = compute_audit_hash(
            last_row["previous_hash"],
            last_row["user_id"],
            last_row["action"],
            last_row["log_time"],
        )
        if last_row["entry_hash"] != expected_last:
            raise ValueError(
                f"Audit log entry #{last_row['log_id']} failed hash verification."
            )
        prev_hash = last_row["entry_hash"]

    log_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entry_hash = compute_audit_hash(prev_hash, user_id, action, log_time)

    conn.execute(
        "INSERT INTO Audit_Log (user_id, action, log_time, previous_hash, entry_hash)"
        " VALUES (?, ?, ?, ?, ?)",
        (user_id, action, log_time, prev_hash, entry_hash),
    )


def log_action(user_id, action: str, conn=None) -> None:
    """
    Insert a row into Audit_Log using cryptographic hash chaining.

    When `conn` is provided, the entry is written within the caller's active
    connection and transaction so audit logs commit or roll back atomically
    with the enclosing operation. When `conn` is None, opens and commits its
    own transaction for standalone/non-financial audit events.
    """
    if conn is not None:
        _append_audit_row(conn, user_id, action)
        return

    own_conn = db.get_connection()
    try:
        db.begin_write_transaction(own_conn)
        _append_audit_row(own_conn, user_id, action)
        own_conn.execute("COMMIT")
    except Exception:
        db.safe_rollback(own_conn)
        raise
    finally:
        own_conn.close()


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
