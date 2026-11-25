"""
bank/alerts.py -- Security alert creation and three-state remediation workflow.
"""

from datetime import datetime, timezone

from bank import audit, db


def raise_alert(
    user_id: int,
    alert_type: str,
    description: str,
    severity: str = "medium",
) -> None:
    """Insert a security alert and commit it before returning."""
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        cursor = conn.execute(
            "INSERT INTO Alerts (user_id, alert_type, description, severity)"
            " VALUES (?, ?, ?, ?)",
            (user_id, alert_type, description, severity),
        )
        conn.execute("COMMIT")
        return cursor.lastrowid
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def review_alert(alert_id: int, admin_user_id: int, note: str = "") -> bool:
    """Move an open alert to reviewed, with admin attribution."""
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        if not db._is_admin(conn, admin_user_id):
            conn.execute("ROLLBACK")
            return False
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "UPDATE Alerts SET status = 'reviewed', reviewed_by = ?, reviewed_at = ?, "
            "resolution_note = ? WHERE alert_id = ? AND status = 'open'",
            (admin_user_id, now, note, alert_id),
        )
        if getattr(cursor, "rowcount", 1) != 1:
            conn.execute("ROLLBACK")
            return False
        conn.execute("COMMIT")
        audit.log_action(admin_user_id, f"Admin reviewed alert #{alert_id}")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def close_alert(alert_id: int, admin_user_id: int, note: str = "") -> bool:
    """Close a reviewed alert; an open alert must be reviewed first."""
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        if not db._is_admin(conn, admin_user_id):
            conn.execute("ROLLBACK")
            return False
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            "UPDATE Alerts SET status = 'closed', closed_by = ?, closed_at = ?, "
            "resolution_note = CASE WHEN ? = '' THEN resolution_note ELSE ? END "
            "WHERE alert_id = ? AND status = 'reviewed'",
            (admin_user_id, now, note, note, alert_id),
        )
        if getattr(cursor, "rowcount", 1) != 1:
            conn.execute("ROLLBACK")
            return False
        conn.execute("COMMIT")
        audit.log_action(admin_user_id, f"Admin closed alert #{alert_id}")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def resolve_alert(alert_id: int, admin_user_id: int = None) -> bool:
    """
    Backward-compatible helper: review and close an alert in one call.
    """
    if review_alert(alert_id, admin_user_id):
        return close_alert(alert_id, admin_user_id)
    return False


def get_all_alerts(admin_user_id: int = None) -> list:
    """Return all alerts. Admin use only."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        return conn.execute("SELECT * FROM Alerts ORDER BY alert_time DESC").fetchall()
    finally:
        conn.close()


def get_open_alerts(admin_user_id: int = None) -> list:
    """Return all open (unresolved) security alerts."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        return conn.execute(
            "SELECT * FROM Alerts WHERE status = 'open' ORDER BY alert_time DESC"
        ).fetchall()
    finally:
        conn.close()

