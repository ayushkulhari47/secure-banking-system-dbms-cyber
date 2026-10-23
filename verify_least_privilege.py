#!/usr/bin/env python3
"""Verify the MySQL runtime account cannot perform administrative writes.

Run this after setup_db.py has provisioned the database and .env has been
switched to DB_USER=bank_app. The script intentionally makes two failed
attempts and rolls back any unexpected success.
"""

import db


def _expect_denied(label: str, statement: str) -> None:
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        conn.execute(statement)
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        finally:
            conn.close()
        print(f"PASS: {label} denied ({type(exc).__name__})")
        return
    conn.execute("ROLLBACK")
    conn.close()
    raise AssertionError(f"FAIL: {label} was permitted")


def main() -> None:
    if db.DB_TYPE != "mysql":
        raise SystemExit(
            "Set DB_TYPE=mysql and use the bank_app runtime account first."
        )
    conn = db.get_connection()
    is_mysql = db.is_mysql_connection(conn)
    conn.close()
    if not is_mysql:
        raise SystemExit("Configured connection is not MySQL.")
    _expect_denied(
        "Audit_Log update",
        "UPDATE Audit_Log SET action = 'tampered' WHERE log_id = 1",
    )
    _expect_denied("table drop", "DROP TABLE Transactions")
    print("Least-privilege verification passed.")


if __name__ == "__main__":
    main()
