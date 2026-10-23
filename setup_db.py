#!/usr/bin/env python3
"""
setup_db.py  --  Provision the MySQL database for the Secure Banking System.

What this script does (idempotent -- safe to run multiple times):
  1. Connects to MySQL and creates the `secure_banking` database if absent.
  2. Runs db.init_db() to create all five tables (IF NOT EXISTS) and seed
     demo users / accounts via the application's own code path.
  3. Adds the `ip_address` column to Audit_Log if it is missing (migration).
  4. Creates / replaces the three stored procedures from sql/procedures.sql:
       deposit, withdraw, transfer
  5. Removes legacy audit-writing triggers. Audit entries and alerts are owned
     by the Python transaction layer so every entry uses the hash chain exactly once.
  6. Creates a least-privilege MySQL user 'bank_app'@'localhost' and grants
     only the required privileges per table (principle of least privilege).
     The bank_app password
     must be set in .env as DB_APP_PASSWORD.  Root is used ONLY for this
     provisioning step; the running application uses bank_app.
  7. Runs diagnostic SELECTs to confirm the database is properly populated.

Usage:
    python setup_db.py

Configuration is read from .env (git-ignored).  See .env.example for keys.
DB_TYPE must be set to 'mysql' for this script to connect.
"""

import os
import sys
import pymysql
import config
import db

# ---------------------------------------------------------------------------
# Helper: raw PyMySQL connection (autocommit=True for DDL)
# ---------------------------------------------------------------------------


def _raw_conn():
    """Open a raw PyMySQL connection to secure_banking with autocommit."""
    return pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        autocommit=True,
        charset="utf8mb4",
    )


DB_APP_USER = "bank_app"
DB_APP_HOST = "localhost"


# ---------------------------------------------------------------------------
# Step 1 -- Ensure the database exists
# ---------------------------------------------------------------------------


def ensure_database():
    print(f"\n[1/6] Ensuring database '{config.DB_NAME}' exists ...")
    admin = pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        autocommit=True,
        charset="utf8mb4",
    )
    try:
        with admin.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{config.DB_NAME}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        print(f"    OK  Database `{config.DB_NAME}` is present.")
    finally:
        admin.close()


# ---------------------------------------------------------------------------
# Step 2 -- Create tables and seed demo data via db.init_db()
# ---------------------------------------------------------------------------


def init_schema():
    print("\n[2/6] Running db.init_db() to create tables and seed demo data ...")
    db.init_db()
    # Only the provisioning account may run MySQL schema migrations.
    conn = db.get_connection()
    try:
        db._migrate_mysql_alert_workflow(conn)
    finally:
        conn.close()
    print("    OK  All five tables created (IF NOT EXISTS) and demo data seeded.")


# ---------------------------------------------------------------------------
# Step 3 -- Column migration: add ip_address to Audit_Log if missing
# ---------------------------------------------------------------------------


def migrate_audit_log():
    print("\n[3/6] Checking Audit_Log.ip_address column ...")
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'Audit_Log' "
                "  AND COLUMN_NAME = 'ip_address'",
                (config.DB_NAME,),
            )
            if cur.fetchone()[0] == 0:
                cur.execute(
                    "ALTER TABLE Audit_Log ADD COLUMN ip_address VARCHAR(45) NULL"
                )
                print("    OK  ip_address column added to Audit_Log.")
            else:
                print("    OK  ip_address column already present (no action needed).")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Step 4 -- Stored procedures (from sql/procedures.sql logic)
# ---------------------------------------------------------------------------


def create_stored_procedures():
    print("\n[4/6] Creating stored procedures: deposit, withdraw, transfer ...")
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:

            # Drop existing versions
            for name in ("deposit", "withdraw", "transfer"):
                cur.execute(f"DROP PROCEDURE IF EXISTS `{name}`")

            cur.execute("""
            CREATE PROCEDURE deposit(IN acc_id INT, IN amt DECIMAL(15,2))
            BEGIN
                UPDATE Accounts SET balance = balance + amt WHERE account_id = acc_id;
                INSERT INTO Transactions (from_account, to_account, amount, txn_type)
                VALUES (NULL, acc_id, amt, 'deposit');
            END
            """)

            cur.execute("""
            CREATE PROCEDURE withdraw(IN acc_id INT, IN amt DECIMAL(15,2))
            BEGIN
                IF (SELECT balance FROM Accounts WHERE account_id = acc_id) >= amt THEN
                    UPDATE Accounts SET balance = balance - amt WHERE account_id = acc_id;
                    INSERT INTO Transactions (from_account, to_account, amount, txn_type)
                    VALUES (acc_id, NULL, amt, 'withdraw');
                ELSE
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance';
                END IF;
            END
            """)

            cur.execute("""
            CREATE PROCEDURE transfer(IN from_acc INT, IN to_acc INT, IN amt DECIMAL(15,2))
            BEGIN
                IF (SELECT balance FROM Accounts WHERE account_id = from_acc) >= amt THEN
                    UPDATE Accounts SET balance = balance - amt WHERE account_id = from_acc;
                    UPDATE Accounts SET balance = balance + amt WHERE account_id = to_acc;
                    INSERT INTO Transactions (from_account, to_account, amount, txn_type)
                    VALUES (from_acc, to_acc, amt, 'transfer');
                ELSE
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance';
                END IF;
            END
            """)

            cur.execute(
                "SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES "
                "WHERE ROUTINE_SCHEMA = %s AND ROUTINE_TYPE = 'PROCEDURE'",
                (config.DB_NAME,),
            )
            procs = [r[0] for r in cur.fetchall()]
        print(f"    OK  Stored procedures: {procs}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Step 5 -- Triggers (from sql/triggers.sql logic, corrected for MySQL 8)
# ---------------------------------------------------------------------------


def create_triggers():
    print("\n[5/6] Removing legacy audit-writing triggers ...")
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:

            for name in ("after_failed_login", "after_transaction", "after_user_login"):
                cur.execute(f"DROP TRIGGER IF EXISTS `{name}`")

            # Intentionally leave no triggers that write security records.
            # Python owns the transaction boundary and the audit hash chain.
        print(
            "    OK  Legacy triggers removed; Python transaction layer is authoritative."
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Step 6 -- Verification: show tables and seeded data
# ---------------------------------------------------------------------------


def verify():
    print("\n[6/6] Verification ...")
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:

            cur.execute("SHOW TABLES")
            tables = [r[0] for r in cur.fetchall()]
            print(f"    Tables in `{config.DB_NAME}`: {tables}")

            cur.execute(
                "SELECT u.user_id, u.name, u.email, u.role, a.balance "
                "FROM Users u JOIN Accounts a ON u.user_id = a.user_id "
                "ORDER BY u.user_id"
            )
            rows = cur.fetchall()
            print("    Seeded users & balances:")
            for r in rows:
                print(
                    f"      user_id={r[0]}  {r[1]:<20} {r[2]:<30} role={r[3]}  "
                    f"balance=Rs {float(r[4]):,.2f}"
                )

            cur.execute(
                "SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES "
                "WHERE ROUTINE_SCHEMA = %s AND ROUTINE_TYPE = 'PROCEDURE'",
                (config.DB_NAME,),
            )
            procs = [r[0] for r in cur.fetchall()]
            print(f"    Stored procedures: {procs}")

            cur.execute(
                "SELECT TRIGGER_NAME FROM INFORMATION_SCHEMA.TRIGGERS "
                "WHERE TRIGGER_SCHEMA = %s",
                (config.DB_NAME,),
            )
            trigs = [r[0] for r in cur.fetchall()]
            print(f"    Triggers: {trigs}")

    finally:
        conn.close()

    # Also confirm db.get_connection() returns MySQL
    conn2 = db.get_connection()
    engine = "MySQL" if db.is_mysql_connection(conn2) else "SQLite"
    conn2.close()
    print(f"\n    db.get_connection() engine: {engine}")
    if engine != "MySQL":
        print(
            "    WARNING: application is NOT using MySQL -- check your .env DB_TYPE value."
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Step 6 -- Least-privilege app user: bank_app
# ---------------------------------------------------------------------------


def create_app_user():
    """
    Create 'bank_app'@'localhost' with the minimum privileges the application
    needs at runtime (ISO 27001:2022 A.8.18 Privileged Access Rights / A.5.15
    Principle of Least Privilege).

    Grants are table-specific. Audit_Log is append-only: it receives SELECT and
    INSERT but never UPDATE or DELETE.
    No DROP, ALTER, GRANT, DELETE, or administrative privileges.

    The bank_app password is read from DB_APP_PASSWORD in .env.
    Root credentials are used ONLY during this provisioning step.
    """
    app_password = os.environ.get("DB_APP_PASSWORD", "")
    if not app_password:
        print(
            "\n[6/7] Skipping bank_app user creation: DB_APP_PASSWORD not set in .env.\n"
            "      Set DB_APP_PASSWORD=<strong_password> in your .env and re-run to\n"
            "      create the least-privilege application user."
        )
        return

    print(
        f"\n[6/7] Creating least-privilege MySQL user '{DB_APP_USER}'@'{DB_APP_HOST}' ..."
    )
    admin = pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        autocommit=True,
        charset="utf8mb4",
    )
    try:
        with admin.cursor() as cur:
            # Create user if not exists (idempotent)
            cur.execute(
                f"CREATE USER IF NOT EXISTS '{DB_APP_USER}'@'{DB_APP_HOST}' "
                f"IDENTIFIED BY %s",
                (app_password,),
            )
            # Update password in case it changed
            cur.execute(
                f"ALTER USER '{DB_APP_USER}'@'{DB_APP_HOST}' IDENTIFIED BY %s",
                (app_password,),
            )
            cur.execute(
                f"REVOKE ALL PRIVILEGES, GRANT OPTION ON `{config.DB_NAME}`.* "
                f"FROM '{DB_APP_USER}'@'{DB_APP_HOST}'"
            )
            for table, privileges in config.APP_TABLE_GRANTS.items():
                cur.execute(
                    f"GRANT {', '.join(privileges)} ON `{config.DB_NAME}`.`{table}` "
                    f"TO '{DB_APP_USER}'@'{DB_APP_HOST}'"
                )
            cur.execute("FLUSH PRIVILEGES")

            # Verify
            cur.execute(f"SHOW GRANTS FOR '{DB_APP_USER}'@'{DB_APP_HOST}'")
            grants = [r[0] for r in cur.fetchall()]
        print(f"    OK  User '{DB_APP_USER}'@'{DB_APP_HOST}' created/updated.")
        for g in grants:
            print(f"       {g}")
        print(
            f"\n    ACTION REQUIRED: Update your .env to switch the app to bank_app:\n"
            f"      DB_USER={DB_APP_USER}\n"
            f"      DB_PASSWORD=<same value as DB_APP_PASSWORD>\n"
            f"    Keep root credentials only in DB_ADMIN_USER / DB_ADMIN_PASSWORD\n"
            f"    (or remove them from .env entirely after provisioning)."
        )
    finally:
        admin.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if config.DB_TYPE != "mysql":
        print(
            f"ERROR: DB_TYPE is '{config.DB_TYPE}' in your .env.\n"
            "       Set DB_TYPE=mysql and fill in DB_PASSWORD before running this script."
        )
        sys.exit(1)

    print("=" * 60)
    print("  Secure Banking System -- MySQL Database Setup")
    print(f"  Host: {config.DB_HOST}:{config.DB_PORT}  DB: {config.DB_NAME}")
    print("=" * 60)

    try:
        ensure_database()
        init_schema()
        migrate_audit_log()
        create_stored_procedures()
        create_triggers()
        create_app_user()
        verify()
        print("\n" + "=" * 60)
        print("  Setup complete! MySQL database is ready.")
        print("=" * 60)
    except Exception as exc:
        print(f"\nERROR: {exc}")
        sys.exit(1)
