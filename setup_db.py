#!/usr/bin/env python3
"""
setup_db.py  --  Provision the MySQL database for the Secure Banking System.

What this script does (idempotent -- safe to run multiple times):
  1. Connects to MySQL and creates the configured database if absent.
  2. Runs db.init_db() to create all five tables (IF NOT EXISTS) and apply migrations.
  3. Adds the `ip_address` column to Audit_Log if it is missing (migration).
  4. Creates / replaces the three stored procedures from sql/procedures.sql:
       deposit, withdraw, transfer
  5. Removes legacy audit-writing triggers so Python owns the audit hash chain.
  6. Creates a least-privilege MySQL user 'bank_app'@'localhost' when
     DB_APP_PASSWORD is set in environment variables.
  7. Runs diagnostic SELECTs to confirm the database schema is ready.

Usage:
    python setup_db.py
    python scripts/seed_demo.py   # optional explicit demo seeding
"""

import os
import re
import sys

import mysql.connector
from bank import config, db

DB_APP_USER = "bank_app"
DB_APP_HOST = "localhost"
_VALID_IDENT = re.compile(r"^[A-Za-z0-9_]+$")
_VALID_PRIVS = {"SELECT", "INSERT", "UPDATE"}


def _validate_identifier(name: str, label: str) -> str:
    if not name or not _VALID_IDENT.fullmatch(name):
        raise ValueError(f"Invalid SQL identifier for {label}: {name!r}")
    return name


def _raw_conn():
    """Open a raw mysql-connector-python connection to DB_NAME with autocommit."""
    mysql_cfg = config.get_mysql_config()
    return mysql.connector.connect(
        host=mysql_cfg["host"],
        port=mysql_cfg["port"],
        user=mysql_cfg["user"],
        password=mysql_cfg["password"],
        database=mysql_cfg["database"],
        autocommit=True,
        charset="utf8mb4",
    )


# ---------------------------------------------------------------------------
# Step 1 -- Ensure the database exists
# ---------------------------------------------------------------------------


def ensure_database():
    mysql_cfg = config.get_mysql_config()
    db_name = _validate_identifier(mysql_cfg["database"], "DB_NAME")
    print(f"\n[1/6] Ensuring database '{db_name}' exists ...")
    admin = mysql.connector.connect(
        host=mysql_cfg["host"],
        port=mysql_cfg["port"],
        user=mysql_cfg["user"],
        password=mysql_cfg["password"],
        autocommit=True,
        charset="utf8mb4",
    )
    try:
        with admin.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        print(f"    OK  Database `{db_name}` is present.")
    finally:
        admin.close()


# ---------------------------------------------------------------------------
# Step 2 -- Create tables via db.init_db()
# ---------------------------------------------------------------------------


def init_schema():
    print("\n[2/6] Running db.init_db() to create tables and apply migrations ...")
    db.init_db()
    conn = db.get_connection()
    try:
        db._migrate_mysql_alert_workflow(conn)
    finally:
        conn.close()
    print("    OK  All five tables created (IF NOT EXISTS).")


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
# Step 4 -- Stored procedures
# ---------------------------------------------------------------------------


def create_stored_procedures():
    print("\n[4/6] Creating stored procedures: deposit, withdraw, transfer ...")
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            for name in ("deposit", "withdraw", "transfer"):
                cur.execute(f"DROP PROCEDURE IF EXISTS `{name}`")

            cur.execute("""
            CREATE PROCEDURE deposit(IN acc_id INT, IN amt DECIMAL(12,2))
            BEGIN
                UPDATE Accounts SET balance = balance + amt WHERE account_id = acc_id;
                INSERT INTO Transactions (from_account, to_account, amount, txn_type)
                VALUES (NULL, acc_id, amt, 'deposit');
            END
            """)

            cur.execute("""
            CREATE PROCEDURE withdraw(IN acc_id INT, IN amt DECIMAL(12,2))
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
            CREATE PROCEDURE transfer(IN from_acc INT, IN to_acc INT, IN amt DECIMAL(12,2))
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
# Step 5 -- Remove legacy audit-writing triggers
# ---------------------------------------------------------------------------


def create_triggers():
    print("\n[5/6] Removing legacy audit-writing triggers ...")
    conn = _raw_conn()
    try:
        with conn.cursor() as cur:
            for name in ("after_failed_login", "after_transaction", "after_user_login"):
                cur.execute(f"DROP TRIGGER IF EXISTS `{name}`")
        print(
            "    OK  Legacy triggers removed; Python transaction layer is authoritative."
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Step 6 -- Verification
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
            print(f"    Users & balances present: {len(rows)}")
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
# Least-privilege app user: bank_app
# ---------------------------------------------------------------------------


def create_app_user():
    """
    Create 'bank_app'@'localhost' with the minimum privileges the application
    needs at runtime when DB_APP_PASSWORD is set.
    """
    app_password = os.environ.get("DB_APP_PASSWORD", "")
    if not app_password:
        print(
            "\n[6/7] Skipping bank_app user creation: DB_APP_PASSWORD not set.\n"
            "      Set DB_APP_PASSWORD in environment/.env and re-run to create\n"
            "      the least-privilege application user."
        )
        return

    mysql_cfg = config.get_mysql_config()
    db_name = _validate_identifier(mysql_cfg["database"], "DB_NAME")
    print(
        f"\n[6/7] Creating least-privilege MySQL user '{DB_APP_USER}'@'{DB_APP_HOST}' ..."
    )
    admin = mysql.connector.connect(
        host=mysql_cfg["host"],
        port=mysql_cfg["port"],
        user=mysql_cfg["user"],
        password=mysql_cfg["password"],
        autocommit=True,
        charset="utf8mb4",
    )
    try:
        with admin.cursor() as cur:
            cur.execute(
                "CREATE USER IF NOT EXISTS %s@%s IDENTIFIED BY %s",
                (DB_APP_USER, DB_APP_HOST, app_password),
            )
            cur.execute(
                "ALTER USER %s@%s IDENTIFIED BY %s",
                (DB_APP_USER, DB_APP_HOST, app_password),
            )
            cur.execute(
                "REVOKE ALL PRIVILEGES, GRANT OPTION FROM %s@%s",
                (DB_APP_USER, DB_APP_HOST),
            )
            for table, privileges in config.APP_TABLE_GRANTS.items():
                safe_table = _validate_identifier(table, "table")
                if not set(privileges).issubset(_VALID_PRIVS):
                    raise ValueError(f"Unexpected privileges for {table}: {privileges}")
                cur.execute(
                    f"GRANT {', '.join(privileges)} ON `{db_name}`.`{safe_table}` "
                    "TO %s@%s",
                    (DB_APP_USER, DB_APP_HOST),
                )
            cur.execute("FLUSH PRIVILEGES")

            cur.execute("SHOW GRANTS FOR %s@%s", (DB_APP_USER, DB_APP_HOST))
            grants = [r[0] for r in cur.fetchall()]
        print(f"    OK  User '{DB_APP_USER}'@'{DB_APP_HOST}' created/updated.")
        for g in grants:
            print(f"       {g}")
        print(
            f"\n    ACTION REQUIRED: Update your .env to switch the app to {DB_APP_USER}:\n"
            f"      DB_USER={DB_APP_USER}\n"
            f"      DB_PASSWORD=<value of DB_APP_PASSWORD>"
        )
    finally:
        admin.close()


if __name__ == "__main__":
    if config.DB_TYPE != "mysql":
        print(
            f"ERROR: DB_TYPE is '{config.DB_TYPE}'.\n"
            "       Set DB_TYPE=mysql and configure MySQL environment variables before running."
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
        print("  Run `python scripts/seed_demo.py` to seed demo users if needed.")
        print("=" * 60)
    except Exception as exc:
        print(f"\nERROR: {exc}")
        sys.exit(1)
