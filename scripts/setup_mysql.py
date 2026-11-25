"""
scripts/setup_mysql.py - Provision and verify MySQL database and SQL definitions.
"""

import os
import re
import sys

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mysql.connector
from bank import config, db

_VALID_IDENT = re.compile(r"^[A-Za-z0-9_]+$")


def main():
    mysql_cfg = config.get_mysql_config()
    db_name = mysql_cfg["database"]
    if not _VALID_IDENT.fullmatch(db_name):
        raise ValueError(f"Invalid database name: {db_name!r}")

    print(
        f"Connecting to MySQL at {mysql_cfg['host']}:{mysql_cfg['port']} as {mysql_cfg['user']}..."
    )

    # 1. Connect without database to ensure DB exists
    conn = mysql.connector.connect(
        host=mysql_cfg["host"],
        port=mysql_cfg["port"],
        user=mysql_cfg["user"],
        password=mysql_cfg["password"],
        autocommit=True,
        charset="utf8mb4",
    )
    with conn.cursor() as cur:
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        print(f"Database `{db_name}` verified/created.")
    conn.close()

    # 2. Connect to the target database
    conn = mysql.connector.connect(
        host=mysql_cfg["host"],
        port=mysql_cfg["port"],
        user=mysql_cfg["user"],
        password=mysql_cfg["password"],
        database=db_name,
        autocommit=True,
        charset="utf8mb4",
    )
    cur = conn.cursor()

    # 3. Ensure schema tables exist (Users, Accounts, Transactions, Audit_Log, Alerts)
    db.init_db()
    print("Application schema verified.")

    # 4. Ensure Audit_Log has ip_address column for triggers compatibility
    cur.execute("SHOW COLUMNS FROM Audit_Log LIKE 'ip_address'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE Audit_Log ADD COLUMN ip_address VARCHAR(45) NULL")
        print("Added ip_address column to Audit_Log for trigger compatibility.")

    # 5. Stored Procedures from sql/procedures.sql
    for proc in ["deposit", "withdraw", "transfer"]:
        cur.execute(f"DROP PROCEDURE IF EXISTS `{proc}`")

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
    print("Stored procedures created: deposit, withdraw, transfer.")

    # 6. Install tamper-resistant audit triggers and drop legacy unhashed triggers
    for trig in db.LEGACY_MYSQL_TRIGGERS:
        cur.execute(f"DROP TRIGGER IF EXISTS `{trig}`")
    for trig_name, trig_sql in db.MYSQL_AUDIT_TRIGGERS:
        cur.execute(f"DROP TRIGGER IF EXISTS `{trig_name}`")
        cur.execute(trig_sql)
    print(
        "Triggers created: "
        + ", ".join(name for name, _ in db.MYSQL_AUDIT_TRIGGERS)
        + "."
    )

    # 7. Verification: Run diagnostic query
    cur.execute("""
    SELECT u.name, u.email, u.role, a.balance
    FROM Users u
    JOIN Accounts a ON u.user_id = a.user_id
    """)
    rows = cur.fetchall()
    print("Verification Query (Users & Balances in MySQL):")
    for r in rows:
        print(f"  - User: {r[0]} ({r[1]}), Role: {r[2]}, Balance: {r[3]}")

    conn.close()
    print("MySQL database setup & verification complete!")


if __name__ == "__main__":
    main()
