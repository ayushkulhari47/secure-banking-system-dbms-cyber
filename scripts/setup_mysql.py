"""
scripts/setup_mysql.py - Provision and verify MySQL database and SQL definitions.
"""

import os
import sys

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pymysql
import config


def main():
    print(
        f"Connecting to MySQL at {config.DB_HOST}:{config.DB_PORT} as {config.DB_USER}..."
    )

    # 1. Connect without database to ensure DB exists
    conn = pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        autocommit=True,
    )
    with conn.cursor() as cur:
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{config.DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        print(f"Database `{config.DB_NAME}` verified/created.")
    conn.close()

    # 2. Connect to the secure_banking database
    conn = pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        autocommit=True,
    )
    cur = conn.cursor()

    # 3. Ensure schema tables exist (Users, Accounts, Transactions, Audit_Log, Alerts)
    import db

    db.init_db()
    print("Application schema & seed verified.")

    # 4. Ensure Audit_Log has ip_address column for triggers compatibility
    cur.execute("SHOW COLUMNS FROM Audit_Log LIKE 'ip_address'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE Audit_Log ADD COLUMN ip_address VARCHAR(45) NULL")
        print("Added ip_address column to Audit_Log for trigger compatibility.")

    # 5. Stored Procedures from sql/procedures.sql
    for proc in ["deposit", "withdraw", "transfer"]:
        cur.execute(f"DROP PROCEDURE IF EXISTS `{proc}`")

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
    print("Stored procedures created: deposit, withdraw, transfer.")

    # 6. Triggers from sql/triggers.sql
    for trig in ["after_failed_login", "after_transaction", "after_user_login"]:
        cur.execute(f"DROP TRIGGER IF EXISTS `{trig}`")

    # In MySQL, self-table update in AFTER UPDATE causes error 1442; BEFORE UPDATE is the valid MySQL syntax
    cur.execute("""
    CREATE TRIGGER after_failed_login
    BEFORE UPDATE ON Users
    FOR EACH ROW
    BEGIN
        IF NEW.failed_attempts >= 3 THEN
            SET NEW.is_locked = 1;
            INSERT INTO Alerts (user_id, alert_type, description)
            VALUES (NEW.user_id, 'Brute Force', 'Account locked after 3 failed login attempts');
        END IF;
    END
    """)

    cur.execute("""
    CREATE TRIGGER after_transaction
    AFTER INSERT ON Transactions
    FOR EACH ROW
    BEGIN
        INSERT INTO Audit_Log (user_id, action, ip_address)
        SELECT a.user_id, CONCAT('Transaction of ', NEW.amount, ' type: ', NEW.txn_type), '0.0.0.0'
        FROM Accounts a
        WHERE a.account_id = NEW.from_account;

        IF NEW.amount > 50000 THEN
            INSERT INTO Alerts (user_id, alert_type, description)
            SELECT a.user_id, 'Large Transaction', CONCAT('Suspicious large transaction of ', NEW.amount)
            FROM Accounts a
            WHERE a.account_id = NEW.from_account;
        END IF;
    END
    """)

    cur.execute("""
    CREATE TRIGGER after_user_login
    AFTER UPDATE ON Users
    FOR EACH ROW
    BEGIN
        IF NEW.failed_attempts = 0 AND OLD.failed_attempts > 0 THEN
            INSERT INTO Audit_Log (user_id, action, ip_address)
            VALUES (NEW.user_id, 'Successful Login', '0.0.0.0');
        END IF;
    END
    """)
    print("Triggers created: after_failed_login, after_transaction, after_user_login.")

    # 7. Verification: Run diagnostic queries from sql/queries.sql
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
