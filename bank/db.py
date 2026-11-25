"""
bank/db.py -- Database connections, schema definitions, initialization, and migrations.
"""

import hashlib
import os
import sqlite3

try:
    import mysql.connector

    HAS_MYSQL_CONNECTOR = True
except ImportError:
    mysql = None
    HAS_MYSQL_CONNECTOR = False

from bank import config

# ---------------------------------------------------------------------------
# Connection & Database Engine Abstraction
# ---------------------------------------------------------------------------

DB_TYPE = config.DB_TYPE
DB_PATH = (
    config.DB_PATH
    if os.path.isabs(config.DB_PATH)
    else os.path.join(config.BASE_DIR, config.DB_PATH)
)


class MySQLCursorWrapper:
    """Wraps a mysql-connector-python cursor to provide an interface matching sqlite3."""

    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def close(self):
        self._cursor.close()


class MySQLConnectionWrapper:
    """
    Wraps a mysql-connector-python connection so SQL execution works consistently
    across SQLite and MySQL:
      - Automatically maps '?' placeholders to '%s'
      - Intercepts BEGIN, COMMIT, and ROLLBACK to control transactions
      - Ignores SQLite-specific PRAGMAs
      - Provides dict-like row access via dictionary=True buffered cursors
    """

    def __init__(self, raw_conn):
        self._conn = raw_conn

    @property
    def in_transaction(self) -> bool:
        """Return True when a MySQL transaction is currently active."""
        return bool(self._conn.in_transaction)

    def execute(self, sql: str, params=()):
        sql_clean = sql.strip()
        upper_sql = sql_clean.upper()

        if upper_sql in {"BEGIN", "BEGIN IMMEDIATE"}:
            if not self._conn.in_transaction:
                self._conn.start_transaction()
            return None
        if upper_sql == "COMMIT":
            self._conn.commit()
            return None
        if upper_sql == "ROLLBACK":
            self._conn.rollback()
            return None
        if upper_sql.startswith("PRAGMA"):
            return None

        converted_sql = sql.replace("?", "%s")
        cursor = self._conn.cursor(dictionary=True, buffered=True)
        cursor.execute(converted_sql, params)
        return MySQLCursorWrapper(cursor)

    def executescript(self, script: str):
        statements = script.split(";")
        for stmt in statements:
            stmt = stmt.strip()
            if stmt:
                self.execute(stmt)

    def close(self):
        self._conn.close()


def _sqlite_sha256(value) -> str:
    """Compute SHA-256 hex digest for SQLite audit trigger payloads."""
    if value is None:
        raise ValueError("Cannot compute SHA-256 of NULL audit payload.")
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _get_sqlite_connection(path: str = None) -> sqlite3.Connection:
    target_path = path or DB_PATH
    conn = sqlite3.connect(target_path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.create_function("sha256_hex", 1, _sqlite_sha256, deterministic=True)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_mysql_connection():
    """Open and return a wrapped mysql-connector-python connection."""
    if not HAS_MYSQL_CONNECTOR:
        raise RuntimeError(
            "mysql-connector-python package is not installed. "
            "Run: pip install mysql-connector-python"
        )
    mysql_cfg = config.get_mysql_config()
    raw_conn = mysql.connector.connect(
        host=mysql_cfg["host"],
        port=mysql_cfg["port"],
        user=mysql_cfg["user"],
        password=mysql_cfg["password"],
        database=mysql_cfg["database"],
        autocommit=False,
        charset="utf8mb4",
    )
    return MySQLConnectionWrapper(raw_conn)


def get_connection():
    """
    Open and return a database connection for the configured engine.
    A configured MySQL connection failure is fatal and never falls back to SQLite.
    """
    if DB_TYPE == "mysql":
        return get_mysql_connection()

    if DB_TYPE != "sqlite":
        raise ValueError(
            f"Unsupported DB_TYPE={DB_TYPE!r}; expected 'sqlite' or 'mysql'."
        )

    return _get_sqlite_connection()


def is_mysql_connection(conn) -> bool:
    """Return True if conn wraps a MySQL connection."""
    return isinstance(conn, MySQLConnectionWrapper)


def begin_write_transaction(conn) -> None:
    """Start an immediate/locked write transaction for the active database engine."""
    if is_mysql_connection(conn):
        conn.execute("BEGIN")
    else:
        conn.execute("BEGIN IMMEDIATE")


def safe_rollback(conn) -> None:
    """Roll back an active transaction safely without raising if none is active."""
    try:
        if getattr(conn, "in_transaction", True):
            conn.execute("ROLLBACK")
    except Exception:
        pass


def _is_admin(conn, user_id: int) -> bool:
    """Enforce privileged operations at the data layer, not only in the CLI."""
    if user_id is None:
        return False
    row = conn.execute(
        "SELECT role FROM Users WHERE user_id = ?", (user_id,)
    ).fetchone()
    return bool(row and row["role"] == "admin")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS Users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    email           TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'user'
                            CHECK(role IN ('admin','user')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    is_locked       INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS Accounts (
    account_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL UNIQUE REFERENCES Users(user_id),
    balance    DECIMAL(12,2) NOT NULL DEFAULT 0.00
                       CHECK(balance >= 0 AND ROUND(balance, 2) = balance),
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS Transactions (
    txn_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account INTEGER REFERENCES Accounts(account_id),
    to_account   INTEGER REFERENCES Accounts(account_id),
    amount       DECIMAL(12,2) NOT NULL
                         CHECK(amount > 0 AND ROUND(amount, 2) = amount),
    txn_type     TEXT    NOT NULL
                         CHECK(txn_type IN ('deposit','withdraw','transfer')),
    status       TEXT    NOT NULL DEFAULT 'completed'
                         CHECK(status IN ('completed','pending','rejected')),
    txn_time     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS Audit_Log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    action        TEXT NOT NULL,
    log_time      TEXT NOT NULL DEFAULT (datetime('now')),
    previous_hash TEXT,
    entry_hash    TEXT,
    ip_address    TEXT
);

CREATE TABLE IF NOT EXISTS Alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES Users(user_id),
    alert_type  TEXT    NOT NULL,
    description TEXT,
    severity    TEXT    NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high')),
    status      TEXT    NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','reviewed','closed')),
    alert_time  TEXT    NOT NULL DEFAULT (datetime('now')),
    reviewed_by INTEGER REFERENCES Users(user_id),
    reviewed_at TEXT,
    closed_by   INTEGER REFERENCES Users(user_id),
    closed_at   TEXT,
    resolution_note TEXT
);

CREATE TRIGGER IF NOT EXISTS after_accounts_balance_update
AFTER UPDATE OF balance ON Accounts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Audit_Log chain is corrupted or missing hash fields')
    WHERE EXISTS (SELECT 1 FROM Audit_Log)
      AND (
        (SELECT previous_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1) IS NULL
        OR (SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1) IS NULL
        OR LENGTH((SELECT previous_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)) != 64
        OR LENGTH((SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)) != 64
        OR (SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1) != sha256_hex(
            (SELECT previous_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
            || '|' || COALESCE(CAST((SELECT user_id FROM Audit_Log ORDER BY log_id DESC LIMIT 1) AS TEXT), 'None')
            || '|' || (SELECT action FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
            || '|' || (SELECT log_time FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
        )
      );

    INSERT INTO Audit_Log (user_id, action, log_time, previous_hash, entry_hash)
    SELECT
        v.user_id,
        v.action,
        v.log_time,
        v.prev_hash,
        sha256_hex(v.prev_hash || '|' || v.user_id || '|' || v.action || '|' || v.log_time)
    FROM (
        SELECT
            NEW.user_id AS user_id,
            'Account #' || NEW.account_id || ' balance updated: Rs'
            || printf('%.2f', OLD.balance) || ' -> Rs' || printf('%.2f', NEW.balance) AS action,
            datetime('now') AS log_time,
            CASE
                WHEN NOT EXISTS (SELECT 1 FROM Audit_Log)
                THEN '0000000000000000000000000000000000000000000000000000000000000000'
                ELSE (SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
            END AS prev_hash
    ) AS v;
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
BEFORE UPDATE ON Audit_Log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Audit_Log is append-only: UPDATE is prohibited');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
BEFORE DELETE ON Audit_Log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Audit_Log is append-only: DELETE is prohibited');
END;
"""


MYSQL_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS Users (
    user_id         INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    email           VARCHAR(100) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            ENUM('admin','user') NOT NULL DEFAULT 'user',
    failed_attempts INT NOT NULL DEFAULT 0,
    is_locked       TINYINT(1) NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Accounts (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL UNIQUE,
    balance    DECIMAL(12,2) NOT NULL DEFAULT 0.00,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    CHECK (balance >= 0)
);

CREATE TABLE IF NOT EXISTS Transactions (
    txn_id       INT AUTO_INCREMENT PRIMARY KEY,
    from_account INT NULL,
    to_account   INT NULL,
    amount       DECIMAL(12,2) NOT NULL,
    txn_type     ENUM('deposit','withdraw','transfer') NOT NULL,
    status       ENUM('completed','pending','rejected') NOT NULL DEFAULT 'completed',
    txn_time     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_account) REFERENCES Accounts(account_id),
    FOREIGN KEY (to_account) REFERENCES Accounts(account_id),
    CHECK (amount > 0)
);

CREATE TABLE IF NOT EXISTS Audit_Log (
    log_id        INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NULL,
    action        VARCHAR(255) NOT NULL,
    log_time      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    previous_hash VARCHAR(64) NULL,
    entry_hash    VARCHAR(64) NULL,
    ip_address    VARCHAR(45) NULL,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

CREATE TABLE IF NOT EXISTS Alerts (
    alert_id    INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NULL,
    alert_type  VARCHAR(100) NOT NULL,
    description TEXT NULL,
    severity    ENUM('low','medium','high') NOT NULL DEFAULT 'medium',
    status      ENUM('open','reviewed','closed') NOT NULL DEFAULT 'open',
    alert_time  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    closed_by   INT NULL,
    closed_at   DATETIME NULL,
    resolution_note TEXT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);
"""


LEGACY_MYSQL_TRIGGERS = (
    "after_failed_login",
    "after_transaction",
    "after_user_login",
)

MYSQL_AUDIT_TRIGGERS = (
    (
        "after_accounts_balance_update",
        """
        CREATE TRIGGER after_accounts_balance_update
        AFTER UPDATE ON Accounts
        FOR EACH ROW
        BEGIN
            DECLARE v_cnt INT DEFAULT 0;
            DECLARE v_prev_uid INT DEFAULT NULL;
            DECLARE v_prev_act VARCHAR(255) DEFAULT '';
            DECLARE v_prev_time_str VARCHAR(19) DEFAULT '';
            DECLARE v_prev_prev VARCHAR(64) DEFAULT NULL;
            DECLARE v_prev_hash VARCHAR(64) DEFAULT NULL;
            DECLARE v_log_time VARCHAR(19) DEFAULT '';
            DECLARE v_action VARCHAR(255) DEFAULT '';
            DECLARE v_entry_hash VARCHAR(64) DEFAULT '';

            SELECT COUNT(*) INTO v_cnt FROM Audit_Log;
            IF v_cnt = 0 THEN
                SET v_prev_hash = REPEAT('0', 64);
            ELSE
                SELECT user_id, action, DATE_FORMAT(log_time, '%Y-%m-%d %H:%i:%s'), previous_hash, entry_hash
                INTO v_prev_uid, v_prev_act, v_prev_time_str, v_prev_prev, v_prev_hash
                FROM Audit_Log
                ORDER BY log_id DESC
                LIMIT 1
                FOR UPDATE;

                IF v_prev_prev IS NULL OR v_prev_hash IS NULL OR CHAR_LENGTH(v_prev_prev) <> 64 OR CHAR_LENGTH(v_prev_hash) <> 64 THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log chain is corrupted or missing hash fields';
                END IF;

                IF v_prev_hash <> LOWER(SHA2(CONCAT(v_prev_prev, '|', COALESCE(CAST(v_prev_uid AS CHAR), 'None'), '|', v_prev_act, '|', v_prev_time_str), 256)) THEN
                    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log hash verification failed';
                END IF;
            END IF;

            SET v_log_time = DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s');
            SET v_action = CONCAT('Account #', NEW.account_id, ' balance updated: Rs', CAST(OLD.balance AS CHAR), ' -> Rs', CAST(NEW.balance AS CHAR));
            SET v_entry_hash = LOWER(SHA2(CONCAT(v_prev_hash, '|', CAST(NEW.user_id AS CHAR), '|', v_action, '|', v_log_time), 256));

            INSERT INTO Audit_Log (user_id, action, log_time, previous_hash, entry_hash)
            VALUES (NEW.user_id, v_action, v_log_time, v_prev_hash, v_entry_hash);
        END
        """,
    ),
    (
        "prevent_audit_log_update",
        """
        CREATE TRIGGER prevent_audit_log_update
        BEFORE UPDATE ON Audit_Log
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log is append-only: UPDATE is prohibited';
        END
        """,
    ),
    (
        "prevent_audit_log_delete",
        """
        CREATE TRIGGER prevent_audit_log_delete
        BEFORE DELETE ON Audit_Log
        FOR EACH ROW
        BEGIN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log is append-only: DELETE is prohibited';
        END
        """,
    ),
)


def _mysql_schema_exists(conn) -> bool:
    """
    True when all five tables already exist.

    The least-privilege runtime user (bank_app) cannot run CREATE TABLE, so the
    DDL runs only when tables are missing. Provisioning is done once by
    setup_db.py using the admin account.
    """
    for table in ("Users", "Accounts", "Transactions", "Audit_Log", "Alerts"):
        try:
            conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()
        except Exception:
            return False
    return True


def init_db() -> None:
    """
    Create tables and apply schema migrations if needed.
    Safe to call on every startup -- IF NOT EXISTS prevents duplicates.
    Demo users are NOT seeded here; use scripts/seed_demo.py explicitly.
    """
    conn = get_connection()
    try:
        if is_mysql_connection(conn):
            if not _mysql_schema_exists(conn):
                conn.executescript(MYSQL_SCHEMA_SQL)
        else:
            conn.executescript(SCHEMA_SQL)
            audit_cols = [
                r["name"]
                for r in conn.execute("PRAGMA table_info(Audit_Log)").fetchall()
            ]
            if "previous_hash" not in audit_cols:
                conn.execute("ALTER TABLE Audit_Log ADD COLUMN previous_hash TEXT")
            if "entry_hash" not in audit_cols:
                conn.execute("ALTER TABLE Audit_Log ADD COLUMN entry_hash TEXT")
            if "ip_address" not in audit_cols:
                conn.execute("ALTER TABLE Audit_Log ADD COLUMN ip_address TEXT")
            _migrate_sqlite_alert_workflow(conn)
    finally:
        conn.close()


def _migrate_sqlite_alert_workflow(conn) -> None:
    """Upgrade the original open/resolved Alerts table without losing rows."""
    columns = [r["name"] for r in conn.execute("PRAGMA table_info(Alerts)").fetchall()]
    required = {
        "reviewed_by",
        "reviewed_at",
        "closed_by",
        "closed_at",
        "resolution_note",
    }
    has_three_state_check = (
        "reviewed"
        in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='Alerts'"
        ).fetchone()[0]
    )
    if required.issubset(columns) and has_three_state_check:
        return

    conn.execute("ALTER TABLE Alerts RENAME TO Alerts_legacy")
    conn.execute("""CREATE TABLE Alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES Users(user_id),
            alert_type TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL DEFAULT 'medium'
                CHECK(severity IN ('low','medium','high')),
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN ('open','reviewed','closed')),
            alert_time TEXT NOT NULL DEFAULT (datetime('now')),
            reviewed_by INTEGER REFERENCES Users(user_id),
            reviewed_at TEXT,
            closed_by INTEGER REFERENCES Users(user_id),
            closed_at TEXT,
            resolution_note TEXT
        )""")
    conn.execute("""INSERT INTO Alerts
           (alert_id, user_id, alert_type, description, severity, status, alert_time)
           SELECT alert_id, user_id, alert_type, description, severity,
                  CASE WHEN status = 'resolved' THEN 'closed' ELSE status END,
                  alert_time
           FROM Alerts_legacy""")
    conn.execute("DROP TABLE Alerts_legacy")


def _migrate_mysql_alert_workflow(conn) -> None:
    """Upgrade an existing MySQL Alerts table to the three-state workflow."""
    rows = conn.execute("SHOW COLUMNS FROM Alerts").fetchall()
    columns = {row["Field"] for row in rows}
    conn.execute(
        "ALTER TABLE Alerts MODIFY COLUMN status ENUM('open','reviewed','closed') "
        "NOT NULL DEFAULT 'open'"
    )
    definitions = {
        "reviewed_by": "INT NULL",
        "reviewed_at": "DATETIME NULL",
        "closed_by": "INT NULL",
        "closed_at": "DATETIME NULL",
        "resolution_note": "TEXT NULL",
    }
    for column, definition in definitions.items():
        if column not in columns:
            conn.execute(f"ALTER TABLE Alerts ADD COLUMN {column} {definition}")
