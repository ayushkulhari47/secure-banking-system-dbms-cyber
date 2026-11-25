"""
bank/db.py -- Database connections, schema definitions, initialization, and migrations.
"""

import os
import sqlite3

try:
    import pymysql
    import pymysql.cursors

    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

from bank.config import (
    BASE_DIR,
    DB_TYPE,
    DB_PATH as CFG_DB_PATH,
    DB_HOST,
    DB_PORT,
    DB_USER,
    DB_PASSWORD,
    DB_NAME,
)

# ---------------------------------------------------------------------------
# Connection & Database Engine Abstraction
# ---------------------------------------------------------------------------

DB_PATH = (
    CFG_DB_PATH
    if os.path.isabs(CFG_DB_PATH)
    else os.path.join(BASE_DIR, CFG_DB_PATH)
)


class MySQLCursorWrapper:
    """Wraps a PyMySQL cursor to provide an interface matching sqlite3."""

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


class MySQLConnectionWrapper:
    """
    Wraps a PyMySQL connection so SQL execution works consistently across SQLite and MySQL:
      - Automatically maps '?' placeholders to '%s'
      - Intercepts BEGIN, COMMIT, and ROLLBACK to control transactions
      - Ignores SQLite-specific PRAGMAs
      - Provides dict-like row access via PyMySQL DictCursor
    """

    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, sql: str, params=()):
        sql_clean = sql.strip()
        upper_sql = sql_clean.upper()

        if upper_sql == "BEGIN":
            self._conn.begin()
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
        cursor = self._conn.cursor(pymysql.cursors.DictCursor)
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


def _get_sqlite_connection(path: str = None) -> sqlite3.Connection:
    target_path = path or DB_PATH
    conn = sqlite3.connect(target_path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_mysql_connection():
    """Open and return a wrapped PyMySQL connection using runtime credentials."""
    if not HAS_PYMYSQL:
        raise RuntimeError("PyMySQL package is not installed. Run: pip install PyMySQL")
    try:
        raw_conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            autocommit=False,
            cursorclass=pymysql.cursors.DictCursor,
        )
        return MySQLConnectionWrapper(raw_conn)
    except pymysql.err.OperationalError:
        # Runtime credentials must never create databases or silently acquire
        # administrative privileges. Provisioning belongs exclusively to
        # setup_db.py, which uses the explicitly configured admin account.
        raise


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
    balance    REAL    NOT NULL DEFAULT 0.00
                       CHECK(balance >= 0),
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS Transactions (
    txn_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account INTEGER REFERENCES Accounts(account_id),
    to_account   INTEGER REFERENCES Accounts(account_id),
    amount       REAL    NOT NULL CHECK(amount > 0),
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
    balance    DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    CHECK (balance >= 0)
);

CREATE TABLE IF NOT EXISTS Transactions (
    txn_id       INT AUTO_INCREMENT PRIMARY KEY,
    from_account INT NULL,
    to_account   INT NULL,
    amount       DECIMAL(15,2) NOT NULL,
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
    Create tables and seed demo data if the database does not yet exist.
    Safe to call on every startup -- IF NOT EXISTS prevents duplicates.
    Includes automated column migrations for schema upgrades.
    """
    conn = get_connection()
    try:
        if is_mysql_connection(conn):
            if not _mysql_schema_exists(conn):
                conn.executescript(MYSQL_SCHEMA_SQL)
        else:
            conn.executescript(SCHEMA_SQL)
            # Automated column migrations for existing databases
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
        _seed_if_empty(conn)
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


def _seed_if_empty(conn) -> None:
    """
    Insert demo users and accounts only when the Users table is empty.

    DEMO CREDENTIALS (hardcoded seed only -- remove before production):
        ayush@bank.com  / ayush123  (admin)
        rahul@bank.com  / rahul123  (user)
        priya@bank.com  / priya123  (user)
    """
    from bank.auth import hash_password

    row = conn.execute("SELECT COUNT(*) AS cnt FROM Users").fetchone()
    if row["cnt"] > 0:
        return  # Already seeded

    demo_users = [
        ("Ayush Kulhari", "ayush@bank.com", hash_password("ayush123"), "admin"),
        ("Rahul Sharma", "rahul@bank.com", hash_password("rahul123"), "user"),
        ("Priya Singh", "priya@bank.com", hash_password("priya123"), "user"),
    ]

    conn.execute("BEGIN")
    try:
        for name, email, pw_hash, role in demo_users:
            conn.execute(
                "INSERT INTO Users (name, email, password_hash, role)"
                " VALUES (?, ?, ?, ?)",
                (name, email, pw_hash, role),
            )
        conn.execute("INSERT INTO Accounts (user_id, balance) VALUES (1, 50000.00)")
        conn.execute("INSERT INTO Accounts (user_id, balance) VALUES (2, 25000.00)")
        conn.execute("INSERT INTO Accounts (user_id, balance) VALUES (3, 15000.00)")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

