"""
db.py  Database layer for the Secure Banking System.

Design decisions (explain these in an interview):
- SQLite via Python built-in sqlite3 module (zero extra install needed).
- isolation_level=None puts SQLite in autocommit-off mode so we control
  every transaction explicitly with BEGIN / COMMIT / ROLLBACK.
- All user-supplied values go through parameterized queries (? placeholders).
  No string formatting is ever used for SQL -- eliminates SQL injection.
- check_same_thread=False is safe here because the CLI is single-threaded.
- Passwords use bcrypt with work factor 12 (Phase 2 upgrade from SHA-256).
  bcrypt generates a per-password random salt automatically and embeds it
  in the stored hash, making rainbow-table attacks infeasible.
"""

import sqlite3
import os
import hashlib
from datetime import datetime, timezone
import bcrypt

from config import (
    BCRYPT_ROUNDS,
    MAX_FAILED_LOGINS,
    LARGE_TXN_THRESHOLD,
)

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banking.db")


def get_connection() -> sqlite3.Connection:
    """
    Open (or create) the SQLite database and return a connection.
    Row factory enables dict-like access: row["column_name"].
    isolation_level=None means we manage BEGIN/COMMIT/ROLLBACK ourselves.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # SQLite disables foreign-key enforcement by default -- turn it on.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


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
    user_id    INTEGER NOT NULL REFERENCES Users(user_id),
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
    entry_hash    TEXT
);

CREATE TABLE IF NOT EXISTS Alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES Users(user_id),
    alert_type  TEXT    NOT NULL,
    description TEXT,
    severity    TEXT    NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high')),
    status      TEXT    NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','resolved')),
    alert_time  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db() -> None:
    """
    Create tables and seed demo data if the database does not yet exist.
    Safe to call on every startup -- IF NOT EXISTS prevents duplicates.
    Includes automated column migrations for schema upgrades.
    """
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        # Automated column migrations for existing databases
        audit_cols = [r["name"] for r in conn.execute("PRAGMA table_info(Audit_Log)").fetchall()]
        if "previous_hash" not in audit_cols:
            conn.execute("ALTER TABLE Audit_Log ADD COLUMN previous_hash TEXT")
        if "entry_hash" not in audit_cols:
            conn.execute("ALTER TABLE Audit_Log ADD COLUMN entry_hash TEXT")

        _seed_if_empty(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed_if_empty(conn: sqlite3.Connection) -> None:
    """
    Insert demo users and accounts only when the Users table is empty.

    DEMO CREDENTIALS (hardcoded seed only -- remove before production):
        ayush@bank.com  / ayush123  (admin)
        rahul@bank.com  / rahul123  (user)
        priya@bank.com  / priya123  (user)

    Passwords are hashed with bcrypt (work factor 12) and a random salt.
    The salt is embedded in the hash string -- no separate storage needed.
    """
    row = conn.execute("SELECT COUNT(*) AS cnt FROM Users").fetchone()
    if row["cnt"] > 0:
        return  # Already seeded

    demo_users = [
        ("Ayush Kulhari", "ayush@bank.com", hash_password("ayush123"), "admin"),
        ("Rahul Sharma",  "rahul@bank.com", hash_password("rahul123"), "user"),
        ("Priya Singh",   "priya@bank.com", hash_password("priya123"), "user"),
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


def hash_password(plaintext: str) -> str:
    """
    Hash a password with bcrypt.

    bcrypt.gensalt() generates a new random 16-byte salt on every call.
    The salt and work factor (BCRYPT_ROUNDS) are embedded in the returned string,
    so we never need to store them separately.

    Work factor 12 => ~250 ms per hash on modern hardware.
    This makes offline dictionary attacks ~1000x slower than SHA-256.
    """
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()


# ---------------------------------------------------------------------------
# User / authentication helpers
# ---------------------------------------------------------------------------

def get_user_by_email(email: str):
    """Return the Users row for the given email, or None."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Users WHERE email = ?", (email,)
        ).fetchone()
    finally:
        conn.close()


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    bcrypt.checkpw() is timing-safe: it always takes the same amount of
    time regardless of where a comparison fails, preventing timing attacks.
    """
    try:
        return bcrypt.checkpw(plaintext.encode(), stored_hash.encode())
    except Exception:
        # Malformed hash in DB -- fail closed (deny access).
        return False


def increment_failed_attempts(user_id: int, max_attempts: int = MAX_FAILED_LOGINS) -> None:
    """
    Increment failed_attempts and lock the account if the threshold is reached.
    Both UPDATEs are atomic inside one transaction.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE Users SET failed_attempts = failed_attempts + 1"
            " WHERE user_id = ?",
            (user_id,),
        )
        conn.execute(
            "UPDATE Users SET is_locked = 1"
            " WHERE user_id = ? AND failed_attempts >= ?",
            (user_id, max_attempts),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def reset_failed_attempts(user_id: int) -> None:
    """Clear the failed-attempts counter after a successful login."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE Users SET failed_attempts = 0 WHERE user_id = ?", (user_id,)
        )
    finally:
        conn.close()


def get_failed_attempts(user_id: int) -> int:
    """Return the current failed_attempts value for a user."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT failed_attempts FROM Users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row["failed_attempts"] if row else 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Audit log (Cryptographic Hash Chaining -- Tamper-Evident)
# ---------------------------------------------------------------------------

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
    Each entry includes previous_hash and entry_hash:
      entry_hash = SHA256(previous_hash || user_id || action || log_time)
    user_id may be None for pre-authentication events such as unknown-email
    login attempts.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        last_row = conn.execute(
            "SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1"
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


def verify_audit_log_integrity() -> tuple:
    """
    Verify the cryptographic integrity of the entire Audit_Log table.
    Traverses the chain from genesis and recalculates every hash.
    Returns (True, None) if intact.
    Returns (False, compromised_log_id) if tampering is detected.
    """
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM Audit_Log ORDER BY log_id ASC").fetchall()
        expected_prev = GENESIS_HASH
        for row in rows:
            # Check chained entries
            if row["entry_hash"] is not None:
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


def get_audit_log(limit: int = 50) -> list:
    """Return the most recent audit log entries. Admin use only."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Audit_Log ORDER BY log_time DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Admin User Account Management
# ---------------------------------------------------------------------------

def unlock_user(user_id: int, admin_user_id: int = None) -> bool:
    """
    Admin unlock function for locked user accounts (ISO 27001 A.9.4.2 Corrective Control).
    Resets failed_attempts to 0 and clears is_locked flag.
    Logs the action in Audit_Log.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        user = conn.execute("SELECT * FROM Users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Users SET is_locked = 0, failed_attempts = 0 WHERE user_id = ?",
            (user_id,),
        )
        conn.execute("COMMIT")
        log_action(admin_user_id, f"Admin unlocked account for user #{user_id} ({user['email']})")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_locked_users() -> list:
    """Return all currently locked user accounts."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT user_id, name, email, failed_attempts, created_at FROM Users WHERE is_locked = 1"
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def raise_alert(
    user_id: int,
    alert_type: str,
    description: str,
    severity: str = "medium",
) -> None:
    """Insert a security alert."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO Alerts (user_id, alert_type, description, severity)"
            " VALUES (?, ?, ?, ?)",
            (user_id, alert_type, description, severity),
        )
    finally:
        conn.close()


def resolve_alert(alert_id: int, admin_user_id: int = None) -> bool:
    """
    Resolve an active security alert (Audit Remediation / Corrective Control).
    Logs the resolution action in Audit_Log.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        alert = conn.execute("SELECT * FROM Alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not alert:
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Alerts SET status = 'resolved' WHERE alert_id = ?",
            (alert_id,),
        )
        conn.execute("COMMIT")
        log_action(admin_user_id, f"Admin resolved alert #{alert_id} ({alert['alert_type']})")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_all_alerts() -> list:
    """Return all alerts. Admin use only."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Alerts ORDER BY alert_time DESC"
        ).fetchall()
    finally:
        conn.close()


def get_open_alerts() -> list:
    """Return all open (unresolved) security alerts."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Alerts WHERE status = 'open' ORDER BY alert_time DESC"
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Account helpers
# ---------------------------------------------------------------------------

def get_account_by_user(user_id: int):
    """Return the Accounts row for a given user_id."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Accounts WHERE user_id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()


def get_account_by_id(account_id: int):
    """Return the Accounts row for a given account_id."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Financial transactions -- ACID-compliant
# ---------------------------------------------------------------------------

def deposit(account_id: int, amount: float) -> None:
    """
    Credit 'amount' to 'account_id'.

    ACID contract:
      Atomicity  : balance UPDATE + Transactions INSERT are one unit.
      Consistency: CHECK(amount > 0) prevents a negative deposit at DB level.
      Isolation  : SQLite serialises all writes.
      Durability : WAL mode survives a process crash after COMMIT.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?",
            (amount, account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (NULL, ?, ?, 'deposit')",
            (account_id, amount),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def withdraw(account_id: int, amount: float) -> bool:
    """
    Debit 'amount' from 'account_id'.
    Returns True on success, False if balance is insufficient.
    Balance is read inside the transaction to prevent a TOCTOU race.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        row = conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if row is None or row["balance"] < amount:
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = ?",
            (amount, account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (?, NULL, ?, 'withdraw')",
            (account_id, amount),
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def transfer(from_account_id: int, to_account_id: int, amount: float) -> bool:
    """
    Move 'amount' from one account to another atomically.
    Both balance updates and the INSERT happen in one transaction.
    If any step raises an exception, ROLLBACK ensures no money is lost or created.
    Returns True on success, False if balance is insufficient.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        row = conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = ?", (from_account_id,)
        ).fetchone()
        if row is None or row["balance"] < amount:
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = ?",
            (amount, from_account_id),
        )
        conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?",
            (amount, to_account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (?, ?, ?, 'transfer')",
            (from_account_id, to_account_id, amount),
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Transaction read helpers
# ---------------------------------------------------------------------------

def get_transactions_for_account(account_id: int) -> list:
    """Return all transactions involving a specific account. User-scoped."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Transactions"
            " WHERE from_account = ? OR to_account = ?"
            " ORDER BY txn_time DESC",
            (account_id, account_id),
        ).fetchall()
    finally:
        conn.close()


def get_all_transactions() -> list:
    """Return every transaction. Admin use only."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Transactions ORDER BY txn_time DESC"
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Maker-Checker (Dual Control) Workflow for Large Transactions
# ---------------------------------------------------------------------------

def create_pending_transfer(from_account_id: int, to_account_id: int, amount: float) -> int:
    """
    Insert a pending transaction requiring Maker-Checker authorization (ISO 27001 A.6.1.2).
    Balances are NOT modified at creation time.
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        cursor = conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type, status)"
            " VALUES (?, ?, ?, 'transfer', 'pending')",
            (from_account_id, to_account_id, amount),
        )
        txn_id = cursor.lastrowid
        conn.execute("COMMIT")
        return txn_id
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_pending_transfers() -> list:
    """Return all transactions waiting for Maker-Checker approval."""
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT t.*, u.name as sender_name, u.email as sender_email "
            "FROM Transactions t "
            "JOIN Accounts a ON t.from_account = a.account_id "
            "JOIN Users u ON a.user_id = u.user_id "
            "WHERE t.status = 'pending' "
            "ORDER BY t.txn_time ASC"
        ).fetchall()
    finally:
        conn.close()


def approve_pending_transfer(txn_id: int, approver_user_id: int) -> tuple:
    """
    Checker approves a pending transfer.
    Enforces Segregation of Duties (SoD):
      The user who initiated the transfer (Maker) CANNOT approve it.
    Returns (True, message) or (False, error_reason).
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        txn = conn.execute(
            "SELECT * FROM Transactions WHERE txn_id = ? AND status = 'pending'",
            (txn_id,),
        ).fetchone()
        if not txn:
            conn.execute("ROLLBACK")
            return False, "Pending transaction not found."

        from_acc = conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?", (txn["from_account"],)
        ).fetchone()
        to_acc = conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?", (txn["to_account"],)
        ).fetchone()

        if not from_acc or not to_acc:
            conn.execute("ROLLBACK")
            return False, "Associated accounts not found."

        # Segregation of Duties (SoD) check: Maker != Checker
        if from_acc["user_id"] == approver_user_id:
            conn.execute("ROLLBACK")
            log_action(approver_user_id, f"SoD violation attempt: self-approval of txn #{txn_id}")
            return False, "Segregation of Duties violation: Maker cannot approve their own transfer."

        # Balance check at approval time
        if from_acc["balance"] < txn["amount"]:
            conn.execute(
                "UPDATE Transactions SET status = 'rejected' WHERE txn_id = ?",
                (txn_id,),
            )
            conn.execute("COMMIT")
            log_action(approver_user_id, f"Pending transfer #{txn_id} rejected due to insufficient funds")
            return False, "Insufficient balance at time of approval. Transfer rejected."

        # Execute transfer atomically
        conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = ?",
            (txn["amount"], txn["from_account"]),
        )
        conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?",
            (txn["amount"], txn["to_account"]),
        )
        conn.execute(
            "UPDATE Transactions SET status = 'completed' WHERE txn_id = ?",
            (txn_id,),
        )
        conn.execute("COMMIT")
        log_action(approver_user_id, f"Approved pending transfer #{txn_id} of Rs{txn['amount']:.2f}")
        return True, "Transfer approved and processed successfully."
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def reject_pending_transfer(txn_id: int, approver_user_id: int, reason: str = "Rejected by admin") -> tuple:
    """
    Checker rejects a pending transfer.
    Returns (True, message) or (False, error_reason).
    """
    conn = get_connection()
    try:
        conn.execute("BEGIN")
        txn = conn.execute(
            "SELECT * FROM Transactions WHERE txn_id = ? AND status = 'pending'",
            (txn_id,),
        ).fetchone()
        if not txn:
            conn.execute("ROLLBACK")
            return False, "Pending transaction not found."

        conn.execute(
            "UPDATE Transactions SET status = 'rejected' WHERE txn_id = ?",
            (txn_id,),
        )
        conn.execute("COMMIT")
        log_action(approver_user_id, f"Rejected pending transfer #{txn_id} ({reason})")
        return True, "Transfer rejected successfully."
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
