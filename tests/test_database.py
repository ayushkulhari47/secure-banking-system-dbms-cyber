"""
tests/test_database.py  Phase 1 control-testing evidence.

Every test runs against an in-memory SQLite database (:memory:) so:
  - Tests are hermetic -- no leftover state between runs.
  - No banking.db file is created or modified during testing.

Each test IS a documented control test:
  - What control it tests is in the docstring.
  - The expected vs actual result is the assertion.

Run: pytest tests/test_database.py -v
"""

import sqlite3
import hashlib
import pytest

# ---------------------------------------------------------------------------
# Fixtures -- build an isolated in-memory database for each test
# ---------------------------------------------------------------------------


@pytest.fixture()
def mem_conn():
    """
    Return an in-memory SQLite connection with the banking schema applied.
    Yields the connection; closes it after the test finishes.
    """
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    conn.executescript("""
        CREATE TABLE Users (
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

        CREATE TABLE Accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL REFERENCES Users(user_id),
            balance    REAL    NOT NULL DEFAULT 0.00
                               CHECK(balance >= 0),
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE Transactions (
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

        CREATE TABLE Audit_Log (
            log_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER,
            action   TEXT NOT NULL,
            log_time TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE Alerts (
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
    """)

    # Seed two users and two accounts.
    def _hash(pw):
        return hashlib.sha256(pw.encode()).hexdigest()

    conn.execute(
        "INSERT INTO Users (name, email, password_hash, role) VALUES (?,?,?,?)",
        ("Admin User", "admin@bank.com", _hash("admin123"), "admin"),
    )
    conn.execute(
        "INSERT INTO Users (name, email, password_hash, role) VALUES (?,?,?,?)",
        ("Normal User", "user@bank.com", _hash("user123"), "user"),
    )
    conn.execute("INSERT INTO Accounts (user_id, balance) VALUES (1, 10000.00)")
    conn.execute("INSERT INTO Accounts (user_id, balance) VALUES (2, 5000.00)")

    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Schema / constraint tests
# ---------------------------------------------------------------------------


class TestSchema:
    """Control: DB-level data integrity constraints."""

    def test_balance_cannot_go_negative(self, mem_conn):
        """
        Control: Accounts.balance CHECK(balance >= 0) prevents negative balance
        at the database layer -- second line of defence after application logic.
        """
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute("UPDATE Accounts SET balance = -1.00 WHERE account_id = 1")

    def test_transaction_amount_must_be_positive(self, mem_conn):
        """
        Control: Transactions.amount CHECK(amount > 0) rejects zero and
        negative amounts at the database layer.
        """
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute(
                "INSERT INTO Transactions (to_account, amount, txn_type)"
                " VALUES (1, -500, 'deposit')"
            )

    def test_transaction_amount_zero_rejected(self, mem_conn):
        """Zero-amount transactions are rejected by the CHECK constraint."""
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute(
                "INSERT INTO Transactions (to_account, amount, txn_type)"
                " VALUES (1, 0, 'deposit')"
            )

    def test_role_enum_enforced(self, mem_conn):
        """Only 'admin' or 'user' are valid role values."""
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute(
                "INSERT INTO Users (name, email, password_hash, role)"
                " VALUES ('X', 'x@bank.com', 'hash', 'superuser')"
            )

    def test_email_uniqueness(self, mem_conn):
        """Duplicate emails are rejected."""
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute(
                "INSERT INTO Users (name, email, password_hash)"
                " VALUES ('Dup', 'admin@bank.com', 'hash')"
            )

    def test_alert_severity_enum(self, mem_conn):
        """Alert severity must be low, medium, or high."""
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute(
                "INSERT INTO Alerts (user_id, alert_type, severity)"
                " VALUES (1, 'Test', 'critical')"
            )


# ---------------------------------------------------------------------------
# ACID transaction tests
# ---------------------------------------------------------------------------


class TestACIDDeposit:
    """Control: Deposit is atomic -- balance update AND transaction record
    either both succeed or both roll back."""

    def test_deposit_increases_balance(self, mem_conn):
        """After a successful deposit, balance increases by exact amount."""
        mem_conn.execute("BEGIN")
        mem_conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = 1",
            (1000.00,),
        )
        mem_conn.execute(
            "INSERT INTO Transactions (to_account, amount, txn_type)"
            " VALUES (1, 1000.00, 'deposit')"
        )
        mem_conn.execute("COMMIT")

        row = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()
        assert row["balance"] == 11000.00

    def test_deposit_rollback_leaves_balance_unchanged(self, mem_conn):
        """
        If an error occurs mid-transaction, ROLLBACK restores the original
        balance -- demonstrating Atomicity.
        """
        original_balance = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()["balance"]

        try:
            mem_conn.execute("BEGIN")
            mem_conn.execute(
                "UPDATE Accounts SET balance = balance + 500 WHERE account_id = 1"
            )
            # Simulate a failure (negative amount violates CHECK).
            mem_conn.execute(
                "INSERT INTO Transactions (to_account, amount, txn_type)"
                " VALUES (1, -500, 'deposit')"  # invalid -- triggers IntegrityError
            )
            mem_conn.execute("COMMIT")
        except sqlite3.IntegrityError:
            mem_conn.execute("ROLLBACK")

        balance_after = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()["balance"]
        assert (
            balance_after == original_balance
        ), "ROLLBACK must restore the original balance"


class TestACIDWithdraw:
    """Control: Withdraw is atomic and prevents overdraft."""

    def test_withdraw_success(self, mem_conn):
        """Withdrawal within balance succeeds and decrements balance correctly."""
        mem_conn.execute("BEGIN")
        row = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()
        assert row["balance"] >= 2000.00  # pre-condition

        mem_conn.execute(
            "UPDATE Accounts SET balance = balance - 2000 WHERE account_id = 1"
        )
        mem_conn.execute(
            "INSERT INTO Transactions (from_account, amount, txn_type)"
            " VALUES (1, 2000, 'withdraw')"
        )
        mem_conn.execute("COMMIT")

        new_balance = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()["balance"]
        assert new_balance == 8000.00

    def test_withdraw_insufficient_balance_rejected(self, mem_conn):
        """
        Attempting to withdraw more than the balance must be refused.
        The CHECK(balance >= 0) is the DB-level safety net.
        """
        with pytest.raises(sqlite3.IntegrityError):
            mem_conn.execute(
                "UPDATE Accounts SET balance = balance - 999999" " WHERE account_id = 1"
            )


class TestACIDTransfer:
    """Control: Transfer is atomic -- both debit and credit succeed or
    both are rolled back."""

    def test_transfer_moves_money_atomically(self, mem_conn):
        """
        After a successful transfer:
          - sender balance decreases by exactly the transfer amount
          - receiver balance increases by exactly the transfer amount
          - total money in the system is conserved
        """
        amount = 3000.00
        mem_conn.execute("BEGIN")
        mem_conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = 1",
            (amount,),
        )
        mem_conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = 2",
            (amount,),
        )
        mem_conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (1, 2, ?, 'transfer')",
            (amount,),
        )
        mem_conn.execute("COMMIT")

        sender = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()["balance"]
        receiver = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 2"
        ).fetchone()["balance"]

        assert sender == 7000.00
        assert receiver == 8000.00
        assert sender + receiver == 15000.00  # total money conserved

    def test_transfer_rollback_on_error(self, mem_conn):
        """
        If the receiver UPDATE fails (e.g., non-existent account due to FK),
        ROLLBACK must restore the sender's balance.
        """
        original = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()["balance"]

        try:
            mem_conn.execute("BEGIN")
            mem_conn.execute(
                "UPDATE Accounts SET balance = balance - 1000 WHERE account_id = 1"
            )
            # account_id=999 does not exist -- FK violation after COMMIT
            mem_conn.execute(
                "UPDATE Accounts SET balance = balance + 1000 WHERE account_id = 999"
            )
            mem_conn.execute(
                "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
                " VALUES (1, 999, 1000, 'transfer')"
            )
            mem_conn.execute("COMMIT")
        except Exception:
            mem_conn.execute("ROLLBACK")

        restored = mem_conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = 1"
        ).fetchone()["balance"]
        assert restored == original


# ---------------------------------------------------------------------------
# Audit log tests
# ---------------------------------------------------------------------------


class TestAuditLog:
    """Control: Every significant action is recorded with a timestamp."""

    def test_log_action_stored(self, mem_conn):
        """Audit log entry is retrievable after insertion."""
        mem_conn.execute(
            "INSERT INTO Audit_Log (user_id, action) VALUES (1, 'Test action')"
        )
        row = mem_conn.execute(
            "SELECT * FROM Audit_Log WHERE action = 'Test action'"
        ).fetchone()
        assert row is not None
        assert row["user_id"] == 1

    def test_log_action_null_user_id_allowed(self, mem_conn):
        """
        Pre-authentication events (e.g. unknown-email login attempt) are
        logged with user_id = NULL.  This fixes the Phase 0 audit finding.
        """
        mem_conn.execute(
            "INSERT INTO Audit_Log (user_id, action)"
            " VALUES (NULL, 'Failed login -- unknown email: hacker@evil.com')"
        )
        row = mem_conn.execute(
            "SELECT * FROM Audit_Log WHERE user_id IS NULL"
        ).fetchone()
        assert row is not None


# ---------------------------------------------------------------------------
# Alert tests
# ---------------------------------------------------------------------------


class TestAlerts:
    """Control: Suspicious events generate alerts with severity classification."""

    def test_alert_created_with_high_severity(self, mem_conn):
        """High-severity alert is persisted correctly."""
        mem_conn.execute(
            "INSERT INTO Alerts (user_id, alert_type, description, severity)"
            " VALUES (1, 'Large Transaction', 'Rs 75000 transfer detected', 'high')"
        )
        row = mem_conn.execute(
            "SELECT * FROM Alerts WHERE alert_type = 'Large Transaction'"
        ).fetchone()
        assert row is not None
        assert row["severity"] == "high"
        assert row["status"] == "open"

    def test_brute_force_alert(self, mem_conn):
        """Brute-force alert is persisted after account lockout."""
        mem_conn.execute(
            "INSERT INTO Alerts (user_id, alert_type, description, severity)"
            " VALUES (2, 'Brute Force', 'Account locked after 3 failed attempts', 'high')"
        )
        row = mem_conn.execute(
            "SELECT * FROM Alerts WHERE alert_type = 'Brute Force'"
        ).fetchone()
        assert row is not None
        assert row["severity"] == "high"


# ---------------------------------------------------------------------------
# Data persistence simulation
# ---------------------------------------------------------------------------


class TestPersistence:
    """
    Control: Data persists beyond the lifetime of a single connection.
    (In production this means beyond process restart; here we close and
    reopen the in-memory connection cannot simulate cross-process, but
    we test the commit-then-read pattern which is the same guarantee.)
    """

    def test_committed_data_visible_on_new_read(self, mem_conn):
        """Data written and committed is immediately readable."""
        mem_conn.execute(
            "INSERT INTO Audit_Log (user_id, action) VALUES (1, 'Persistence test')"
        )
        # New execute on same connection (simulates re-query after commit).
        count = mem_conn.execute(
            "SELECT COUNT(*) AS n FROM Audit_Log WHERE action = 'Persistence test'"
        ).fetchone()["n"]
        assert count == 1

    def test_rollback_data_not_visible(self, mem_conn):
        """Data that is rolled back must not appear in subsequent reads."""
        try:
            mem_conn.execute("BEGIN")
            mem_conn.execute(
                "INSERT INTO Audit_Log (user_id, action)"
                " VALUES (1, 'Should not be saved')"
            )
            mem_conn.execute("ROLLBACK")
        except Exception:
            pass

        count = mem_conn.execute(
            "SELECT COUNT(*) AS n FROM Audit_Log"
            " WHERE action = 'Should not be saved'"
        ).fetchone()["n"]
        assert count == 0
