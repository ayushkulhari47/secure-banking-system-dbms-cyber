"""
tests/test_atomic_audit.py -- Phase 7A tests for atomic, fail-closed,
tamper-evident audit logging within active transactions.
"""

from decimal import Decimal
import pytest

from bank import audit, auth, db, transactions


@pytest.fixture
def audit_db(tmp_path, monkeypatch):
    """Isolated SQLite database with one admin and two standard users."""
    temp_db = str(tmp_path / "audit_atomic.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    pw_hash = auth.hash_password("AuditPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Admin", "admin@audit.local", "admin", "50000.00"),
            ("Alice", "alice@audit.local", "user", "70000.00"),
            ("Bob", "bob@audit.local", "user", "10000.00"),
        ):
            cur = conn.execute(
                "INSERT INTO Users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (name, email, pw_hash, role),
            )
            conn.execute(
                "INSERT INTO Accounts (user_id, balance) VALUES (?, ?)",
                (cur.lastrowid, bal),
            )
        conn.execute("COMMIT")
    finally:
        conn.close()
    return temp_db


class _CommitFailingProxy:
    """Wraps a sqlite3.Connection and optionally injects failure on COMMIT."""

    def __init__(self, real_conn, fail_on_commit: bool = False):
        self._conn = real_conn
        self._fail_on_commit = fail_on_commit

    @property
    def in_transaction(self):
        return self._conn.in_transaction

    def execute(self, sql: str, params=()):
        if self._fail_on_commit and sql.strip().upper() == "COMMIT":
            raise RuntimeError("Simulated commit failure")
        return self._conn.execute(sql, params)

    def close(self):
        self._conn.close()


class TestAtomicAuditLogging:
    """Verify audit entries share the financial transaction and roll back together."""

    def test_transfer_and_audit_commit_on_single_connection(
        self, audit_db, monkeypatch
    ):
        orig_get_conn = db.get_connection
        conn_count = {"n": 0}

        def counted_conn():
            conn_count["n"] += 1
            return orig_get_conn()

        monkeypatch.setattr(db, "get_connection", counted_conn)
        assert transactions.transfer(2, 3, Decimal("250.00"), actor_user_id=2) is True
        monkeypatch.setattr(db, "get_connection", orig_get_conn)

        assert conn_count["n"] == 1
        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 2
        assert any("Account #2 balance updated" in row["action"] for row in logs)
        assert any("Account #3 balance updated" in row["action"] for row in logs)
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_financial_rollback_also_removes_audit_row(self, audit_db, monkeypatch):
        # Seed one valid standalone audit entry first
        audit.log_action(1, "System initialized")

        orig_get_conn = db.get_connection
        monkeypatch.setattr(
            db,
            "get_connection",
            lambda: _CommitFailingProxy(orig_get_conn(), fail_on_commit=True),
        )

        with pytest.raises(RuntimeError, match="Simulated commit failure"):
            transactions.transfer(2, 3, Decimal("500.00"), actor_user_id=2)

        monkeypatch.setattr(db, "get_connection", orig_get_conn)

        # Financial balances unchanged and transfer audit row was rolled back
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "70000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "10000.00"
        )
        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 1
        assert logs[0]["action"] == "System initialized"
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_pending_approval_and_audit_commit_atomically(self, audit_db):
        txn_id = transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )
        ok, _ = transactions.approve_pending_transfer(txn_id, approver_user_id=1)
        assert ok is True

        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 3
        assert any("Account #2 balance updated" in row["action"] for row in logs)
        assert any("Account #3 balance updated" in row["action"] for row in logs)
        assert "Initiated transfer" in logs[2]["action"]
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)


class TestTamperDetectionAndFailClosedAudit:
    """Verify hash-chain validation, fail-closed append, and admin RBAC."""

    def test_valid_chain_passes_verification_including_non_financial_actions(
        self, audit_db
    ):
        audit.log_action(None, "Anonymous login attempt")
        transactions.deposit(2, Decimal("100.00"), actor_user_id=2)
        audit.log_action(2, "User viewed statement")

        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_tampering_with_action_previous_hash_or_entry_hash_detected(
        self, audit_db
    ):
        audit.log_action(1, "Step A")
        audit.log_action(2, "Step B")
        audit.log_action(3, "Step C")

        # Simulate offline/trigger-bypass tampering on historical rows
        conn = db.get_connection()
        conn.execute("DROP TRIGGER IF EXISTS prevent_audit_log_update")
        conn.execute(
            "UPDATE Audit_Log SET entry_hash = ? WHERE log_id = 3", ("f" * 64,)
        )
        conn.close()
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (False, 3)

        # 2. Tamper with previous_hash on row 2
        conn = db.get_connection()
        conn.execute(
            "UPDATE Audit_Log SET previous_hash = ? WHERE log_id = 2", ("a" * 64,)
        )
        conn.close()
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (False, 2)

        # 3. Tamper with action on row 1
        conn = db.get_connection()
        conn.execute(
            "UPDATE Audit_Log SET action = 'Falsified A' WHERE log_id = 1"
        )
        conn.close()
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (False, 1)

    def test_missing_hash_fails_verification_and_append_fails_closed(self, audit_db):
        audit.log_action(1, "Valid first row")

        conn = db.get_connection()
        conn.execute(
            "INSERT INTO Audit_Log (user_id, action, previous_hash, entry_hash) "
            "VALUES (?, ?, NULL, NULL)",
            (2, "Corrupted row without hashes"),
        )
        conn.close()

        assert audit.verify_audit_log_integrity(admin_user_id=1) == (False, 2)

        # Subsequent log_action must fail closed instead of resetting to GENESIS_HASH
        with pytest.raises(ValueError, match="missing hash chain fields"):
            audit.log_action(1, "Should not append onto broken chain")

    def test_audit_access_requires_admin(self, audit_db):
        audit.log_action(2, "User event")
        assert audit.get_audit_log(admin_user_id=2) == []
        assert audit.get_audit_log() == []
        with pytest.raises(PermissionError):
            audit.verify_audit_log_integrity(admin_user_id=2)
        with pytest.raises(PermissionError):
            audit.verify_audit_log_integrity()

