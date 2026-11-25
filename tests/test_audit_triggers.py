"""
tests/test_audit_triggers.py -- Phase 7B tests for SQLite balance-change audit triggers,
append-only Audit_Log triggers, hash-chain verification, and MySQL trigger definitions.
"""

from decimal import Decimal
from pathlib import Path
import sqlite3
import pytest

from bank import audit, auth, db, transactions


@pytest.fixture
def trigger_db(tmp_path, monkeypatch):
    """Isolated SQLite database with triggers installed via db.init_db()."""
    temp_db = str(tmp_path / "trigger_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    pw_hash = auth.hash_password("TrigPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Admin", "admin@trig.local", "admin", "50000.00"),
            ("Alice", "alice@trig.local", "user", "70000.00"),
            ("Bob", "bob@trig.local", "user", "10000.00"),
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


class TestSQLiteAuditTriggers:
    """Direct tests of SQLite balance-change and append-only Audit_Log triggers."""

    def test_balance_update_trigger_creates_hashed_audit_row(self, trigger_db):
        conn = db.get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE Accounts SET balance = '71234.56' WHERE account_id = 2"
            )
            conn.execute("COMMIT")
        finally:
            conn.close()

        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 1
        row = logs[0]
        assert row["user_id"] == 2
        assert "Account #2 balance updated" in row["action"]
        assert "70000.00" in row["action"]
        assert "71234.56" in row["action"]
        assert row["log_time"]
        assert row["previous_hash"] == audit.GENESIS_HASH
        assert row["entry_hash"] is not None and len(row["entry_hash"]) == 64
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_deposit_and_withdrawal_create_single_valid_audit_row_each(
        self, trigger_db
    ):
        transactions.deposit(2, Decimal("250.50"), actor_user_id=2)
        logs_after_dep = audit.get_audit_log(admin_user_id=1)
        assert len(logs_after_dep) == 1
        assert "70250.50" in logs_after_dep[0]["action"]

        assert transactions.withdraw(2, Decimal("100.25"), actor_user_id=2) is True
        logs_after_wd = audit.get_audit_log(admin_user_id=1)
        assert len(logs_after_wd) == 2
        assert "70150.25" in logs_after_wd[0]["action"]
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_transfer_creates_two_valid_audit_rows_without_duplicates(self, trigger_db):
        assert transactions.transfer(2, 3, Decimal("500.00"), actor_user_id=2) is True

        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 2
        assert logs[0]["previous_hash"] == logs[1]["entry_hash"]
        assert all(r["previous_hash"] and r["entry_hash"] for r in logs)
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_pending_approval_and_rejection_create_valid_audit_rows(self, trigger_db):
        txn_approve = transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )
        ok, _ = transactions.approve_pending_transfer(txn_approve, approver_user_id=1)
        assert ok is True

        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 3  # 1 initiation + 2 balance-change trigger rows
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

        # Rejection does not mutate balance; logs rejection cleanly
        transactions.deposit(2, Decimal("60000.00"), actor_user_id=2)
        txn_reject = transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )
        ok_rej, _ = transactions.reject_pending_transfer(
            txn_reject, approver_user_id=1, reason="Policy check"
        )
        assert ok_rej is True
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_complete_mixed_hash_chain_verifies_with_no_null_hashes(self, trigger_db):
        audit.log_action(None, "Login probe")
        transactions.deposit(2, Decimal("100.00"), actor_user_id=2)
        transactions.withdraw(2, Decimal("50.00"), actor_user_id=2)
        transactions.transfer(2, 3, Decimal("25.00"), actor_user_id=2)
        ok, _ = auth.change_password(
            2, "TrigPass@123", "TrigNew@123", actor_user_id=2
        )
        assert ok is True

        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 6
        assert all(r["previous_hash"] and r["entry_hash"] for r in logs)
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_update_and_delete_on_audit_log_are_blocked(self, trigger_db):
        transactions.deposit(2, Decimal("10.00"), actor_user_id=2)

        conn = db.get_connection()
        try:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(
                    "UPDATE Audit_Log SET action = 'Tampered' WHERE log_id = 1"
                )
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute("DELETE FROM Audit_Log WHERE log_id = 1")
        finally:
            conn.close()

        logs = audit.get_audit_log(admin_user_id=1)
        assert len(logs) == 1
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_trigger_aborts_if_audit_chain_has_null_or_tampered_hash(
        self, trigger_db
    ):
        conn = db.get_connection()
        try:
            conn.execute(
                "INSERT INTO Audit_Log (user_id, action, previous_hash, entry_hash) "
                "VALUES (1, 'Broken unhashed row', NULL, NULL)"
            )
            assert audit.verify_audit_log_integrity(admin_user_id=1) == (False, 1)

            with pytest.raises(sqlite3.IntegrityError, match="corrupted"):
                conn.execute(
                    "UPDATE Accounts SET balance = '70500.00' WHERE account_id = 2"
                )
        finally:
            conn.close()


class TestMySQLTriggerDefinitions:
    """Verify MySQL trigger definitions use SHA2 and drop legacy unhashed triggers."""

    def test_mysql_audit_triggers_defined_and_hash_chained(self):
        names = [name for name, _ in db.MYSQL_AUDIT_TRIGGERS]
        assert names == [
            "after_accounts_balance_update",
            "prevent_audit_log_update",
            "prevent_audit_log_delete",
        ]
        balance_trigger_sql = db.MYSQL_AUDIT_TRIGGERS[0][1]
        assert "SHA2(" in balance_trigger_sql
        assert "Audit_Log" in balance_trigger_sql
        assert "SIGNAL SQLSTATE '45000'" in db.MYSQL_AUDIT_TRIGGERS[1][1]
        assert "SIGNAL SQLSTATE '45000'" in db.MYSQL_AUDIT_TRIGGERS[2][1]

        triggers_file = (
            Path(__file__).resolve().parent.parent / "sql" / "triggers.sql"
        ).read_text(encoding="utf-8")
        assert "after_accounts_balance_update" in triggers_file
        assert "prevent_audit_log_update" in triggers_file
        assert "prevent_audit_log_delete" in triggers_file
        assert "DROP TRIGGER IF EXISTS `after_transaction`" in triggers_file
        assert "DROP TRIGGER IF EXISTS `after_user_login`" in triggers_file

