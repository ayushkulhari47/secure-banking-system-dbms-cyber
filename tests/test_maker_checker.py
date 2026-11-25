"""
tests/test_maker_checker.py -- Phase 9 verification and hardening tests for
Maker-Checker dual-control transfers.
"""

from decimal import Decimal
import pytest

from bank import alerts, audit, auth, config, db, security, transactions
import main


@pytest.fixture
def mc_db(tmp_path, monkeypatch):
    """
    Isolated SQLite DB with:
      1: Admin One   (admin, acc 1, Rs 120,000.00)
      2: Alice       (user,  acc 2, Rs 120,000.00)
      3: Bob         (user,  acc 3, Rs  25,000.00)
      4: Admin Two   (admin, acc 4, Rs  80,000.00)
    """
    temp_db = str(tmp_path / "maker_checker_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    pw_hash = auth.hash_password("MakerPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Admin One", "admin1@mc.local", "admin", "120000.00"),
            ("Alice", "alice@mc.local", "user", "120000.00"),
            ("Bob", "bob@mc.local", "user", "25000.00"),
            ("Admin Two", "admin2@mc.local", "admin", "80000.00"),
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


def _cli_transfer(monkeypatch, capsys, user_id: int, to_account_id: int, amount_str: str) -> str:
    """Invoke main.do_transfer with scripted user input and return stdout."""
    session = security.Session()
    inputs = iter([str(to_account_id), amount_str])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    main.do_transfer(user_id, session)
    return capsys.readouterr().out


class TestMakerCheckerThresholdRouting:
    """Verify maker-checker applies strictly to transfers above LARGE_TXN_THRESHOLD."""

    def test_transfer_at_threshold_completes_immediately(self, mc_db, monkeypatch, capsys):
        out = _cli_transfer(monkeypatch, capsys, user_id=2, to_account_id=3, amount_str="50000.00")
        assert "transferred!" in out

        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("70000.00")
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal("75000.00")
        assert transactions.get_pending_transfers(admin_user_id=1) == []
        assert alerts.get_all_alerts(admin_user_id=1) == []

        txns = transactions.get_transactions_for_account(2, actor_user_id=2)
        assert len(txns) == 1
        assert txns[0]["status"] == "completed"
        assert txns[0]["amount"] == config.LARGE_TXN_THRESHOLD

    def test_transfer_above_threshold_becomes_pending_and_reserves_without_moving_funds(
        self, mc_db, monkeypatch, capsys
    ):
        out = _cli_transfer(monkeypatch, capsys, user_id=2, to_account_id=3, amount_str="50000.01")
        assert "pending" in out.lower()

        # Balances remain untouched prior to approval
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("120000.00")
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal("25000.00")

        pending = transactions.get_pending_transfers(admin_user_id=1)
        assert len(pending) == 1
        assert pending[0]["amount"] == Decimal("50000.01")
        assert pending[0]["status"] == "pending"

        # High-severity Large Transaction alert is raised for the pending transfer
        all_alerts = alerts.get_all_alerts(admin_user_id=1)
        assert len(all_alerts) == 1
        assert all_alerts[0]["alert_type"] == "Large Transaction"
        assert all_alerts[0]["severity"] == "high"
        assert all_alerts[0]["user_id"] == 2

        # Pending amount is reserved (120000.00 - 50000.01 = 69999.99 available)
        assert transactions.withdraw(2, Decimal("70000.00"), actor_user_id=2) is False
        assert transactions.transfer(2, 3, Decimal("70000.00"), actor_user_id=2) is False
        assert transactions.withdraw(2, Decimal("69999.99"), actor_user_id=2) is True

    def test_deposits_and_withdrawals_do_not_require_maker_checker(
        self, mc_db, monkeypatch, capsys
    ):
        session = security.Session()

        # Deposit above threshold completes immediately
        monkeypatch.setattr("builtins.input", lambda _p="": "75000.00")
        main.do_deposit(2, session)
        capsys.readouterr()
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("195000.00")

        # Withdrawal above threshold completes immediately
        monkeypatch.setattr("builtins.input", lambda _p="": "80000.00")
        main.do_withdraw(2, session)
        capsys.readouterr()
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("115000.00")

        assert transactions.get_pending_transfers(admin_user_id=1) == []
        txns = transactions.get_transactions_for_account(2, actor_user_id=2)
        assert len(txns) == 2
        assert all(t["status"] == "completed" for t in txns)


class TestMakerCheckerSegregationAndLifecycle:
    """Verify RBAC, Segregation of Duties, rejection, idempotency, and atomic approval."""

    def test_approval_rejects_non_admin_maker_and_recipient_admin_but_allows_other_admin(
        self, mc_db, monkeypatch, capsys
    ):
        # 1. Normal user Alice (user 2) -> Bob (user 3)
        _cli_transfer(monkeypatch, capsys, user_id=2, to_account_id=3, amount_str="60000.00")
        txn_user = transactions.get_pending_transfers(admin_user_id=1)[0]["txn_id"]

        # Non-admin (Alice or Bob) cannot approve or reject
        assert transactions.approve_pending_transfer(txn_user, 2)[0] is False
        assert transactions.approve_pending_transfer(txn_user, 3)[0] is False
        assert transactions.reject_pending_transfer(txn_user, 2)[0] is False

        # Independent admin approves -> moves funds atomically
        ok, _ = transactions.approve_pending_transfer(txn_user, 1)
        assert ok is True
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("60000.00")
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal("85000.00")

        # 2. Admin One (user 1) -> Admin Two (user 4) cannot be approved by maker or recipient
        _cli_transfer(monkeypatch, capsys, user_id=1, to_account_id=4, amount_str="60000.00")
        txn_admin_to_admin = transactions.get_pending_transfers(admin_user_id=1)[0]["txn_id"]

        ok_maker, msg_maker = transactions.approve_pending_transfer(txn_admin_to_admin, 1)
        assert ok_maker is False
        assert "maker" in msg_maker.lower()

        ok_recip, msg_recip = transactions.approve_pending_transfer(txn_admin_to_admin, 4)
        assert ok_recip is False
        assert "recipient" in msg_recip.lower()

        # 3. Admin One -> Bob (user 3) can be approved by Admin Two (user 4)
        _cli_transfer(monkeypatch, capsys, user_id=1, to_account_id=3, amount_str="55000.00")
        pending_for_admin2 = transactions.get_pending_transfers(admin_user_id=4)
        txn_admin_to_bob = [t for t in pending_for_admin2 if t["to_account"] == 3][0]["txn_id"]

        ok_peer, _ = transactions.approve_pending_transfer(txn_admin_to_bob, 4)
        assert ok_peer is True
        assert transactions.get_account_by_id(1, actor_user_id=1)["balance"] == Decimal("65000.00")
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal("140000.00")

    def test_approval_fails_safely_when_funds_become_unavailable(self, mc_db):
        txn_id = transactions.create_pending_transfer(
            2, 3, Decimal("80000.00"), actor_user_id=2
        )

        # Simulate balance reduction before approval
        conn = db.get_connection()
        try:
            conn.execute("UPDATE Accounts SET balance = '50000.00' WHERE account_id = 2")
        finally:
            conn.close()

        ok, msg = transactions.approve_pending_transfer(txn_id, approver_user_id=1)
        assert ok is False
        assert "insufficient" in msg.lower()

        # Balances remain intact and transfer is marked rejected
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("50000.00")
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal("25000.00")
        assert transactions.get_pending_transfers(admin_user_id=1) == []

        txns = transactions.get_transactions_for_account(2, actor_user_id=2)
        assert len(txns) == 1
        assert txns[0]["status"] == "rejected"

    def test_rejection_leaves_balances_unchanged_and_releases_reserved_amount(
        self, mc_db, monkeypatch, capsys
    ):
        _cli_transfer(monkeypatch, capsys, user_id=2, to_account_id=3, amount_str="100000.00")
        txn_id = transactions.get_pending_transfers(admin_user_id=1)[0]["txn_id"]

        # While pending, Alice only has 20,000.00 unreserved
        assert transactions.withdraw(2, Decimal("30000.00"), actor_user_id=2) is False

        ok, msg = transactions.reject_pending_transfer(
            txn_id, approver_user_id=1, reason="Dual control declined"
        )
        assert ok is True
        assert "rejected" in msg.lower()

        # Balances unchanged and pending queue empty
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("120000.00")
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal("25000.00")
        assert transactions.get_pending_transfers(admin_user_id=1) == []

        # Reserved funds are released after rejection
        assert transactions.withdraw(2, Decimal("30000.00"), actor_user_id=2) is True
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal("90000.00")

    def test_duplicate_approval_or_rejection_is_rejected(self, mc_db):
        # Completed transfer cannot be approved or rejected again
        txn_complete = transactions.create_pending_transfer(
            2, 3, Decimal("60000.00"), actor_user_id=2
        )
        assert transactions.approve_pending_transfer(txn_complete, 1)[0] is True
        assert transactions.approve_pending_transfer(txn_complete, 4)[0] is False
        assert transactions.reject_pending_transfer(txn_complete, 4)[0] is False

        # Rejected transfer cannot be approved or rejected again
        txn_reject = transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )
        assert transactions.reject_pending_transfer(txn_reject, 1, "Nope")[0] is True
        assert transactions.approve_pending_transfer(txn_reject, 4)[0] is False
        assert transactions.reject_pending_transfer(txn_reject, 4)[0] is False

        # Audit hash chain remains valid after all operations
        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

