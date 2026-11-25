"""
tests/test_intrusion_and_unlock.py -- Phase 8 tests for intrusion detection
(Brute Force lockout + Large Transaction alerts) and admin account unlock.
"""

from decimal import Decimal
import getpass
import pytest

import main
from bank import alerts, audit, auth, config, db, security, transactions


@pytest.fixture
def ids_db(tmp_path, monkeypatch):
    """Isolated SQLite DB with one admin and two standard users."""
    temp_db = str(tmp_path / "ids_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    monkeypatch.setattr(security, "is_odd_hour", lambda *_a, **_kw: False)
    db.init_db()

    pw_hash = auth.hash_password("IdsPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Admin", "admin@ids.local", "admin", "100000.00"),
            ("Alice", "alice@ids.local", "user", "100000.00"),
            ("Bob", "bob@ids.local", "user", "20000.00"),
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


def _cli_login(monkeypatch, capsys, email: str, password: str):
    monkeypatch.setattr("builtins.input", lambda _p="": email)
    monkeypatch.setattr(getpass, "getpass", lambda _p="": password)
    res = main.login()
    out = capsys.readouterr().out
    return res, out


class TestBruteForceLockoutAndAdminUnlock:
    """Verify 3-attempt lockout, single Brute Force alert, and admin-only unlock."""

    def test_three_failed_logins_lock_on_third_and_create_one_alert(
        self, ids_db, monkeypatch, capsys
    ):
        # Attempts 1 & 2: unlocked, no Brute Force alert
        for attempt in (1, 2):
            res, out = _cli_login(monkeypatch, capsys, "alice@ids.local", "Wrong@123")
            assert res == (None, None)
            assert "Invalid email or password." in out
            user = auth.get_user_by_email("alice@ids.local")
            assert user["failed_attempts"] == attempt
            assert user["is_locked"] == 0
            assert alerts.get_all_alerts(admin_user_id=1) == []

        # Attempt 3: locks account and creates exactly one high-severity Brute Force alert
        res3, out3 = _cli_login(monkeypatch, capsys, "alice@ids.local", "Wrong@123")
        assert res3 == (None, None)
        assert "Invalid email or password." in out3
        user = auth.get_user_by_email("alice@ids.local")
        assert user["failed_attempts"] == 3
        assert user["is_locked"] == 1

        all_alerts = alerts.get_all_alerts(admin_user_id=1)
        bf_alerts = [a for a in all_alerts if a["alert_type"] == "Brute Force"]
        assert len(bf_alerts) == 1
        assert bf_alerts[0]["user_id"] == 2
        assert bf_alerts[0]["severity"] == "high"

        # Attempt 4 (wrong and right passwords): denied generically, no duplicate alert
        res4_wrong, out4_wrong = _cli_login(
            monkeypatch, capsys, "alice@ids.local", "Wrong@123"
        )
        res4_right, out4_right = _cli_login(
            monkeypatch, capsys, "alice@ids.local", "IdsPass@123"
        )
        assert res4_wrong == (None, None)
        assert res4_right == (None, None)
        assert "Invalid email or password." in out4_wrong
        assert "locked" not in out4_wrong.lower()
        assert out4_wrong == out3
        assert out4_right == out3

        bf_alerts_after = [
            a
            for a in alerts.get_all_alerts(admin_user_id=1)
            if a["alert_type"] == "Brute Force"
        ]
        assert len(bf_alerts_after) == 1

    def test_normal_user_cannot_unlock_and_admin_unlock_restores_login(
        self, ids_db, monkeypatch, capsys
    ):
        for _ in range(config.MAX_FAILED_LOGINS):
            _cli_login(monkeypatch, capsys, "alice@ids.local", "Wrong@123")

        # Normal user (Bob, user_id=3) cannot unlock via data layer or CLI
        assert auth.unlock_user(2, admin_user_id=3) is False
        assert auth.get_user_by_email("alice@ids.local")["is_locked"] == 1

        session = security.Session()
        main.manage_locked_users(3, "user", session)
        assert "Access denied" in capsys.readouterr().out
        assert auth.get_user_by_email("alice@ids.local")["is_locked"] == 1

        # Admin (user_id=1) unlocks Alice via CLI
        monkeypatch.setattr("builtins.input", lambda _p="": "2")
        main.manage_locked_users(1, "admin", session)
        assert "unlocked successfully" in capsys.readouterr().out

        alice = auth.get_user_by_email("alice@ids.local")
        assert alice["is_locked"] == 0
        assert alice["failed_attempts"] == 0

        logs = audit.get_audit_log(admin_user_id=1)
        assert any("Admin unlocked account for user #2" in r["action"] for r in logs)

        # Restored login works with correct password
        res, out = _cli_login(monkeypatch, capsys, "alice@ids.local", "IdsPass@123")
        assert res == (2, "user")
        assert "Welcome Alice!" in out


class TestLargeTransactionAlerts:
    """Verify high-severity Large Transaction alerts across deposit/withdraw/transfer."""

    def test_large_deposit_creates_single_alert_and_executes_immediately(
        self, ids_db, monkeypatch, capsys
    ):
        session = security.Session()
        monkeypatch.setattr("builtins.input", lambda _p="": "50000.01")
        main.do_deposit(2, session)
        capsys.readouterr()

        acc = transactions.get_account_by_user(2)
        assert acc["balance"] == Decimal("150000.01")

        large_alerts = [
            a
            for a in alerts.get_all_alerts(admin_user_id=1)
            if a["alert_type"] == "Large Transaction"
        ]
        assert len(large_alerts) == 1
        assert large_alerts[0]["severity"] == "high"
        assert large_alerts[0]["user_id"] == 2

    def test_large_withdrawal_creates_single_alert_and_executes_immediately(
        self, ids_db, monkeypatch, capsys
    ):
        session = security.Session()
        monkeypatch.setattr("builtins.input", lambda _p="": "60000.00")
        main.do_withdraw(2, session)
        capsys.readouterr()

        acc = transactions.get_account_by_user(2)
        assert acc["balance"] == Decimal("40000.00")

        large_alerts = [
            a
            for a in alerts.get_all_alerts(admin_user_id=1)
            if a["alert_type"] == "Large Transaction"
        ]
        assert len(large_alerts) == 1
        assert large_alerts[0]["severity"] == "high"
        assert large_alerts[0]["user_id"] == 2

    def test_large_transfer_request_creates_single_alert_and_no_duplicate_on_approval(
        self, ids_db, monkeypatch, capsys
    ):
        session = security.Session()
        inputs = iter(["3", "75000.00"])
        monkeypatch.setattr("builtins.input", lambda _p="": next(inputs))
        main.do_transfer(2, session)
        capsys.readouterr()

        pending = transactions.get_pending_transfers(admin_user_id=1)
        assert len(pending) == 1
        assert pending[0]["amount"] == Decimal("75000.00")

        large_alerts = [
            a
            for a in alerts.get_all_alerts(admin_user_id=1)
            if a["alert_type"] == "Large Transaction"
        ]
        assert len(large_alerts) == 1
        assert large_alerts[0]["severity"] == "high"

        # Approving the pending transfer must not create a duplicate alert
        ok, _ = transactions.approve_pending_transfer(
            pending[0]["txn_id"], approver_user_id=1
        )
        assert ok is True
        large_alerts_after = [
            a
            for a in alerts.get_all_alerts(admin_user_id=1)
            if a["alert_type"] == "Large Transaction"
        ]
        assert len(large_alerts_after) == 1

    def test_threshold_boundary_behavior(self, ids_db):
        # Exactly at threshold (50000.00) -> no Large Transaction alert
        transactions.deposit(2, config.LARGE_TXN_THRESHOLD, actor_user_id=2)
        assert transactions.withdraw(2, config.LARGE_TXN_THRESHOLD, actor_user_id=2) is True
        assert (
            transactions.transfer(2, 3, config.LARGE_TXN_THRESHOLD, actor_user_id=2)
            is True
        )
        assert alerts.get_all_alerts(admin_user_id=1) == []

        # Strictly above threshold (50000.01) -> creates 1 Large Transaction alert
        transactions.deposit(
            2, config.LARGE_TXN_THRESHOLD + Decimal("0.01"), actor_user_id=2
        )
        large_alerts = alerts.get_all_alerts(admin_user_id=1)
        assert len(large_alerts) == 1
        assert large_alerts[0]["alert_type"] == "Large Transaction"
        assert large_alerts[0]["severity"] == "high"

    def test_failed_and_rolled_back_transactions_create_no_alerts(
        self, ids_db, monkeypatch
    ):
        # 1. Insufficient balance withdrawal (> 50,000 on Bob who has 20,000)
        assert transactions.withdraw(3, Decimal("60000.00"), actor_user_id=3) is False
        # 2. Insufficient balance transfer
        assert transactions.transfer(3, 2, Decimal("60000.00"), actor_user_id=3) is False
        # 3. Insufficient balance pending transfer
        with pytest.raises(ValueError, match="Insufficient available balance"):
            transactions.create_pending_transfer(
                3, 2, Decimal("60000.00"), actor_user_id=3
            )
        assert alerts.get_all_alerts(admin_user_id=1) == []

        # 4. Simulated mid-transaction rollback on large deposit
        orig_get_conn = db.get_connection

        class _FailCommitConn:
            def __init__(self, real_conn):
                self._conn = real_conn

            @property
            def in_transaction(self):
                return self._conn.in_transaction

            def execute(self, sql, params=()):
                if sql.strip().upper() == "COMMIT":
                    raise RuntimeError("Simulated commit failure")
                return self._conn.execute(sql, params)

            def close(self):
                self._conn.close()

        monkeypatch.setattr(
            db, "get_connection", lambda: _FailCommitConn(orig_get_conn())
        )
        with pytest.raises(RuntimeError, match="Simulated commit failure"):
            transactions.deposit(2, Decimal("80000.00"), actor_user_id=2)
        monkeypatch.setattr(db, "get_connection", orig_get_conn)

        assert alerts.get_all_alerts(admin_user_id=1) == []

