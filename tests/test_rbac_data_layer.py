"""
tests/test_rbac_data_layer.py -- Phase 4 tests verifying RBAC, ownership checks,
and Maker-Checker Segregation of Duties directly at the bank/ data layer.
"""

import pytest

from bank import alerts, audit, auth, config, db, transactions


@pytest.fixture
def rbac_db(tmp_path, monkeypatch):
    """
    Isolated SQLite DB with:
      1: Admin One   (admin, acc 1, Rs 100,000)
      2: User Two    (user,  acc 2, Rs 100,000)
      3: User Three  (user,  acc 3, Rs 50,000)
      4: Admin Four  (admin, acc 4, Rs 50,000)
    """
    temp_db = str(tmp_path / "rbac_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    pw_hash = auth.hash_password("RbacPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Admin One", "admin1@test.local", "admin", 100000.00),
            ("User Two", "user2@test.local", "user", 100000.00),
            ("User Three", "user3@test.local", "user", 50000.00),
            ("Admin Four", "admin4@test.local", "admin", 50000.00),
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


class TestOwnershipEnforcement:
    """Normal users can only access and mutate their own account and password."""

    def test_cross_user_account_read_blocked(self, rbac_db):
        with pytest.raises(PermissionError):
            transactions.get_account_by_id(3, actor_user_id=2)
        with pytest.raises(PermissionError):
            transactions.get_account_by_id(2, actor_user_id=None)

        # Owner and admin can read
        assert transactions.get_account_by_id(2, actor_user_id=2)["user_id"] == 2
        assert transactions.get_account_by_id(2, actor_user_id=1)["user_id"] == 2

    def test_cross_user_transactions_read_blocked(self, rbac_db):
        transactions.deposit(3, 250.00, actor_user_id=3)
        with pytest.raises(PermissionError):
            transactions.get_transactions_for_account(3, actor_user_id=2)
        with pytest.raises(PermissionError):
            transactions.get_transactions_for_account(3, actor_user_id=None)

        assert len(transactions.get_transactions_for_account(3, actor_user_id=3)) == 1
        assert len(transactions.get_transactions_for_account(3, actor_user_id=1)) == 1

    def test_cross_user_deposit_withdraw_transfer_blocked(self, rbac_db):
        # Normal user cannot mutate another user's account
        with pytest.raises(PermissionError):
            transactions.deposit(3, 100.00, actor_user_id=2)
        with pytest.raises(PermissionError):
            transactions.withdraw(3, 100.00, actor_user_id=2)
        with pytest.raises(PermissionError):
            transactions.transfer(3, 2, 100.00, actor_user_id=2)
        with pytest.raises(PermissionError):
            transactions.create_pending_transfer(3, 2, 60000.00, actor_user_id=2)

        # Even admins cannot deposit/withdraw/transfer from another user's account
        with pytest.raises(PermissionError):
            transactions.deposit(2, 100.00, actor_user_id=1)
        with pytest.raises(PermissionError):
            transactions.withdraw(2, 100.00, actor_user_id=1)
        with pytest.raises(PermissionError):
            transactions.transfer(2, 3, 100.00, actor_user_id=1)
        with pytest.raises(PermissionError):
            transactions.create_pending_transfer(2, 3, 60000.00, actor_user_id=1)

        # Balances remain untouched
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == 100000.00
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == 50000.00

    def test_owner_can_deposit_withdraw_and_transfer(self, rbac_db):
        transactions.deposit(2, 500.00, actor_user_id=2)
        assert transactions.withdraw(2, 200.00, actor_user_id=2) is True
        assert transactions.transfer(2, 3, 300.00, actor_user_id=2) is True
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == 100000.00
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == 50300.00

    def test_cross_user_change_password_blocked(self, rbac_db):
        with pytest.raises(PermissionError):
            auth.change_password(
                3, "RbacPass@123", "NewStrong@123", actor_user_id=2
            )
        with pytest.raises(PermissionError):
            auth.change_password(
                2, "RbacPass@123", "NewStrong@123", actor_user_id=1
            )
        with pytest.raises(PermissionError):
            auth.change_password(2, "RbacPass@123", "NewStrong@123")

        ok, err = auth.change_password(
            2, "RbacPass@123", "NewStrong@123", actor_user_id=2
        )
        assert ok is True
        assert err is None


class TestAdminOnlyDataLayerControls:
    """Only admins can access global transactions, audit, alerts, and user unlock."""

    def test_all_transactions_admin_only(self, rbac_db):
        transactions.deposit(2, 100.00, actor_user_id=2)
        assert transactions.get_all_transactions(admin_user_id=2) == []
        assert transactions.get_all_transactions(admin_user_id=None) == []
        assert len(transactions.get_all_transactions(admin_user_id=1)) == 1

    def test_audit_log_and_integrity_admin_only(self, rbac_db):
        audit.log_action(2, "User action")
        assert audit.get_audit_log(admin_user_id=2) == []
        assert audit.get_audit_log(admin_user_id=None) == []
        assert len(audit.get_audit_log(admin_user_id=1)) == 1

        with pytest.raises(PermissionError):
            audit.verify_audit_log_integrity(admin_user_id=2)
        with pytest.raises(PermissionError):
            audit.verify_audit_log_integrity()

        assert audit.verify_audit_log_integrity(admin_user_id=1) == (True, None)

    def test_alerts_admin_only(self, rbac_db):
        alert_id = alerts.raise_alert(2, "Brute Force", "Locked", severity="high")

        assert alerts.get_all_alerts(admin_user_id=2) == []
        assert alerts.get_open_alerts(admin_user_id=2) == []
        assert alerts.review_alert(alert_id, admin_user_id=2, note="nope") is False
        assert alerts.close_alert(alert_id, admin_user_id=2, note="nope") is False
        assert alerts.resolve_alert(alert_id, admin_user_id=2) is False

        assert len(alerts.get_open_alerts(admin_user_id=1)) == 1
        assert alerts.review_alert(alert_id, admin_user_id=1, note="checked") is True
        assert alerts.close_alert(alert_id, admin_user_id=1, note="done") is True

    def test_locked_users_and_unlock_admin_only(self, rbac_db):
        for _ in range(config.MAX_FAILED_LOGINS):
            auth.increment_failed_attempts(3)

        assert auth.get_locked_users(admin_user_id=2) == []
        assert auth.get_locked_users() == []
        assert len(auth.get_locked_users(admin_user_id=1)) == 1

        assert auth.unlock_user(3, admin_user_id=2) is False
        assert auth.get_user_by_email("user3@test.local")["is_locked"] == 1

        assert auth.unlock_user(3, admin_user_id=1) is True
        assert auth.get_user_by_email("user3@test.local")["is_locked"] == 0


class TestMakerCheckerApprovalRules:
    """Approval rejects non-admins, the maker, and an admin recipient."""

    def test_rejects_non_admin_and_allows_independent_admin(self, rbac_db):
        txn_id = transactions.create_pending_transfer(
            2, 3, 60000.00, actor_user_id=2
        )
        assert transactions.get_pending_transfers(admin_user_id=2) == []
        assert len(transactions.get_pending_transfers(admin_user_id=1)) == 1

        ok, msg = transactions.approve_pending_transfer(txn_id, approver_user_id=2)
        assert ok is False
        assert "administrators" in msg.lower()

        ok_rej, _ = transactions.reject_pending_transfer(txn_id, approver_user_id=3)
        assert ok_rej is False

        ok_admin, _ = transactions.approve_pending_transfer(txn_id, approver_user_id=1)
        assert ok_admin is True
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == 40000.00
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == 110000.00

    def test_rejects_maker_admin_self_approval(self, rbac_db):
        # Admin 1 initiates transfer to User 3 -> Admin 1 cannot self-approve
        txn_id = transactions.create_pending_transfer(
            1, 3, 60000.00, actor_user_id=1
        )
        ok, msg = transactions.approve_pending_transfer(txn_id, approver_user_id=1)
        assert ok is False
        assert "maker" in msg.lower()
        assert transactions.get_account_by_id(1, actor_user_id=1)["balance"] == 100000.00

        # Independent Admin 4 can approve
        ok4, _ = transactions.approve_pending_transfer(txn_id, approver_user_id=4)
        assert ok4 is True

    def test_rejects_recipient_admin_approval(self, rbac_db):
        # User 2 initiates transfer to Admin 1 -> Admin 1 (recipient) cannot approve
        txn_id = transactions.create_pending_transfer(
            2, 1, 60000.00, actor_user_id=2
        )
        ok, msg = transactions.approve_pending_transfer(txn_id, approver_user_id=1)
        assert ok is False
        assert "recipient" in msg.lower()
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == 100000.00
        assert transactions.get_account_by_id(1, actor_user_id=1)["balance"] == 100000.00

        # Independent Admin 4 can approve
        ok4, _ = transactions.approve_pending_transfer(txn_id, approver_user_id=4)
        assert ok4 is True
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == 40000.00
        assert transactions.get_account_by_id(1, actor_user_id=1)["balance"] == 160000.00

