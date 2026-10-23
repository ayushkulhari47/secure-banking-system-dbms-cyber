"""
tests/test_cyber_controls.py  Phase 3 Cyber Controls & IT Audit Testing Evidence.

Covers IT Audit & Cyber Risk Controls:
  - ISO 27001 A.12.1.1 (Operational Procedures / Centralized Configuration)
  - ISO 27001 A.12.4.1 / A.12.4.3 (Event Logging & Tamper-Evident Hash Chaining)
  - ISO 27001 A.6.1.2 (Segregation of Duties / Maker-Checker Dual Control)
  - ISO 27001 A.9.4.2 (User Account Management / Admin Unlock Remediation)
  - ISO 27001 A.16.1.4 (Information Security Incident Assessment & Resolution)

Run: pytest tests/test_cyber_controls.py -v
"""

import os
import sqlite3
import pytest

import config
import db


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """
    Hermetic test database fixture:
    Redirects db.DB_PATH to an isolated SQLite file for each test,
    initializes the schema, and seeds demo data.
    """
    temp_db_path = str(tmp_path / "test_banking.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db_path)
    db.init_db()
    return temp_db_path


# ===========================================================================
# 1. Centralized Security Configuration (ISO 27001 A.12.1.1)
# ===========================================================================

class TestCentralizedConfiguration:
    """Control: Tuneable parameters must be centralized and properly typed."""

    def test_configuration_constants_exist(self):
        assert hasattr(config, "LARGE_TXN_THRESHOLD")
        assert hasattr(config, "MAX_FAILED_LOGINS")
        assert hasattr(config, "SESSION_TIMEOUT_SECONDS")
        assert hasattr(config, "MIN_PASSWORD_LENGTH")
        assert hasattr(config, "MIN_AMOUNT")
        assert hasattr(config, "MAX_AMOUNT")
        assert hasattr(config, "BCRYPT_ROUNDS")

    def test_configuration_values_within_safe_bounds(self):
        assert config.LARGE_TXN_THRESHOLD == 50_000.00
        assert config.MAX_FAILED_LOGINS == 3
        assert config.SESSION_TIMEOUT_SECONDS == 300
        assert config.MIN_PASSWORD_LENGTH == 8
        assert config.MIN_AMOUNT == 0.01
        assert config.MAX_AMOUNT == 1_000_000.00
        assert config.BCRYPT_ROUNDS == 12

    def test_database_configuration_constants_exist(self):
        assert hasattr(config, "DB_TYPE")
        assert hasattr(config, "DB_PATH")
        assert hasattr(config, "DB_HOST")
        assert hasattr(config, "DB_PORT")
        assert hasattr(config, "DB_USER")
        assert hasattr(config, "DB_PASSWORD")
        assert hasattr(config, "DB_NAME")

    def test_dotenv_loader_parses_custom_file(self, tmp_path):
        custom_env = tmp_path / "custom.env"
        custom_env.write_text("TEST_BANK_KEY=secret_value\n# Comment line\nDB_TEST_PORT=9999\n", encoding="utf-8")
        config.load_dotenv(str(custom_env))
        assert os.environ.get("TEST_BANK_KEY") == "secret_value"
        assert os.environ.get("DB_TEST_PORT") == "9999"




# ===========================================================================
# 2. Tamper-Evident Audit Logging (ISO 27001 A.12.4.1 & A.12.4.3)
# ===========================================================================

class TestTamperEvidentAuditLog:
    """Control: Cryptographic hash chaining ensures audit logs are tamper-evident."""

    def test_audit_log_hash_chain_creation(self, test_db):
        """Writing audit entries creates a cryptographic SHA-256 hash chain."""
        db.log_action(1, "First action")
        db.log_action(2, "Second action")
        db.log_action(3, "Third action")

        conn = db.get_connection()
        rows = conn.execute("SELECT * FROM Audit_Log ORDER BY log_id ASC").fetchall()
        conn.close()

        assert len(rows) >= 3
        # First entry in chain must link to GENESIS_HASH
        assert rows[0]["previous_hash"] == db.GENESIS_HASH
        assert rows[0]["entry_hash"] is not None
        # Subsequent entries link to previous entry_hash
        assert rows[1]["previous_hash"] == rows[0]["entry_hash"]
        assert rows[2]["previous_hash"] == rows[1]["entry_hash"]

    def test_audit_log_integrity_passes_when_untampered(self, test_db):
        """verify_audit_log_integrity() returns (True, None) for legitimate audit log."""
        db.log_action(1, "User login")
        db.log_action(1, "User deposit")
        db.log_action(2, "User transfer")

        is_valid, corrupted_id = db.verify_audit_log_integrity()
        assert is_valid is True
        assert corrupted_id is None

    def test_tamper_detection_on_modified_action(self, test_db):
        """If an attacker modifies the action text of an audit row, the integrity check fails."""
        db.log_action(1, "Legitimate transfer of Rs500")
        db.log_action(2, "Password change")
        db.log_action(3, "Account view")

        # Attacker modifies the second entry directly in SQLite
        conn = db.get_connection()
        conn.execute("UPDATE Audit_Log SET action = 'Falsified record' WHERE log_id = 2")
        conn.close()

        is_valid, corrupted_id = db.verify_audit_log_integrity()
        assert is_valid is False
        assert corrupted_id == 2, "Integrity check must pinpoint the exact corrupted record ID"

    def test_tamper_detection_on_broken_hash_link(self, test_db):
        """If an attacker deletes or alters a hash link, integrity check detects the rupture."""
        db.log_action(1, "Step 1")
        db.log_action(1, "Step 2")
        db.log_action(1, "Step 3")

        # Attacker falsifies the previous_hash link
        conn = db.get_connection()
        conn.execute("UPDATE Audit_Log SET previous_hash = 'badhash123' WHERE log_id = 3")
        conn.close()

        is_valid, corrupted_id = db.verify_audit_log_integrity()
        assert is_valid is False
        assert corrupted_id == 3


# ===========================================================================
# 3. Maker-Checker Dual Control & Segregation of Duties (ISO 27001 A.6.1.2)
# ===========================================================================

class TestMakerCheckerWorkflow:
    """Control: High-value transactions require Maker-Checker authorization with SoD."""

    def test_pending_transfer_does_not_modify_balances(self, test_db):
        """When a pending transfer is created, no money is deducted or credited."""
        # Rahul (user_id 2, account_id 2, balance 25000)
        # Ayush (user_id 1, account_id 1, balance 50000)
        acc_rahul_before = db.get_account_by_id(2)["balance"]
        acc_ayush_before = db.get_account_by_id(1)["balance"]

        txn_id = db.create_pending_transfer(from_account_id=2, to_account_id=1, amount=10000.00)
        assert txn_id > 0

        acc_rahul_after = db.get_account_by_id(2)["balance"]
        acc_ayush_after = db.get_account_by_id(1)["balance"]

        assert acc_rahul_after == acc_rahul_before
        assert acc_ayush_after == acc_ayush_before

        pending = db.get_pending_transfers()
        assert any(t["txn_id"] == txn_id for t in pending)

    def test_segregation_of_duties_prevents_maker_self_approval(self, test_db):
        """Segregation of Duties (SoD): The maker cannot approve their own transaction."""
        # Rahul (user_id 2, account_id 2) initiates transfer
        txn_id = db.create_pending_transfer(from_account_id=2, to_account_id=1, amount=5000.00)

        # Rahul tries to approve his own transfer
        success, message = db.approve_pending_transfer(txn_id=txn_id, approver_user_id=2)
        assert success is False
        assert "Segregation of Duties" in message

        # Balances remain intact
        assert db.get_account_by_id(2)["balance"] == 25000.00

    def test_checker_approval_executes_transfer_atomically(self, test_db):
        """An authorized independent checker can approve, executing the atomic debit & credit."""
        # Rahul (account_id 2, balance 25000) -> Priya (account_id 3, balance 15000)
        txn_id = db.create_pending_transfer(from_account_id=2, to_account_id=3, amount=8000.00)

        # Ayush (admin, user_id 1) approves
        success, message = db.approve_pending_transfer(txn_id=txn_id, approver_user_id=1)
        assert success is True
        assert "approved" in message.lower()

        assert db.get_account_by_id(2)["balance"] == 17000.00  # 25000 - 8000
        assert db.get_account_by_id(3)["balance"] == 23000.00  # 15000 + 8000

        # Check transaction status updated to completed
        conn = db.get_connection()
        txn = conn.execute("SELECT status FROM Transactions WHERE txn_id = ?", (txn_id,)).fetchone()
        conn.close()
        assert txn["status"] == "completed"

    def test_checker_rejection_marks_transaction_rejected(self, test_db):
        """A checker can reject a transfer, leaving balances completely untouched."""
        txn_id = db.create_pending_transfer(from_account_id=2, to_account_id=3, amount=5000.00)

        success, message = db.reject_pending_transfer(txn_id=txn_id, approver_user_id=1, reason="Suspicious pattern")
        assert success is True

        # Balances unchanged
        assert db.get_account_by_id(2)["balance"] == 25000.00
        assert db.get_account_by_id(3)["balance"] == 15000.00

        conn = db.get_connection()
        txn = conn.execute("SELECT status FROM Transactions WHERE txn_id = ?", (txn_id,)).fetchone()
        conn.close()
        assert txn["status"] == "rejected"

    def test_insufficient_funds_at_approval_time_rejects(self, test_db):
        """If the maker spends funds before checker approves, approval fails safely."""
        # Rahul has 25000
        txn_id = db.create_pending_transfer(from_account_id=2, to_account_id=3, amount=20000.00)

        # Rahul withdraws 10000, leaving only 15000 in balance
        assert db.withdraw(2, 10000.00) is True

        # Admin tries to approve the 20000 transfer
        success, message = db.approve_pending_transfer(txn_id=txn_id, approver_user_id=1)
        assert success is False
        assert "insufficient" in message.lower()

        # Balance remains 15000 (not negative)
        assert db.get_account_by_id(2)["balance"] == 15000.00


# ===========================================================================
# 4. User Account Lockout & Admin Unlock (ISO 27001 A.9.4.2)
# ===========================================================================

class TestAdminAccountUnlock:
    """Control: Corrective control allowing admins to unlock brute-force locked accounts."""

    def test_account_locks_after_max_failed_attempts(self, test_db):
        """Account is locked when failed attempts hit MAX_FAILED_LOGINS."""
        # User 2 (Rahul)
        for _ in range(config.MAX_FAILED_LOGINS):
            db.increment_failed_attempts(2)

        user = db.get_user_by_email("rahul@bank.com")
        assert user["is_locked"] == 1
        assert user["failed_attempts"] >= config.MAX_FAILED_LOGINS

        locked_users = db.get_locked_users()
        assert any(u["user_id"] == 2 for u in locked_users)

    def test_admin_unlock_clears_lockout_and_resets_counter(self, test_db):
        """Admin unlock sets is_locked=0 and resets failed_attempts=0."""
        for _ in range(config.MAX_FAILED_LOGINS):
            db.increment_failed_attempts(2)

        assert db.unlock_user(user_id=2, admin_user_id=1) is True

        user = db.get_user_by_email("rahul@bank.com")
        assert user["is_locked"] == 0
        assert user["failed_attempts"] == 0

        locked_users = db.get_locked_users()
        assert not any(u["user_id"] == 2 for u in locked_users)


# ===========================================================================
# 5. Security Alert Remediation (ISO 27001 A.16.1.4)
# ===========================================================================

class TestSecurityAlertRemediation:
    """Control: Corrective incident response control to track and resolve alerts."""

    def test_raise_and_resolve_security_alert(self, test_db):
        """Alert starts as 'open' and changes to 'resolved' on admin remediation."""
        db.raise_alert(user_id=2, alert_type="Brute Force", description="3 failed attempts", severity="high")

        open_alerts = db.get_open_alerts()
        assert len(open_alerts) >= 1
        target_alert = open_alerts[0]
        assert target_alert["status"] == "open"

        # Resolve alert
        assert db.resolve_alert(alert_id=target_alert["alert_id"], admin_user_id=1) is True

        # Verify no longer in open alerts
        remaining_open = db.get_open_alerts()
        assert not any(a["alert_id"] == target_alert["alert_id"] for a in remaining_open)
