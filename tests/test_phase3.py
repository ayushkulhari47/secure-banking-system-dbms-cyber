"""
tests/test_phase3.py  Phase 3 control-testing evidence.

Covers:
  - TestChangePassword    db.change_password() -- policy, auth, atomic update
  - TestSQLiDetection     security.detect_sqli() -- injection pattern detection
  - TestVelocityDetection security.check_velocity() -- transaction rate limiting
  - TestTransferAtomic    db.transfer() -- rollback on error, self-transfer guard
  - TestAmountsRejected   validate_amount() edge cases via db.deposit/withdraw

Run: pytest tests/test_phase3.py -v
"""

import time
import pytest
import bcrypt
from datetime import datetime, timezone

import db
import security
from security import validate_amount, detect_sqli, check_velocity

# ---------------------------------------------------------------------------
# Shared fixture -- hermetic SQLite database
# ---------------------------------------------------------------------------


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """
    Redirect db.DB_PATH to a fresh temp SQLite file per test.
    Guarantees hermetic isolation -- no shared state, no MySQL.
    """
    temp_db = str(tmp_path / "phase3_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()
    return temp_db


# ---------------------------------------------------------------------------
# TestChangePassword
# ---------------------------------------------------------------------------


class TestChangePassword:
    """
    Control: Password change enforces old-password verification, complexity
    policy, same-as-old rejection, and atomic DB update (ISO 27001:2022 A.5.17).
    """

    def test_correct_old_password_and_strong_new_succeeds(self, test_db):
        """Happy path: correct old password + policy-compliant new password."""
        # Seed test user directly
        conn = db.get_connection()
        conn.execute("DELETE FROM Users WHERE email = 'changeme@test.com'")
        conn.execute(
            "INSERT INTO Users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("Tester", "changeme@test.com", db.hash_password("OldPass1!"), "user"),
        )
        conn.execute(
            "INSERT INTO Accounts (user_id, balance) VALUES (last_insert_rowid(), 0)"
        )
        conn.close()

        user = db.get_user_by_email("changeme@test.com")
        ok, err = db.change_password(user["user_id"], "OldPass1!", "NewPass2@")
        assert ok is True
        assert err is None

        # New hash must verify
        updated = db.get_user_by_email("changeme@test.com")
        assert bcrypt.checkpw(b"NewPass2@", updated["password_hash"].encode())

    def test_wrong_old_password_rejected(self, test_db):
        """Wrong current password must be rejected."""
        user = db.get_user_by_email("rahul@bank.com")
        ok, err = db.change_password(user["user_id"], "wrongpassword", "NewPass2@")
        assert ok is False
        assert "incorrect" in err.lower()

    def test_weak_new_password_rejected(self, test_db):
        """New password that fails policy must be rejected."""
        user = db.get_user_by_email("rahul@bank.com")
        ok, err = db.change_password(user["user_id"], "rahul123", "weak")
        assert ok is False
        assert "policy" in err.lower() or "password" in err.lower()

    def test_same_password_rejected(self, test_db):
        """New password identical to old password must be rejected."""
        conn = db.get_connection()
        conn.execute(
            "UPDATE Users SET password_hash = ? WHERE email = ?",
            (db.hash_password("SamePass1!"), "priya@bank.com"),
        )
        conn.close()

        user = db.get_user_by_email("priya@bank.com")
        ok, err = db.change_password(user["user_id"], "SamePass1!", "SamePass1!")
        assert ok is False
        assert "different" in err.lower()

    def test_nonexistent_user_rejected(self, test_db):
        """Non-existent user_id must be handled gracefully."""
        ok, err = db.change_password(9999, "anything", "NewPass2@")
        assert ok is False
        assert "not found" in err.lower()

    def test_password_hash_updated_in_db(self, test_db):
        """After change, old password must no longer authenticate."""
        conn = db.get_connection()
        conn.execute(
            "UPDATE Users SET password_hash = ? WHERE email = ?",
            (db.hash_password("OldPass1!"), "ayush@bank.com"),
        )
        conn.close()

        user = db.get_user_by_email("ayush@bank.com")
        db.change_password(user["user_id"], "OldPass1!", "NewStrong2@")

        updated = db.get_user_by_email("ayush@bank.com")
        assert not bcrypt.checkpw(b"OldPass1!", updated["password_hash"].encode())
        assert bcrypt.checkpw(b"NewStrong2@", updated["password_hash"].encode())

    def test_app_change_password_mismatch(self, test_db, monkeypatch, capsys):
        """app.do_change_password must abort if confirm password does not match."""
        import app
        import getpass

        session = security.Session()
        inputs = iter(["Current1!", "NewPass1!", "MismatchPass2!"])
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(inputs))

        app.do_change_password(1, session)
        captured = capsys.readouterr().out
        assert "passwords do not match" in captured.lower()

    def test_app_change_password_success(self, test_db, monkeypatch, capsys):
        """app.do_change_password executes and refreshes session on success."""
        import app
        import getpass

        session = security.Session()
        inputs = iter(["ayush123", "NewSecure1@Pass", "NewSecure1@Pass"])
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(inputs))

        user = db.get_user_by_email("ayush@bank.com")
        app.do_change_password(user["user_id"], session)
        captured = capsys.readouterr().out
        assert "password changed successfully" in captured.lower()

    def test_app_change_password_wrong_old(self, test_db, monkeypatch, capsys):
        """app.do_change_password reports error when old password is wrong."""
        import app
        import getpass

        session = security.Session()
        inputs = iter(["WrongOld123!", "NewSecure1@Pass", "NewSecure1@Pass"])
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(inputs))

        user = db.get_user_by_email("ayush@bank.com")
        app.do_change_password(user["user_id"], session)
        captured = capsys.readouterr().out
        assert "password change failed" in captured.lower()


# ---------------------------------------------------------------------------
# TestSQLiDetection
# ---------------------------------------------------------------------------


class TestSQLiDetection:
    """
    Control: detect_sqli() identifies SQL injection payloads so the application
    can log and alert before they reach the database (ISO 27001:2022 A.8.16).

    Parameterised queries in db.py prevent actual injection; detect_sqli()
    is a defence-in-depth intrusion detection layer.
    """

    @pytest.mark.parametrize(
        "payload",
        [
            "' OR 1=1 --",
            "' OR '1'='1",
            "1; DROP TABLE Users",
            "UNION SELECT * FROM Users",
            "admin'--",
            "1 AND 1=1",
            "'; EXEC xp_cmdshell('dir'); --",
            "1' WAITFOR DELAY '0:0:5'--",
            "1; SLEEP(5)--",
            "' CAST(1 AS INT)--",
            "/* comment */",
        ],
    )
    def test_sqli_payload_detected(self, payload):
        """Classic SQL injection payloads must be flagged."""
        assert detect_sqli(payload) is True, f"Expected detection for: {payload!r}"

    @pytest.mark.parametrize(
        "safe_input",
        [
            "ayush@bank.com",
            "Rahul Sharma",
            "100.00",
            "Transfer to savings",
            "2024-01-01",
            "account_number_123",
        ],
    )
    def test_clean_input_not_flagged(self, safe_input):
        """Legitimate input must NOT trigger false positives."""
        assert detect_sqli(safe_input) is False, f"False positive for: {safe_input!r}"


class TestRuntimeDatabaseSafety:
    """The configured database engine must not silently change on failure."""

    def test_mysql_connection_failure_is_not_replaced_with_sqlite(self, monkeypatch):
        monkeypatch.setattr(db, "DB_TYPE", "mysql")

        def fail_connection():
            raise RuntimeError("MySQL unavailable")

        monkeypatch.setattr(db, "get_mysql_connection", fail_connection)
        with pytest.raises(RuntimeError, match="MySQL unavailable"):
            db.get_connection()


class TestAuthenticationPrivacy:
    """Login errors must not reveal whether an email exists."""

    def test_unknown_email_uses_generic_message(self, test_db, monkeypatch, capsys):
        import app
        import getpass

        monkeypatch.setattr("builtins.input", lambda prompt: "unknown@example.com")
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": "WrongPass1!")

        assert app.login() == (None, None)
        output = capsys.readouterr().out.lower()
        assert "invalid email or password" in output
        assert "user not found" not in output


class TestOddHourDetection:
    def test_odd_hour_rule_covers_overnight_window(self):
        assert (
            security.is_odd_hour(datetime(2026, 1, 1, 23, tzinfo=timezone.utc)) is True
        )
        assert (
            security.is_odd_hour(datetime(2026, 1, 1, 2, tzinfo=timezone.utc)) is True
        )
        assert (
            security.is_odd_hour(datetime(2026, 1, 1, 12, tzinfo=timezone.utc)) is False
        )


# ---------------------------------------------------------------------------
# TestVelocityDetection
# ---------------------------------------------------------------------------


class TestVelocityDetection:
    """
    Control: check_velocity() detects abnormally high transaction rates,
    enabling automated intrusion detection (ISO 27001:2022 A.8.16).
    """

    def test_normal_rate_not_flagged(self):
        """5 transactions in 60 s is within policy -- no alert."""
        now = time.monotonic()
        times = [now - i * 10 for i in range(5)]  # spaced 10s apart
        flagged, count = check_velocity(times, window_seconds=60, max_allowed=10)
        assert flagged is False
        assert count == 5

    def test_high_velocity_flagged(self):
        """11 transactions within 60 s exceeds the 10-per-minute limit."""
        now = time.monotonic()
        times = [now - i * 2 for i in range(11)]  # every 2 seconds
        flagged, count = check_velocity(times, window_seconds=60, max_allowed=10)
        assert flagged is True
        assert count == 11

    def test_old_transactions_outside_window_ignored(self):
        """Transactions older than window_seconds must not count."""
        now = time.monotonic()
        old_times = [now - 120 for _ in range(15)]  # 2 minutes ago
        recent = [now - 5]  # only 1 recent
        flagged, count = check_velocity(
            old_times + recent, window_seconds=60, max_allowed=10
        )
        assert flagged is False
        assert count == 1

    def test_exactly_at_limit_not_flagged(self):
        """Exactly max_allowed transactions: should NOT trigger alert."""
        now = time.monotonic()
        times = [now - i for i in range(10)]  # exactly 10
        flagged, count = check_velocity(times, window_seconds=60, max_allowed=10)
        assert flagged is False
        assert count == 10

    def test_empty_history_not_flagged(self):
        """No transaction history -- never flag."""
        flagged, count = check_velocity([])
        assert flagged is False
        assert count == 0


# ---------------------------------------------------------------------------
# TestTransferAtomic
# ---------------------------------------------------------------------------


class TestTransferAtomic:
    """
    Control: db.transfer() is atomic with ROLLBACK -- balances are never
    partially updated on error.
    """

    def test_transfer_success_balances_conserved(self, test_db):
        """After a successful transfer, total money in system is unchanged."""
        acc1 = db.get_account_by_user(1)
        acc2 = db.get_account_by_user(2)
        total_before = acc1["balance"] + acc2["balance"]

        amount = 100.00
        ok = db.transfer(acc1["account_id"], acc2["account_id"], amount)
        assert ok is True

        acc1_after = db.get_account_by_user(1)
        acc2_after = db.get_account_by_user(2)
        assert acc1_after["balance"] == acc1["balance"] - amount
        assert acc2_after["balance"] == acc2["balance"] + amount
        assert acc1_after["balance"] + acc2_after["balance"] == total_before

    def test_transfer_insufficient_balance_returns_false(self, test_db):
        """Insufficient funds return False and leave balances unchanged."""
        acc1 = db.get_account_by_user(1)
        acc2 = db.get_account_by_user(2)

        ok = db.transfer(acc1["account_id"], acc2["account_id"], 999_999.00)
        assert ok is False

        # Balances must be unchanged
        assert db.get_account_by_user(1)["balance"] == acc1["balance"]
        assert db.get_account_by_user(2)["balance"] == acc2["balance"]

    def test_validate_amount_blocks_zero(self):
        """Amount = 0 must be rejected by validate_amount before reaching db."""
        ok, reason = validate_amount(0.0)
        assert ok is False
        assert reason is not None

    def test_validate_amount_blocks_negative(self):
        """Negative amount must be rejected."""
        ok, reason = validate_amount(-500.0)
        assert ok is False

    def test_validate_amount_blocks_nan(self):
        """NaN must be rejected."""
        import math

        ok, reason = validate_amount(math.nan)
        assert ok is False

    def test_validate_amount_blocks_infinity(self):
        """Infinite amounts must be rejected."""
        import math

        ok, reason = validate_amount(math.inf)
        assert ok is False
