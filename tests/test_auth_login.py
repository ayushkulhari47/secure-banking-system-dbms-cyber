"""
tests/test_auth_login.py -- Phase 3 authentication, bcrypt, and lockout tests
exercising the real main.login() and auth.authenticate() flow.
"""

import getpass
from pathlib import Path
import pytest

import main
from bank import alerts, auth, config, db
from scripts import seed_demo


@pytest.fixture
def auth_db(tmp_path, monkeypatch):
    """Isolated SQLite database seeded with one admin and one user via bcrypt."""
    temp_db = str(tmp_path / "auth_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, pw, role in (
            ("Test Admin", "admin@test.local", "AdminPass@123", "admin"),
            ("Test User", "user@test.local", "UserPass@123", "user"),
        ):
            cur = conn.execute(
                "INSERT INTO Users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (name, email, auth.hash_password(pw), role),
            )
            conn.execute(
                "INSERT INTO Accounts (user_id, balance) VALUES (?, ?)",
                (cur.lastrowid, 10000.00),
            )
        conn.execute("COMMIT")
    finally:
        conn.close()
    return temp_db


def _attempt_login(monkeypatch, capsys, email: str, password: str):
    monkeypatch.setattr("builtins.input", lambda _prompt="": email)
    monkeypatch.setattr(getpass, "getpass", lambda _prompt="": password)
    result = main.login()
    out = capsys.readouterr().out.strip().splitlines()[-1]
    return result, out


class TestLoginHardening:
    """Verify constant-work bcrypt verification, generic errors, and lockout."""

    def test_login_uses_bcrypt_verification_and_succeeds(
        self, auth_db, monkeypatch, capsys
    ):
        calls = []
        orig_verify = auth.verify_password

        def spy_verify(plain, stored_hash):
            calls.append(stored_hash)
            return orig_verify(plain, stored_hash)

        monkeypatch.setattr(auth, "verify_password", spy_verify)

        result, out = _attempt_login(
            monkeypatch, capsys, "user@test.local", "UserPass@123"
        )
        assert result == (2, "user")
        assert "Welcome Test User!" in out
        assert len(calls) == 1
        assert calls[0].startswith("$2b$")

    def test_identical_error_message_and_bcrypt_work_for_all_failures(
        self, auth_db, monkeypatch, capsys
    ):
        calls = []
        orig_verify = auth.verify_password

        def spy_verify(plain, stored_hash):
            calls.append(stored_hash)
            return orig_verify(plain, stored_hash)

        monkeypatch.setattr(auth, "verify_password", spy_verify)

        # 1. Unknown email -> dummy hash verified
        res_unknown, msg_unknown = _attempt_login(
            monkeypatch, capsys, "nobody@test.local", "AnyPass@123"
        )
        assert res_unknown == (None, None)
        assert msg_unknown == "Invalid email or password."
        assert calls[-1] == auth.DUMMY_PASSWORD_HASH

        # 2. Wrong password on existing user -> account hash verified
        res_wrong, msg_wrong = _attempt_login(
            monkeypatch, capsys, "user@test.local", "WrongPass@123"
        )
        assert res_wrong == (None, None)
        assert msg_wrong == "Invalid email or password."
        assert calls[-1].startswith("$2b$")
        assert calls[-1] != auth.DUMMY_PASSWORD_HASH

        # 3. Lock the account, then attempt login with wrong and right passwords
        for _ in range(config.MAX_FAILED_LOGINS - 1):
            _attempt_login(monkeypatch, capsys, "user@test.local", "WrongPass@123")

        user_row = auth.get_user_by_email("user@test.local")
        assert user_row["is_locked"] == 1

        calls_before_locked = len(calls)
        res_locked_wrong, msg_locked_wrong = _attempt_login(
            monkeypatch, capsys, "user@test.local", "WrongPass@123"
        )
        res_locked_right, msg_locked_right = _attempt_login(
            monkeypatch, capsys, "user@test.local", "UserPass@123"
        )
        assert res_locked_wrong == (None, None)
        assert res_locked_right == (None, None)
        assert len(calls) == calls_before_locked + 2
        assert msg_unknown == msg_wrong == msg_locked_wrong == msg_locked_right

    def test_three_failed_attempts_lock_account_and_raise_brute_force_alert(
        self, auth_db, monkeypatch, capsys
    ):
        for idx in range(config.MAX_FAILED_LOGINS):
            result, out = _attempt_login(
                monkeypatch, capsys, "user@test.local", f"BadPass@{idx}1"
            )
            assert result == (None, None)
            assert out == "Invalid email or password."

        user = auth.get_user_by_email("user@test.local")
        assert user["failed_attempts"] == config.MAX_FAILED_LOGINS
        assert user["is_locked"] == 1

        open_alerts = alerts.get_open_alerts(admin_user_id=1)
        assert any(
            a["user_id"] == user["user_id"]
            and a["alert_type"] == "Brute Force"
            and a["severity"] == "high"
            for a in open_alerts
        )

    def test_successful_login_resets_failed_attempts(
        self, auth_db, monkeypatch, capsys
    ):
        for _ in range(config.MAX_FAILED_LOGINS - 1):
            _attempt_login(monkeypatch, capsys, "user@test.local", "WrongPass@123")

        assert auth.get_failed_attempts(2) == config.MAX_FAILED_LOGINS - 1

        result, _ = _attempt_login(
            monkeypatch, capsys, "user@test.local", "UserPass@123"
        )
        assert result == (2, "user")
        assert auth.get_failed_attempts(2) == 0
        assert auth.get_user_by_email("user@test.local")["is_locked"] == 0

    def test_locked_account_cannot_login_even_with_correct_password(
        self, auth_db, monkeypatch, capsys
    ):
        for _ in range(config.MAX_FAILED_LOGINS):
            _attempt_login(monkeypatch, capsys, "user@test.local", "WrongPass@123")

        result, out = _attempt_login(
            monkeypatch, capsys, "user@test.local", "UserPass@123"
        )
        assert result == (None, None)
        assert out == "Invalid email or password."


class TestDemoPasswordPolicyAndSourceHygiene:
    """Verify demo seeding enforces password policy and no hardcoded credentials exist."""

    def test_seed_demo_rejects_weak_passwords(self, tmp_path, monkeypatch):
        temp_db = str(tmp_path / "weak_seed.db")
        monkeypatch.setattr(db, "DB_PATH", temp_db)
        monkeypatch.setattr(db, "DB_TYPE", "sqlite")
        monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "weakpass")
        monkeypatch.setenv("DEMO_RAHUL_PASSWORD", "RahulSeed@123")
        monkeypatch.setenv("DEMO_PRIYA_PASSWORD", "PriyaSeed@123")

        with pytest.raises(ValueError, match="does not meet policy"):
            seed_demo.seed_demo_users()

    def test_no_legacy_plaintext_passwords_or_sha256_password_hashing_in_source(self):
        repo_root = Path(__file__).resolve().parent.parent
        forbidden_tokens = (
            "ayush" + "123",
            "rahul" + "123",
            "priya" + "123",
            "admin" + "123",
            "user" + "123",
        )

        source_files = [
            repo_root / "main.py",
            repo_root / "setup_db.py",
            repo_root / "backup_restore.py",
            repo_root / "verify_least_privilege.py",
            *sorted((repo_root / "bank").glob("*.py")),
            *sorted((repo_root / "scripts").glob("*.py")),
            *sorted((repo_root / "tests").glob("*.py")),
        ]

        sha256_allowed_files = {
            "audit.py",
            "backup_restore.py",
            "test_backup_restore.py",
            "test_security_fixes.py",
        }
        for path in source_files:
            text = path.read_text(encoding="utf-8")
            for token in forbidden_tokens:
                assert token not in text, f"Found {token!r} in {path}"
            if path.name not in sha256_allowed_files and path.name != "test_auth_login.py":
                assert "sha256" not in text.lower(), f"Unexpected sha256 in {path}"
