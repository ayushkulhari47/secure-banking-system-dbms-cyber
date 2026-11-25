"""
tests/test_config_db.py -- Focused tests for safe configuration, engine selection,
mysql-connector-python integration (mocked), and explicit demo seeding.
"""

import sqlite3
import pytest

from bank import config, db
from scripts import seed_demo


class TestSafeConfig:
    """Verify environment-only database config and absence of unsafe defaults."""

    def test_no_default_root_user_in_resolve_credentials(self):
        user, password = config.resolve_db_credentials("main.py", {})
        assert user == ""
        assert password == ""

    def test_setup_db_requires_env_user_for_mysql(self):
        with pytest.raises(RuntimeError, match="DB_ADMIN_USER or DB_USER"):
            config.resolve_db_credentials("setup_db.py", {"DB_TYPE": "mysql"})

    def test_resolve_db_credentials_reads_env_only(self):
        env = {
            "DB_TYPE": "mysql",
            "DB_USER": "app_svc",
            "DB_PASSWORD": "app_secret_value",
        }
        assert config.resolve_db_credentials("main.py", env) == (
            "app_svc",
            "app_secret_value",
        )

    def test_get_mysql_config_fails_when_missing_values(self, monkeypatch):
        monkeypatch.setattr(config, "DB_HOST", "")
        monkeypatch.setattr(config, "DB_NAME", "")
        monkeypatch.setattr(config, "DB_USER", "")
        monkeypatch.setattr(config, "DB_PASSWORD", "")
        with pytest.raises(RuntimeError, match="Missing required MySQL"):
            config.get_mysql_config()

    def test_get_mysql_config_returns_configured_values(self, monkeypatch):
        monkeypatch.setattr(config, "DB_HOST", "db.internal")
        monkeypatch.setattr(config, "DB_PORT", 3307)
        monkeypatch.setattr(config, "DB_NAME", "banking_test")
        monkeypatch.setattr(config, "DB_USER", "bank_user")
        monkeypatch.setattr(config, "DB_PASSWORD", "test_pw")

        cfg = config.get_mysql_config()
        assert cfg == {
            "host": "db.internal",
            "port": 3307,
            "database": "banking_test",
            "user": "bank_user",
            "password": "test_pw",
        }


class TestDatabaseSelection:
    """Verify SQLite vs MySQL selection, fail-closed behavior, and wrapper mechanics."""

    def test_init_db_does_not_seed_demo_users(self, tmp_path, monkeypatch):
        temp_db = str(tmp_path / "empty_init.db")
        monkeypatch.setattr(db, "DB_PATH", temp_db)
        monkeypatch.setattr(db, "DB_TYPE", "sqlite")
        db.init_db()

        conn = db.get_connection()
        try:
            users_count = conn.execute("SELECT COUNT(*) AS c FROM Users").fetchone()["c"]
            acct_count = conn.execute("SELECT COUNT(*) AS c FROM Accounts").fetchone()["c"]
        finally:
            conn.close()
        assert users_count == 0
        assert acct_count == 0

    def test_sqlite_selection_returns_sqlite_connection(self, tmp_path, monkeypatch):
        temp_db = str(tmp_path / "select_sqlite.db")
        monkeypatch.setattr(db, "DB_PATH", temp_db)
        monkeypatch.setattr(db, "DB_TYPE", "sqlite")

        conn = db.get_connection()
        try:
            assert isinstance(conn, sqlite3.Connection)
            assert db.is_mysql_connection(conn) is False
        finally:
            conn.close()

    def test_unsupported_db_type_raises_value_error(self, monkeypatch):
        monkeypatch.setattr(db, "DB_TYPE", "postgres")
        with pytest.raises(ValueError, match="Unsupported DB_TYPE"):
            db.get_connection()

    def test_mysql_missing_config_never_falls_back_to_sqlite(self, monkeypatch):
        monkeypatch.setattr(db, "DB_TYPE", "mysql")
        monkeypatch.setattr(config, "DB_HOST", "")
        monkeypatch.setattr(config, "DB_NAME", "")
        monkeypatch.setattr(config, "DB_USER", "")
        monkeypatch.setattr(config, "DB_PASSWORD", "")

        with pytest.raises(RuntimeError, match="Missing required MySQL"):
            db.get_connection()

    def test_mysql_connection_uses_mysql_connector(self, monkeypatch):
        monkeypatch.setattr(db, "DB_TYPE", "mysql")
        monkeypatch.setattr(config, "DB_HOST", "localhost")
        monkeypatch.setattr(config, "DB_PORT", 3306)
        monkeypatch.setattr(config, "DB_NAME", "banking_test")
        monkeypatch.setattr(config, "DB_USER", "bank_app")
        monkeypatch.setattr(config, "DB_PASSWORD", "secret")

        captured_kwargs = {}

        class DummyCursor:
            lastrowid = 7
            rowcount = 1

            def execute(self, sql, params=()):
                self.sql = sql
                self.params = params

            def fetchone(self):
                return {"ok": 1}

            def fetchall(self):
                return [{"ok": 1}]

            def close(self):
                pass

        class DummyRawConn:
            def __init__(self):
                self.in_transaction = False
                self.cursors = []
                self.committed = False
                self.rolled_back = False
                self.closed = False

            def start_transaction(self):
                self.in_transaction = True

            def commit(self):
                self.committed = True
                self.in_transaction = False

            def rollback(self):
                self.rolled_back = True
                self.in_transaction = False

            def cursor(self, **kwargs):
                cur = DummyCursor()
                self.cursors.append((cur, kwargs))
                return cur

            def close(self):
                self.closed = True

        dummy_raw = DummyRawConn()

        def fake_connect(**kwargs):
            captured_kwargs.update(kwargs)
            return dummy_raw

        monkeypatch.setattr(db.mysql.connector, "connect", fake_connect)

        conn = db.get_connection()
        assert db.is_mysql_connection(conn) is True
        assert captured_kwargs["user"] == "bank_app"
        assert captured_kwargs["database"] == "banking_test"
        assert captured_kwargs["autocommit"] is False

        conn.execute("BEGIN")
        assert dummy_raw.in_transaction is True
        res = conn.execute("SELECT * FROM Users WHERE user_id = ?", (1,))
        assert res.fetchone() == {"ok": 1}
        assert dummy_raw.cursors[0][0].sql == "SELECT * FROM Users WHERE user_id = %s"
        assert dummy_raw.cursors[0][1] == {"dictionary": True, "buffered": True}
        conn.execute("COMMIT")
        assert dummy_raw.committed is True
        conn.close()
        assert dummy_raw.closed is True


class TestSeedDemoScript:
    """Verify explicit demo user seeding via env vars without hardcoded passwords."""

    def test_seed_demo_uses_env_vars_and_is_idempotent(self, tmp_path, monkeypatch):
        temp_db = str(tmp_path / "seed_demo.db")
        monkeypatch.setattr(db, "DB_PATH", temp_db)
        monkeypatch.setattr(db, "DB_TYPE", "sqlite")
        monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "AdminSeed@123")
        monkeypatch.setenv("DEMO_RAHUL_PASSWORD", "RahulSeed@123")
        monkeypatch.setenv("DEMO_PRIYA_PASSWORD", "PriyaSeed@123")

        created = seed_demo.seed_demo_users()
        assert created == 3

        # Second run skips seeding when Users is already populated
        created_again = seed_demo.seed_demo_users()
        assert created_again == 0

    def test_seed_demo_rejects_empty_password(self, tmp_path, monkeypatch):
        temp_db = str(tmp_path / "seed_empty.db")
        monkeypatch.setattr(db, "DB_PATH", temp_db)
        monkeypatch.setattr(db, "DB_TYPE", "sqlite")
        monkeypatch.delenv("DEMO_ADMIN_PASSWORD", raising=False)
        monkeypatch.setattr(seed_demo.getpass, "getpass", lambda _prompt: "")

        with pytest.raises(ValueError, match="cannot be empty"):
            seed_demo.seed_demo_users()

