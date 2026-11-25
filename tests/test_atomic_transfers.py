"""
tests/test_atomic_transfers.py -- Phase 6 tests verifying atomic transfers,
mid-transaction rollback guarantees, pending reserve enforcement, and concurrency locks.
"""

from decimal import Decimal
import pytest

from bank import auth, config, db, transactions


@pytest.fixture
def atomic_db(tmp_path, monkeypatch):
    """Isolated SQLite database with one admin and two standard users."""
    temp_db = str(tmp_path / "atomic_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    pw_hash = auth.hash_password("AtomicPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Checker", "checker@atomic.local", "admin", "50000.00"),
            ("Sender", "sender@atomic.local", "user", "60000.00"),
            ("Recipient", "recipient@atomic.local", "user", "10000.00"),
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


class _FaultInjectingConnection:
    """Proxy around a real sqlite3.Connection that injects a failure on match."""

    def __init__(self, real_conn, fail_predicate):
        self._conn = real_conn
        self._fail_predicate = fail_predicate
        self.executed_sql = []

    @property
    def in_transaction(self):
        return self._conn.in_transaction

    def execute(self, sql: str, params=()):
        self.executed_sql.append(sql)
        if self._fail_predicate(sql, params, self.executed_sql):
            raise RuntimeError("Simulated mid-transaction failure")
        return self._conn.execute(sql, params)

    def close(self):
        self._conn.close()


class TestAtomicTransfers:
    """Verify full ACID atomicity and rollback on mid-transaction failures."""

    def test_successful_transfer_updates_both_balances_and_inserts_record(
        self, atomic_db
    ):
        ok = transactions.transfer(2, 3, Decimal("1234.56"), actor_user_id=2)
        assert ok is True

        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "58765.44"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "11234.56"
        )
        txns = transactions.get_transactions_for_account(2, actor_user_id=2)
        assert len(txns) == 1
        assert txns[0]["amount"] == Decimal("1234.56")
        assert txns[0]["txn_type"] == "transfer"
        assert txns[0]["status"] == "completed"

    def test_insufficient_balance_leaves_balances_and_ledger_unchanged(
        self, atomic_db
    ):
        ok = transactions.transfer(2, 3, Decimal("75000.00"), actor_user_id=2)
        assert ok is False

        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "60000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "10000.00"
        )
        assert transactions.get_transactions_for_account(2, actor_user_id=2) == []

    def test_failure_after_debit_before_credit_rolls_back_completely(
        self, atomic_db, monkeypatch
    ):
        orig_get_conn = db.get_connection
        update_calls = {"count": 0}

        def fail_on_credit(sql, params, _history):
            if sql.strip().upper().startswith("UPDATE ACCOUNTS"):
                update_calls["count"] += 1
                # 1st UPDATE is debit; 2nd UPDATE is credit
                return update_calls["count"] == 2
            return False

        monkeypatch.setattr(
            db,
            "get_connection",
            lambda: _FaultInjectingConnection(orig_get_conn(), fail_on_credit),
        )

        with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
            transactions.transfer(2, 3, Decimal("5000.00"), actor_user_id=2)

        monkeypatch.setattr(db, "get_connection", orig_get_conn)

        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "60000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "10000.00"
        )
        assert transactions.get_all_transactions(admin_user_id=1) == []

    def test_failure_after_credit_before_transaction_insert_rolls_back_completely(
        self, atomic_db, monkeypatch
    ):
        orig_get_conn = db.get_connection

        def fail_on_insert(sql, params, _history):
            return sql.strip().upper().startswith("INSERT INTO TRANSACTIONS")

        monkeypatch.setattr(
            db,
            "get_connection",
            lambda: _FaultInjectingConnection(orig_get_conn(), fail_on_insert),
        )

        with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
            transactions.transfer(2, 3, Decimal("5000.00"), actor_user_id=2)

        monkeypatch.setattr(db, "get_connection", orig_get_conn)

        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "60000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "10000.00"
        )
        assert transactions.get_all_transactions(admin_user_id=1) == []

    def test_safe_rollback_does_not_raise_when_no_transaction_active(self, atomic_db):
        conn = db.get_connection()
        try:
            assert conn.in_transaction is False
            db.safe_rollback(conn)  # must not raise OperationalError
        finally:
            conn.close()


class TestAtomicPendingApprovalsAndReserves:
    """Verify pending-transfer reserves, atomic approvals, and engine locking."""

    def test_successful_pending_transfer_approval(self, atomic_db):
        txn_id = transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )
        ok, msg = transactions.approve_pending_transfer(txn_id, approver_user_id=1)
        assert ok is True
        assert "approved" in msg.lower()

        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "5000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "65000.00"
        )
        txns = transactions.get_transactions_for_account(2, actor_user_id=2)
        assert len(txns) == 1
        assert txns[0]["status"] == "completed"

    def test_failed_approval_rolls_back_and_leaves_pending_unchanged(
        self, atomic_db, monkeypatch
    ):
        txn_id = transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )

        orig_get_conn = db.get_connection

        def fail_on_status_complete(sql, params, _history):
            return "SET status = 'completed'" in sql

        monkeypatch.setattr(
            db,
            "get_connection",
            lambda: _FaultInjectingConnection(orig_get_conn(), fail_on_status_complete),
        )

        with pytest.raises(RuntimeError, match="Simulated mid-transaction failure"):
            transactions.approve_pending_transfer(txn_id, approver_user_id=1)

        monkeypatch.setattr(db, "get_connection", orig_get_conn)

        # Both balances remain untouched and transfer remains pending
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "60000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "10000.00"
        )
        pending = transactions.get_pending_transfers(admin_user_id=1)
        assert len(pending) == 1
        assert pending[0]["txn_id"] == txn_id
        assert pending[0]["status"] == "pending"

    def test_pending_outgoing_amounts_are_reserved_across_withdraw_and_transfer(
        self, atomic_db
    ):
        # Sender has 60,000.00; queue 55,000.00 -> 5,000.00 available
        transactions.create_pending_transfer(
            2, 3, Decimal("55000.00"), actor_user_id=2
        )

        # Cannot withdraw or transfer more than the 5,000.00 unreserved remainder
        assert transactions.withdraw(2, Decimal("5000.01"), actor_user_id=2) is False
        assert (
            transactions.transfer(2, 3, Decimal("5000.01"), actor_user_id=2) is False
        )
        with pytest.raises(ValueError, match="Insufficient available balance"):
            transactions.create_pending_transfer(
                2, 3, Decimal("5000.01"), actor_user_id=2
            )

        # Exact unreserved amount (5,000.00) succeeds and leaves 55,000.00 for approval
        assert transactions.transfer(2, 3, Decimal("5000.00"), actor_user_id=2) is True
        assert transactions.get_account_by_id(2, actor_user_id=2)["balance"] == Decimal(
            "55000.00"
        )
        assert transactions.get_account_by_id(3, actor_user_id=3)["balance"] == Decimal(
            "15000.00"
        )

    def test_sqlite_uses_begin_immediate_and_mysql_uses_for_update(
        self, atomic_db, monkeypatch
    ):
        # 1. Verify SQLite uses BEGIN IMMEDIATE
        orig_get_conn = db.get_connection
        proxies = []

        def tracked_sqlite_conn():
            proxy = _FaultInjectingConnection(orig_get_conn(), lambda *_: False)
            proxies.append(proxy)
            return proxy

        monkeypatch.setattr(db, "get_connection", tracked_sqlite_conn)
        assert transactions.transfer(2, 3, Decimal("100.00"), actor_user_id=2) is True
        assert any(sql.strip().upper() == "BEGIN IMMEDIATE" for sql in proxies[0].executed_sql)

        # 2. Verify MySQL path uses FOR UPDATE and deterministic ordering
        class DummyMySQLCursor:
            lastrowid = 1
            rowcount = 1

            def __init__(self, sql):
                self.sql = sql

            def fetchone(self):
                return None

            def fetchall(self):
                if "FROM Accounts" in self.sql:
                    return [
                        {"account_id": 2, "user_id": 2, "balance": Decimal("1000.00")},
                        {"account_id": 3, "user_id": 3, "balance": Decimal("500.00")},
                    ]
                return []

        class DummyMySQLRaw:
            def __init__(self):
                self.in_transaction = False
                self.started = False
                self.committed = False
                self.executed = []

            def start_transaction(self):
                self.started = True
                self.in_transaction = True

            def commit(self):
                self.committed = True
                self.in_transaction = False

            def rollback(self):
                self.in_transaction = False

            def cursor(self, **_kwargs):
                raw = self

                class _Cur:
                    lastrowid = 1
                    rowcount = 1

                    def execute(self, sql, params=()):
                        raw.executed.append(sql)
                        self._sql = sql

                    def fetchone(self):
                        return None

                    def fetchall(self):
                        if "FROM Accounts" in self._sql:
                            return [
                                {"account_id": 2, "user_id": 2, "balance": Decimal("1000.00")},
                                {"account_id": 3, "user_id": 3, "balance": Decimal("500.00")},
                            ]
                        return []

                return _Cur()

            def close(self):
                pass

        raw_mysql = DummyMySQLRaw()
        wrapper = db.MySQLConnectionWrapper(raw_mysql)
        monkeypatch.setattr(db, "DB_TYPE", "mysql")
        monkeypatch.setattr(db, "get_connection", lambda: wrapper)

        assert transactions.transfer(2, 3, Decimal("50.00"), actor_user_id=2) is True
        assert raw_mysql.started is True
        assert raw_mysql.committed is True
        assert any(
            "ORDER BY account_id ASC FOR UPDATE" in sql for sql in raw_mysql.executed
        )
        assert any("FOR UPDATE" in sql for sql in raw_mysql.executed if "Transactions" in sql)

