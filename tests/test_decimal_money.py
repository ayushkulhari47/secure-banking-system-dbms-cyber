"""
tests/test_decimal_money.py -- Phase 5 tests for Decimal monetary validation,
exact cents arithmetic, SQLite 2-decimal enforcement, and pending balance math.
"""

from decimal import Decimal
import math
import sqlite3
import pytest

from bank import auth, config, db, security, transactions


@pytest.fixture
def money_db(tmp_path, monkeypatch):
    """Isolated SQLite database with accounts starting at exact Decimal balances."""
    temp_db = str(tmp_path / "money_test.db")
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()

    pw_hash = auth.hash_password("MoneyPass@123")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        for name, email, role, bal in (
            ("Admin", "admin@money.local", "admin", "50000.00"),
            ("Alice", "alice@money.local", "user", "0.10"),
            ("Bob", "bob@money.local", "user", "0.20"),
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


class TestDecimalAmountValidation:
    """Strict validation of Decimal, string, and invalid monetary inputs."""

    @pytest.mark.parametrize(
        "valid_amount",
        [
            Decimal("0.01"),
            Decimal("10.5"),
            Decimal("123.45"),
            Decimal("1000000.00"),
            "0.01",
            "250.75",
            " 42.10 ",
            100,
        ],
    )
    def test_valid_decimal_and_string_amounts_accepted(self, valid_amount):
        ok, reason = security.validate_amount(valid_amount)
        assert ok is True
        assert reason is None

    @pytest.mark.parametrize(
        "invalid_amount",
        [
            Decimal("-0.01"),
            Decimal("-500.00"),
            "-10.00",
            Decimal("0"),
            Decimal("0.00"),
            "0.00",
            0,
            0.0,
            "abc",
            "",
            "12.34.56",
            True,
            False,
            None,
            float("nan"),
            Decimal("NaN"),
            "NaN",
            math.inf,
            -math.inf,
            Decimal("Infinity"),
            Decimal("-Infinity"),
            "Infinity",
            Decimal("0.001"),
            Decimal("10.123"),
            Decimal("10.500"),
            "10.123",
            10.123,
            Decimal("1000000.01"),
            "1000000.01",
            config.MAX_AMOUNT + Decimal("0.01"),
        ],
    )
    def test_invalid_amounts_rejected_without_crashing(self, invalid_amount):
        ok, reason = security.validate_amount(invalid_amount)
        assert ok is False
        assert isinstance(reason, str) and len(reason) > 0

    def test_overly_precise_amounts_are_rejected_not_silently_rounded(
        self, money_db
    ):
        with pytest.raises(ValueError, match="two decimal places"):
            transactions.deposit(2, Decimal("10.123"), actor_user_id=2)
        with pytest.raises(ValueError, match="two decimal places"):
            transactions.withdraw(2, "0.001", actor_user_id=2)
        with pytest.raises(ValueError, match="two decimal places"):
            transactions.transfer(2, 3, Decimal("0.055"), actor_user_id=2)

    def test_booleans_and_nonnumeric_rejected_in_transactions(self, money_db):
        with pytest.raises(ValueError):
            transactions.deposit(2, True, actor_user_id=2)
        with pytest.raises(ValueError):
            transactions.withdraw(2, "not-a-number", actor_user_id=2)
        with pytest.raises(ValueError):
            transactions.transfer(2, 3, False, actor_user_id=2)


class TestDecimalMoneyArithmeticAndStorage:
    """Verify exact Decimal calculations, DB conversions, and float drift elimination."""

    def test_fetched_balances_and_amounts_are_exact_decimals(self, money_db):
        acc = transactions.get_account_by_id(2, actor_user_id=2)
        assert isinstance(acc["balance"], Decimal)
        assert acc["balance"] == Decimal("0.10")
        assert acc["balance"].as_tuple().exponent == -2

        transactions.deposit(2, "0.20", actor_user_id=2)
        txns = transactions.get_transactions_for_account(2, actor_user_id=2)
        assert isinstance(txns[0]["amount"], Decimal)
        assert txns[0]["amount"] == Decimal("0.20")
        assert txns[0]["amount"].as_tuple().exponent == -2

    def test_deposit_and_withdraw_with_exact_cents(self, money_db):
        # 0.10 + 0.20 must be exact Decimal('0.30'), never 0.30000000000000004
        transactions.deposit(2, Decimal("0.20"), actor_user_id=2)
        acc = transactions.get_account_by_user(2)
        assert acc["balance"] == Decimal("0.30")

        # 0.30 - 0.19 == 0.11 exact
        assert transactions.withdraw(2, Decimal("0.19"), actor_user_id=2) is True
        acc_after = transactions.get_account_by_user(2)
        assert acc_after["balance"] == Decimal("0.11")

    def test_transfer_without_float_precision_errors(self, money_db):
        # Alice starts with 0.10, deposits 19.89 -> 19.99
        transactions.deposit(2, Decimal("19.89"), actor_user_id=2)
        assert transactions.get_account_by_user(2)["balance"] == Decimal("19.99")

        # Transfer 0.10 from Alice (19.99 -> 19.89) to Bob (0.20 -> 0.30)
        assert transactions.transfer(2, 3, Decimal("0.10"), actor_user_id=2) is True
        alice = transactions.get_account_by_user(2)
        bob = transactions.get_account_by_user(3)
        assert alice["balance"] == Decimal("19.89")
        assert bob["balance"] == Decimal("0.30")
        assert alice["balance"] + bob["balance"] == Decimal("20.19")

    def test_pending_balance_calculations_use_decimal(self, money_db):
        # Give Alice 60000.05
        transactions.deposit(2, Decimal("59999.95"), actor_user_id=2)
        assert transactions.get_account_by_user(2)["balance"] == Decimal("60000.05")

        # Pending transfer of 50000.01 leaves 10000.04 available
        txn1 = transactions.create_pending_transfer(
            2, 3, Decimal("50000.01"), actor_user_id=2
        )
        assert txn1 > 0

        # Trying to queue 10000.05 (0.01 over available) must fail
        with pytest.raises(ValueError, match="Insufficient available balance"):
            transactions.create_pending_transfer(
                2, 3, Decimal("10000.05"), actor_user_id=2
            )

        # Queuing exact 10000.04 succeeds
        txn2 = transactions.create_pending_transfer(
            2, 3, Decimal("10000.04"), actor_user_id=2
        )
        assert txn2 > txn1

        # Independent admin approves txn1; balances remain exact Decimal
        ok, _ = transactions.approve_pending_transfer(txn1, approver_user_id=1)
        assert ok is True
        assert transactions.get_account_by_user(2)["balance"] == Decimal("10000.04")
        assert transactions.get_account_by_user(3)["balance"] == Decimal("50000.21")

    def test_sqlite_schema_enforces_two_decimal_places(self, money_db):
        conn = db.get_connection()
        try:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO Transactions (to_account, amount, txn_type)"
                    " VALUES (2, 1.234, 'deposit')"
                )
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("UPDATE Accounts SET balance = 5.678 WHERE account_id = 2")
        finally:
            conn.close()

