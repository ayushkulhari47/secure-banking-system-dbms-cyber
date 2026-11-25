"""
bank/transactions.py -- Account lookups, ACID banking transactions, and Maker-Checker dual control.
"""

from decimal import Decimal

from bank import audit, db, security


def _require_account_owner(conn, account_id: int, actor_user_id: int, lock_clause: str = ""):
    """Verify actor_user_id is authenticated and owns account_id."""
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    account = conn.execute(
        "SELECT * FROM Accounts WHERE account_id = ?" + lock_clause, (account_id,)
    ).fetchone()
    if account is not None and account["user_id"] != actor_user_id:
        raise PermissionError("Access denied: account belongs to another user.")
    return account


def _normalize_account_row(row):
    """Convert an Accounts DB row into a dict with Decimal balance."""
    if row is None:
        return None
    data = dict(row)
    data["balance"] = security.db_to_decimal(data["balance"])
    return data


def _normalize_txn_row(row):
    """Convert a Transactions DB row into a dict with Decimal amount."""
    if row is None:
        return None
    data = dict(row)
    data["amount"] = security.db_to_decimal(data["amount"])
    return data


def _validated_decimal_amount(amount) -> Decimal:
    """Validate and normalize an input monetary amount to Decimal('0.01')."""
    ok, reason = security.validate_amount(amount)
    if not ok:
        raise ValueError(reason)
    return security.parse_money_input(amount).quantize(security.MONEY_QUANTIZER)


def account_exists(account_id: int) -> bool:
    """Return True if an account ID exists (exposes existence only, no PII or balance)."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT 1 FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def get_account_by_user(user_id: int):
    """Return the Accounts row (with Decimal balance) for a given user_id."""
    if user_id is None:
        raise PermissionError("Authentication required.")
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM Accounts WHERE user_id = ?", (user_id,)
        ).fetchone()
        return _normalize_account_row(row)
    finally:
        conn.close()


def get_account_by_id(account_id: int, actor_user_id: int = None):
    """Return the Accounts row (with Decimal balance) if actor_user_id owns it or is an admin."""
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if row is None:
            return None
        if row["user_id"] != actor_user_id and not db._is_admin(conn, actor_user_id):
            raise PermissionError("Access denied: cannot view another user's account.")
        return _normalize_account_row(row)
    finally:
        conn.close()


def deposit(account_id: int, amount, actor_user_id: int = None) -> None:
    """
    Credit 'amount' to 'account_id' inside an explicit ACID transaction using Decimal math.
    Requires actor_user_id to own the target account.
    """
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    amt = _validated_decimal_amount(amount)
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        account = _require_account_owner(
            conn, account_id, actor_user_id, lock_clause=lock_clause
        )
        if account is None:
            raise ValueError("Source account not found.")
        current_balance = security.db_to_decimal(account["balance"])
        new_balance = current_balance + amt
        conn.execute(
            "UPDATE Accounts SET balance = ? WHERE account_id = ?",
            (str(new_balance), account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (NULL, ?, ?, 'deposit')",
            (account_id, str(amt)),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def withdraw(account_id: int, amount, actor_user_id: int = None) -> bool:
    """
    Debit 'amount' from 'account_id' atomically using Decimal math.
    Requires actor_user_id to own the target account.
    Returns True on success, False if balance is insufficient.
    """
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    amt = _validated_decimal_amount(amount)
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        row = _require_account_owner(
            conn, account_id, actor_user_id, lock_clause=lock_clause
        )
        if row is None:
            conn.execute("ROLLBACK")
            return False
        current_balance = security.db_to_decimal(row["balance"])
        if current_balance < amt:
            conn.execute("ROLLBACK")
            return False
        new_balance = current_balance - amt
        conn.execute(
            "UPDATE Accounts SET balance = ? WHERE account_id = ?",
            (str(new_balance), account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (?, NULL, ?, 'withdraw')",
            (account_id, str(amt)),
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def transfer(
    from_account_id: int,
    to_account_id: int,
    amount,
    actor_user_id: int = None,
) -> bool:
    """
    Move 'amount' from one account to another atomically using Decimal math.
    Requires actor_user_id to own from_account_id.
    Returns True on success, False if balance is insufficient or accounts are invalid.
    """
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        row = _require_account_owner(
            conn, from_account_id, actor_user_id, lock_clause=lock_clause
        )
        if from_account_id == to_account_id:
            conn.execute("ROLLBACK")
            return False
        amt = _validated_decimal_amount(amount)
        destination = conn.execute(
            "SELECT account_id, balance FROM Accounts WHERE account_id = ?" + lock_clause,
            (to_account_id,),
        ).fetchone()
        if row is None or destination is None:
            conn.execute("ROLLBACK")
            return False
        from_balance = security.db_to_decimal(row["balance"])
        to_balance = security.db_to_decimal(destination["balance"])
        if from_balance < amt:
            conn.execute("ROLLBACK")
            return False
        new_from_balance = from_balance - amt
        new_to_balance = to_balance + amt
        conn.execute(
            "UPDATE Accounts SET balance = ? WHERE account_id = ?",
            (str(new_from_balance), from_account_id),
        )
        conn.execute(
            "UPDATE Accounts SET balance = ? WHERE account_id = ?",
            (str(new_to_balance), to_account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (?, ?, ?, 'transfer')",
            (from_account_id, to_account_id, str(amt)),
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_transactions_for_account(account_id: int, actor_user_id: int = None) -> list:
    """Return transactions (with Decimal amounts) if actor_user_id owns account or is admin."""
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    conn = db.get_connection()
    try:
        acc = conn.execute(
            "SELECT user_id FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if acc is None:
            return []
        if acc["user_id"] != actor_user_id and not db._is_admin(conn, actor_user_id):
            raise PermissionError(
                "Access denied: cannot view another user's transactions."
            )
        rows = conn.execute(
            "SELECT * FROM Transactions"
            " WHERE from_account = ? OR to_account = ?"
            " ORDER BY txn_time DESC",
            (account_id, account_id),
        ).fetchall()
        return [_normalize_txn_row(r) for r in rows]
    finally:
        conn.close()


def get_all_transactions(admin_user_id: int = None) -> list:
    """Return every transaction (with Decimal amounts). Admin use only."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        rows = conn.execute(
            "SELECT * FROM Transactions ORDER BY txn_time DESC"
        ).fetchall()
        return [_normalize_txn_row(r) for r in rows]
    finally:
        conn.close()


def create_pending_transfer(
    from_account_id: int,
    to_account_id: int,
    amount,
    actor_user_id: int = None,
) -> int:
    """
    Insert a pending transaction requiring Maker-Checker authorization (ISO 27001 A.6.1.2).
    Requires actor_user_id to own from_account_id.
    Pending balance checks use Decimal arithmetic.
    """
    if actor_user_id is None:
        raise PermissionError("Authentication required.")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        source = _require_account_owner(
            conn, from_account_id, actor_user_id, lock_clause=lock_clause
        )
        if from_account_id == to_account_id:
            raise ValueError(
                "Pending transfer must use two accounts and a positive amount."
            )
        amt = _validated_decimal_amount(amount)
        destination = conn.execute(
            "SELECT account_id FROM Accounts WHERE account_id = ?",
            (to_account_id,),
        ).fetchone()
        if source is None or destination is None:
            raise ValueError("Both transfer accounts must exist.")
        source_balance = security.db_to_decimal(source["balance"])
        pending_rows = conn.execute(
            "SELECT amount FROM Transactions "
            "WHERE from_account = ? AND status = 'pending'",
            (from_account_id,),
        ).fetchall()
        pending_total = sum(
            (security.db_to_decimal(r["amount"]) for r in pending_rows),
            Decimal("0.00"),
        )
        if source_balance - pending_total < amt:
            raise ValueError("Insufficient available balance for pending transfers.")
        cursor = conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type, status)"
            " VALUES (?, ?, ?, 'transfer', 'pending')",
            (from_account_id, to_account_id, str(amt)),
        )
        txn_id = cursor.lastrowid
        conn.execute("COMMIT")
        return txn_id
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_pending_transfers(admin_user_id: int = None) -> list:
    """Return all transactions waiting for Maker-Checker approval (Decimal amounts)."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        rows = conn.execute(
            "SELECT t.*, u.name as sender_name, u.email as sender_email "
            "FROM Transactions t "
            "JOIN Accounts a ON t.from_account = a.account_id "
            "JOIN Users u ON a.user_id = u.user_id "
            "WHERE t.status = 'pending' "
            "ORDER BY t.txn_time ASC"
        ).fetchall()
        return [_normalize_txn_row(r) for r in rows]
    finally:
        conn.close()


def approve_pending_transfer(txn_id: int, approver_user_id: int) -> tuple:
    """
    Checker approves a pending transfer using Decimal math, enforcing Segregation of Duties:
      - approver must be an admin
      - approver cannot be the original maker (from_acc owner)
      - approver cannot be the recipient (to_acc owner)
    """
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        if not db._is_admin(conn, approver_user_id):
            conn.execute("ROLLBACK")
            return (
                False,
                "Only administrators may approve transfers (Segregation of Duties).",
            )
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        txn = conn.execute(
            "SELECT * FROM Transactions WHERE txn_id = ? AND status = 'pending'"
            + lock_clause,
            (txn_id,),
        ).fetchone()
        if not txn:
            conn.execute("ROLLBACK")
            return False, "Pending transaction not found."

        from_acc = conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?" + lock_clause,
            (txn["from_account"],),
        ).fetchone()
        to_acc = conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?" + lock_clause,
            (txn["to_account"],),
        ).fetchone()

        if not from_acc or not to_acc:
            conn.execute("ROLLBACK")
            return False, "Associated accounts not found."

        if from_acc["user_id"] == approver_user_id:
            conn.execute("ROLLBACK")
            audit.log_action(
                approver_user_id,
                f"SoD violation attempt: self-approval of txn #{txn_id}",
            )
            return (
                False,
                "Segregation of Duties violation: Maker cannot approve their own transfer.",
            )

        if to_acc["user_id"] == approver_user_id:
            conn.execute("ROLLBACK")
            audit.log_action(
                approver_user_id,
                f"SoD violation attempt: recipient approval of txn #{txn_id}",
            )
            return (
                False,
                "Segregation of Duties violation: Recipient cannot approve an incoming transfer.",
            )

        txn_amount = security.db_to_decimal(txn["amount"])
        from_balance = security.db_to_decimal(from_acc["balance"])
        to_balance = security.db_to_decimal(to_acc["balance"])

        if from_balance < txn_amount:
            conn.execute(
                "UPDATE Transactions SET status = 'rejected' WHERE txn_id = ?",
                (txn_id,),
            )
            conn.execute("COMMIT")
            audit.log_action(
                approver_user_id,
                f"Pending transfer #{txn_id} rejected due to insufficient funds",
            )
            return False, "Insufficient balance at time of approval. Transfer rejected."

        new_from_balance = from_balance - txn_amount
        new_to_balance = to_balance + txn_amount
        conn.execute(
            "UPDATE Accounts SET balance = ? WHERE account_id = ?",
            (str(new_from_balance), txn["from_account"]),
        )
        conn.execute(
            "UPDATE Accounts SET balance = ? WHERE account_id = ?",
            (str(new_to_balance), txn["to_account"]),
        )
        conn.execute(
            "UPDATE Transactions SET status = 'completed' WHERE txn_id = ?",
            (txn_id,),
        )
        conn.execute("COMMIT")
        audit.log_action(
            approver_user_id,
            f"Approved pending transfer #{txn_id} of Rs{txn_amount:.2f}",
        )
        return True, "Transfer approved and processed successfully."
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def reject_pending_transfer(
    txn_id: int, approver_user_id: int, reason: str = "Rejected by admin"
) -> tuple:
    """Checker rejects a pending transfer."""
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        if not db._is_admin(conn, approver_user_id):
            conn.execute("ROLLBACK")
            return False, "Only administrators may reject transfers."
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        txn = conn.execute(
            "SELECT * FROM Transactions WHERE txn_id = ? AND status = 'pending'"
            + lock_clause,
            (txn_id,),
        ).fetchone()
        if not txn:
            conn.execute("ROLLBACK")
            return False, "Pending transaction not found."

        conn.execute(
            "UPDATE Transactions SET status = 'rejected' WHERE txn_id = ?",
            (txn_id,),
        )
        conn.execute("COMMIT")
        audit.log_action(
            approver_user_id, f"Rejected pending transfer #{txn_id} ({reason})"
        )
        return True, "Transfer rejected successfully."
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
