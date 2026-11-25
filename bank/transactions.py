"""
bank/transactions.py -- Account lookups, ACID banking transactions, and Maker-Checker dual control.
"""

from bank import audit, db


def get_account_by_user(user_id: int):
    """Return the Accounts row for a given user_id."""
    conn = db.get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Accounts WHERE user_id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()


def get_account_by_id(account_id: int):
    """Return the Accounts row for a given account_id."""
    conn = db.get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
    finally:
        conn.close()


def deposit(account_id: int, amount: float) -> None:
    """
    Credit 'amount' to 'account_id' inside an explicit ACID transaction.
    """
    if amount <= 0:
        raise ValueError("Transaction amount must be greater than zero.")
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        account = conn.execute(
            "SELECT account_id FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if account is None:
            conn.execute("ROLLBACK")
            raise ValueError("Source account not found.")
        conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?",
            (amount, account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (NULL, ?, ?, 'deposit')",
            (account_id, amount),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def withdraw(account_id: int, amount: float) -> bool:
    """
    Debit 'amount' from 'account_id' atomically.
    Returns True on success, False if balance is insufficient.
    """
    if amount <= 0:
        return False
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        row = conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if row is None or float(row["balance"]) < float(amount):
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = ?",
            (amount, account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (?, NULL, ?, 'withdraw')",
            (account_id, amount),
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def transfer(from_account_id: int, to_account_id: int, amount: float) -> bool:
    """
    Move 'amount' from one account to another atomically.
    Returns True on success, False if balance is insufficient or accounts are invalid.
    """
    if amount <= 0 or from_account_id == to_account_id:
        return False
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        row = conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = ?", (from_account_id,)
        ).fetchone()
        destination = conn.execute(
            "SELECT account_id FROM Accounts WHERE account_id = ?", (to_account_id,)
        ).fetchone()
        if row is None or destination is None or float(row["balance"]) < float(amount):
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = ?",
            (amount, from_account_id),
        )
        conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?",
            (amount, to_account_id),
        )
        conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type)"
            " VALUES (?, ?, ?, 'transfer')",
            (from_account_id, to_account_id, amount),
        )
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_transactions_for_account(account_id: int) -> list:
    """Return all transactions involving a specific account. User-scoped."""
    conn = db.get_connection()
    try:
        return conn.execute(
            "SELECT * FROM Transactions"
            " WHERE from_account = ? OR to_account = ?"
            " ORDER BY txn_time DESC",
            (account_id, account_id),
        ).fetchall()
    finally:
        conn.close()


def get_all_transactions(admin_user_id: int = None) -> list:
    """Return every transaction. Admin use only."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        return conn.execute(
            "SELECT * FROM Transactions ORDER BY txn_time DESC"
        ).fetchall()
    finally:
        conn.close()


def create_pending_transfer(
    from_account_id: int, to_account_id: int, amount: float
) -> int:
    """
    Insert a pending transaction requiring Maker-Checker authorization (ISO 27001 A.6.1.2).
    Balances are NOT modified at creation time.
    """
    if amount <= 0 or from_account_id == to_account_id:
        raise ValueError(
            "Pending transfer must use two accounts and a positive amount."
        )
    conn = db.get_connection()
    try:
        conn.execute("BEGIN")
        lock_clause = " FOR UPDATE" if db.is_mysql_connection(conn) else ""
        accounts = conn.execute(
            "SELECT account_id FROM Accounts WHERE account_id IN (?, ?)",
            (from_account_id, to_account_id),
        ).fetchall()
        if len(accounts) != 2:
            conn.execute("ROLLBACK")
            raise ValueError("Both transfer accounts must exist.")
        source = conn.execute(
            "SELECT balance FROM Accounts WHERE account_id = ?" + lock_clause,
            (from_account_id,),
        ).fetchone()
        pending = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) AS amount FROM Transactions "
            "WHERE from_account = ? AND status = 'pending'",
            (from_account_id,),
        ).fetchone()["amount"]
        if float(source["balance"]) - float(pending) < float(amount):
            conn.execute("ROLLBACK")
            raise ValueError("Insufficient available balance for pending transfers.")
        cursor = conn.execute(
            "INSERT INTO Transactions (from_account, to_account, amount, txn_type, status)"
            " VALUES (?, ?, ?, 'transfer', 'pending')",
            (from_account_id, to_account_id, amount),
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
    """Return all transactions waiting for Maker-Checker approval."""
    conn = db.get_connection()
    try:
        if not db._is_admin(conn, admin_user_id):
            return []
        return conn.execute(
            "SELECT t.*, u.name as sender_name, u.email as sender_email "
            "FROM Transactions t "
            "JOIN Accounts a ON t.from_account = a.account_id "
            "JOIN Users u ON a.user_id = u.user_id "
            "WHERE t.status = 'pending' "
            "ORDER BY t.txn_time ASC"
        ).fetchall()
    finally:
        conn.close()


def approve_pending_transfer(txn_id: int, approver_user_id: int) -> tuple:
    """
    Checker approves a pending transfer, enforcing Segregation of Duties (Maker != Checker).
    Returns (True, message) or (False, error_reason).
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

        if float(from_acc["balance"]) < float(txn["amount"]):
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

        conn.execute(
            "UPDATE Accounts SET balance = balance - ? WHERE account_id = ?",
            (txn["amount"], txn["from_account"]),
        )
        conn.execute(
            "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?",
            (txn["amount"], txn["to_account"]),
        )
        conn.execute(
            "UPDATE Transactions SET status = 'completed' WHERE txn_id = ?",
            (txn_id,),
        )
        conn.execute("COMMIT")
        audit.log_action(
            approver_user_id,
            f"Approved pending transfer #{txn_id} of Rs{txn['amount']:.2f}",
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
    """
    Checker rejects a pending transfer.
    Returns (True, message) or (False, error_reason).
    """
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

