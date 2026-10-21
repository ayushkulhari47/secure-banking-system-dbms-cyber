-- =============================================================================
-- procedures.sql  --  LEGACY / REFERENCE ONLY (MySQL design, NOT used in production)
-- =============================================================================
-- IMPORTANT: These stored procedures use MySQL 8 dialect (DELIMITER, SIGNAL
-- SQLSTATE) and are NOT compatible with SQLite.
--
-- The production application (db.py) implements equivalent logic as Python
-- functions with explicit ACID transactions:
--
--   MySQL Procedure  -> Python equivalent in db.py
--   ---------------------------------------------------
--   deposit()        -> db.deposit()             (db.py L495)
--   withdraw()       -> db.withdraw()            (db.py L525)
--   transfer()       -> db.transfer()            (db.py L558)
--                       db.create_pending_transfer() for amounts > Rs50,000
--
-- Key differences from the original MySQL design:
--   - Insufficient-balance check uses ROLLBACK (not SIGNAL SQLSTATE).
--   - Transfers > LARGE_TXN_THRESHOLD (Rs 50,000) are routed through
--     Maker-Checker dual control (create_pending_transfer) rather than
--     executing immediately.
--   - All DB-level CHECK constraints (amount > 0, balance >= 0) provide a
--     second line of defence; app-layer validation (validate_amount) is first.
--
-- This file is kept for academic reference to show the original MySQL design.
-- =============================================================================

DELIMITER $$

CREATE PROCEDURE deposit(IN acc_id INT, IN amt DECIMAL(15,2))
BEGIN
    UPDATE Accounts SET balance = balance + amt WHERE account_id = acc_id;
    INSERT INTO Transactions (from_account, to_account, amount, txn_type)
    VALUES (NULL, acc_id, amt, 'deposit');
END$$

CREATE PROCEDURE withdraw(IN acc_id INT, IN amt DECIMAL(15,2))
BEGIN
    IF (SELECT balance FROM Accounts WHERE account_id = acc_id) >= amt THEN
        UPDATE Accounts SET balance = balance - amt WHERE account_id = acc_id;
        INSERT INTO Transactions (from_account, to_account, amount, txn_type)
        VALUES (acc_id, NULL, amt, 'withdraw');
    ELSE
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance';
    END IF;
END$$

CREATE PROCEDURE transfer(IN from_acc INT, IN to_acc INT, IN amt DECIMAL(15,2))
BEGIN
    IF (SELECT balance FROM Accounts WHERE account_id = from_acc) >= amt THEN
        UPDATE Accounts SET balance = balance - amt WHERE account_id = from_acc;
        UPDATE Accounts SET balance = balance + amt WHERE account_id = to_acc;
        INSERT INTO Transactions (from_account, to_account, amount, txn_type)
        VALUES (from_acc, to_acc, amt, 'transfer');
    ELSE
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance';
    END IF;
END$$

DELIMITER ;
