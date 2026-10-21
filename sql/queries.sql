-- =============================================================================
-- queries.sql  --  LEGACY / REFERENCE ONLY (MySQL design, NOT used in production)
-- =============================================================================
-- IMPORTANT: The INSERT statements below use MySQL's SHA2() function which
-- does NOT exist in SQLite.  The production application seeds the database
-- via db._seed_if_empty() using bcrypt-hashed passwords (db.py L133).
--
-- The SELECT queries are standard SQL and will run against the SQLite database
-- (banking.db) with minor dialect adjustments if needed.
--
-- Production query equivalents in db.py:
--
--   Purpose                          -> Python function in db.py
--   ------------------------------------------------------------------
--   List users with balances         -> db.get_account_by_user()     (L469)
--   Transaction history for account  -> db.get_transactions_for_account() (L600)
--   All transactions (admin)         -> db.get_all_transactions()    (L614)
--   Locked users                     -> db.get_locked_users()        (L384)
--   Open alerts                      -> db.get_open_alerts()         (L454)
--   Audit log (latest N)             -> db.get_audit_log(limit)      (L342)
--
-- This file is kept for academic reference to show the original MySQL design.
-- =============================================================================

-- [LEGACY MySQL only -- uses SHA2() which does not exist in SQLite]
INSERT INTO Users (name, email, password_hash, role) VALUES
('Ayush Kulhari', 'ayush@bank.com', SHA2('ayush123', 256), 'admin'),
('Rahul Sharma', 'rahul@bank.com', SHA2('rahul123', 256), 'user'),
('Priya Singh', 'priya@bank.com', SHA2('priya123', 256), 'user');

-- [LEGACY] Seed balances
INSERT INTO Accounts (user_id, balance) VALUES
(1, 50000.00),
(2, 25000.00),
(3, 15000.00);

-- [LEGACY] Sample transactions
INSERT INTO Transactions (from_account, to_account, amount, txn_type) VALUES
(2, 1, 5000.00, 'transfer'),
(1, NULL, 10000.00, 'deposit'),
(3, NULL, 2000.00, 'withdraw');

-- ---- Diagnostic / reporting queries (compatible with SQLite) ----

-- User account summary
SELECT u.name, u.email, u.role, a.balance
FROM Users u
JOIN Accounts a ON u.user_id = a.user_id;

-- Transaction history for account 1
SELECT * FROM Transactions
WHERE from_account = 1 OR to_account = 1
ORDER BY txn_time DESC;

-- Transaction volume per user
SELECT u.name, COUNT(t.txn_id) AS total_transactions, SUM(t.amount) AS total_amount
FROM Users u
JOIN Accounts a ON u.user_id = a.user_id
JOIN Transactions t ON a.account_id = t.from_account
GROUP BY u.user_id;

-- Locked accounts
SELECT * FROM Users WHERE failed_attempts >= 3;

-- Open security alerts
SELECT * FROM Alerts WHERE status = 'open' ORDER BY alert_time DESC;

-- Recent audit log (latest 20)
SELECT * FROM Audit_Log ORDER BY log_time DESC LIMIT 20;

-- [LEGACY MySQL only] Direct balance updates (bypassed by application-layer controls in production)
UPDATE Accounts SET balance = balance + 5000 WHERE account_id = 2;
UPDATE Accounts SET balance = balance - 2000 WHERE account_id = 3 AND balance >= 2000;
