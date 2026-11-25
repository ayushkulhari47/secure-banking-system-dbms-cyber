-- =============================================================================
-- queries.sql -- Diagnostic Reporting SQL Queries (Reference Only)
-- =============================================================================
-- Note: The runtime application hashes passwords exclusively with bcrypt
-- (`bank/auth.py`) and seeds optional demo users only via `scripts/seed_demo.py`.
--
-- Application query equivalents:
--   List users with balances        -> bank.transactions.get_account_by_user()
--   Transaction history for account -> bank.transactions.get_transactions_for_account()
--   All transactions (admin)        -> bank.transactions.get_all_transactions()
--   Locked users (admin)            -> bank.auth.get_locked_users()
--   Open alerts (admin)             -> bank.alerts.get_open_alerts()
--   Audit log (admin, latest N)     -> bank.audit.get_audit_log()
-- =============================================================================

-- User account summary
SELECT u.name, u.email, u.role, a.balance
FROM Users u
JOIN Accounts a ON u.user_id = a.user_id;

-- Transaction history for account 1
SELECT *
FROM Transactions
WHERE from_account = 1 OR to_account = 1
ORDER BY txn_time DESC;

-- Security alerts still needing review
SELECT *
FROM Alerts
WHERE status = 'open'
ORDER BY alert_time DESC;

-- Locked user accounts
SELECT user_id, name, email, failed_attempts
FROM Users
WHERE is_locked = 1;

-- Recent audit log (latest 20)
SELECT *
FROM Audit_Log
ORDER BY log_id DESC
LIMIT 20;
