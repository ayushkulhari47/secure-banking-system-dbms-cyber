-- =============================================================================
-- schema.sql  --  ACTUAL PRODUCTION SCHEMA (SQLite / sqlite3)
-- =============================================================================
-- This file documents the SQLite DDL used by bank/db.py (SCHEMA_SQL constant).
-- The application uses Python's built-in sqlite3 module with:
--   isolation_level = None  (manual BEGIN IMMEDIATE / COMMIT / ROLLBACK)
--   PRAGMA foreign_keys = ON
--
-- NOTE: The application creates and migrates this schema automatically via
--       bank.db.init_db(). You do NOT need to run this file manually.
--       It is provided here for review and documentation purposes only.
-- =============================================================================

PRAGMA foreign_keys = ON;

-- Users table: stores credentials (bcrypt-hashed), role, and lockout state.
CREATE TABLE IF NOT EXISTS Users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    email           TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,          -- bcrypt, work factor 12, random salt
    role            TEXT    NOT NULL DEFAULT 'user'
                            CHECK(role IN ('admin','user')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    is_locked       INTEGER NOT NULL DEFAULT 0, -- 0 = unlocked, 1 = locked
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Accounts table: one account per user; balance cannot go negative (DB constraint).
CREATE TABLE IF NOT EXISTS Accounts (
    account_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL UNIQUE REFERENCES Users(user_id),
    balance    DECIMAL(12,2) NOT NULL DEFAULT 0.00
                       CHECK(balance >= 0 AND ROUND(balance, 2) = balance), -- prevents overdraft and >2 decimals
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Transactions table: immutable ledger of all financial movements.
--   status: 'completed' for immediate transfers/deposits/withdrawals;
--           'pending'   for Maker-Checker high-value transfers awaiting approval;
--           'rejected'  for declined pending transfers.
CREATE TABLE IF NOT EXISTS Transactions (
    txn_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    from_account INTEGER REFERENCES Accounts(account_id),  -- NULL for deposits
    to_account   INTEGER REFERENCES Accounts(account_id),  -- NULL for withdrawals
    amount       DECIMAL(12,2) NOT NULL
                         CHECK(amount > 0 AND ROUND(amount, 2) = amount), -- negative and >2 decimal amounts blocked
    txn_type     TEXT    NOT NULL
                         CHECK(txn_type IN ('deposit','withdraw','transfer')),
    status       TEXT    NOT NULL DEFAULT 'completed'
                         CHECK(status IN ('completed','pending','rejected')),
    txn_time     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Audit_Log table: append-only, tamper-evident log using SHA-256 hash chaining.
--   previous_hash: entry_hash of the immediately preceding log row.
--   entry_hash:    SHA-256( previous_hash || user_id || action || log_time )
--   Genesis entry uses previous_hash = '000...0' (64 zeroes).
--   user_id may be NULL for pre-authentication events (e.g. unknown-email attempts).
CREATE TABLE IF NOT EXISTS Audit_Log (
    log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,                     -- nullable: unknown-email login attempts
    action        TEXT NOT NULL,
    log_time      TEXT NOT NULL DEFAULT (datetime('now')),
    previous_hash TEXT,                        -- hash of preceding log entry
    entry_hash    TEXT,                        -- SHA-256 hash of this entry
    ip_address    TEXT
);

-- Alerts table: security incidents raised by the application.
--   severity: 'low', 'medium', or 'high'.
--   status:   'open' (unresolved) or 'resolved' (remediated by admin).
CREATE TABLE IF NOT EXISTS Alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES Users(user_id),
    alert_type  TEXT    NOT NULL,
    description TEXT,
    severity    TEXT    NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high')),
    status      TEXT    NOT NULL DEFAULT 'open'
                       CHECK(status IN ('open','reviewed','closed')),
    alert_time  TEXT    NOT NULL DEFAULT (datetime('now')),
    reviewed_by INTEGER REFERENCES Users(user_id),
    reviewed_at TEXT,
    closed_by   INTEGER REFERENCES Users(user_id),
    closed_at   TEXT,
    resolution_note TEXT
);

-- Balance-change audit trigger (requires sha256_hex registered on connection).
CREATE TRIGGER IF NOT EXISTS after_accounts_balance_update
AFTER UPDATE OF balance ON Accounts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Audit_Log chain is corrupted or missing hash fields')
    WHERE EXISTS (SELECT 1 FROM Audit_Log)
      AND (
        (SELECT previous_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1) IS NULL
        OR (SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1) IS NULL
        OR LENGTH((SELECT previous_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)) != 64
        OR LENGTH((SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)) != 64
        OR (SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1) != sha256_hex(
            (SELECT previous_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
            || '|' || COALESCE(CAST((SELECT user_id FROM Audit_Log ORDER BY log_id DESC LIMIT 1) AS TEXT), 'None')
            || '|' || (SELECT action FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
            || '|' || (SELECT log_time FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
        )
      );

    INSERT INTO Audit_Log (user_id, action, log_time, previous_hash, entry_hash)
    SELECT
        v.user_id,
        v.action,
        v.log_time,
        v.prev_hash,
        sha256_hex(v.prev_hash || '|' || v.user_id || '|' || v.action || '|' || v.log_time)
    FROM (
        SELECT
            NEW.user_id AS user_id,
            'Account #' || NEW.account_id || ' balance updated: Rs'
            || printf('%.2f', OLD.balance) || ' -> Rs' || printf('%.2f', NEW.balance) AS action,
            datetime('now') AS log_time,
            CASE
                WHEN NOT EXISTS (SELECT 1 FROM Audit_Log)
                THEN '0000000000000000000000000000000000000000000000000000000000000000'
                ELSE (SELECT entry_hash FROM Audit_Log ORDER BY log_id DESC LIMIT 1)
            END AS prev_hash
    ) AS v;
END;

-- Append-only Audit_Log protection triggers.
CREATE TRIGGER IF NOT EXISTS prevent_audit_log_update
BEFORE UPDATE ON Audit_Log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Audit_Log is append-only: UPDATE is prohibited');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_log_delete
BEFORE DELETE ON Audit_Log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'Audit_Log is append-only: DELETE is prohibited');
END;
