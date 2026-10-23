-- =============================================================================
-- schema.sql  --  ACTUAL PRODUCTION SCHEMA (SQLite / sqlite3)
-- =============================================================================
-- This file documents the exact DDL used by db.py (SCHEMA_SQL constant).
-- The application uses Python's built-in sqlite3 module with:
--   isolation_level = None  (manual BEGIN / COMMIT / ROLLBACK)
--   PRAGMA foreign_keys = ON
--
-- NOTE: The application creates and migrates this schema automatically via
--       db.init_db().  You do NOT need to run this file manually.
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
    balance    REAL    NOT NULL DEFAULT 0.00
                       CHECK(balance >= 0),     -- prevents overdraft at DB level
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
    amount       REAL    NOT NULL CHECK(amount > 0),        -- negative amounts blocked at DB level
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
    entry_hash    TEXT                         -- SHA-256 hash of this entry
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
