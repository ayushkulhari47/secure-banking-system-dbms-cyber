# Database Entity-Relationship (ER) Architecture & Data Dictionary

**System Name:** Secure Banking System  
**Database Design:** Normalized 3NF Relational Schema with Foreign Keys, `DECIMAL(12,2)` Money Columns, Audit Triggers, and SHA-256 Hash Chaining (Authoritative DDL in [`bank/db.py`](../bank/db.py))

---

## 1. Visual Entity-Relationship Diagram (Mermaid)

```mermaid
erDiagram
    Users ||--|| Accounts : "owns (1:1)"
    Users ||--o{ Audit_Log : "actor (1:N)"
    Users ||--o{ Alerts : "subject / reviewer (1:N)"
    Accounts ||--o{ Transactions : "source / destination (1:N)"

    Users {
        INTEGER user_id PK "Auto-increment identifier"
        TEXT name "Customer / Admin full name"
        TEXT email UK "Unique login email"
        TEXT password_hash "Salted bcrypt hash (rounds=12)"
        TEXT role "'admin' | 'user'"
        INTEGER failed_attempts "Consecutive failed login count"
        INTEGER is_locked "0=unlocked, 1=locked"
        TEXT created_at "UTC creation timestamp"
    }

    Accounts {
        INTEGER account_id PK "Auto-increment primary key"
        INTEGER user_id FK "References Users(user_id) UNIQUE"
        DECIMAL balance "DECIMAL(12,2), CHECK(balance >= 0)"
        TEXT created_at "UTC creation timestamp"
    }

    Transactions {
        INTEGER txn_id PK "Unique sequence ID"
        INTEGER from_account FK "References Accounts(account_id), NULL for deposits"
        INTEGER to_account FK "References Accounts(account_id), NULL for withdrawals"
        DECIMAL amount "DECIMAL(12,2), CHECK(amount > 0)"
        TEXT txn_type "'deposit' | 'withdraw' | 'transfer'"
        TEXT status "'completed' | 'pending' | 'rejected'"
        TEXT txn_time "UTC transaction timestamp"
    }

    Audit_Log {
        INTEGER log_id PK "Monotonic sequence key"
        INTEGER user_id FK "Actor user_id or NULL for unknown-email attempts"
        TEXT action "Event description"
        TEXT log_time "UTC timestamp"
        TEXT previous_hash "64-char SHA-256 pointer (genesis=64 zeroes)"
        TEXT entry_hash "SHA-256(previous_hash|user_id|action|log_time)"
        TEXT ip_address "Optional client/source IP field"
    }

    Alerts {
        INTEGER alert_id PK "Unique alert ID"
        INTEGER user_id FK "Subject user_id"
        TEXT alert_type "'Brute Force' | 'Large Transaction' | 'Audit Log Tampering'"
        TEXT description "Event context"
        TEXT severity "'low' | 'medium' | 'high'"
        TEXT status "'open' | 'reviewed' | 'closed'"
        TEXT alert_time "UTC trigger timestamp"
        INTEGER reviewed_by FK "Admin user_id who reviewed"
        TEXT reviewed_at "UTC review timestamp"
        INTEGER closed_by FK "Admin user_id who closed"
        TEXT closed_at "UTC closure timestamp"
        TEXT resolution_note "Optional triage/closure note"
    }
```

---

## 2. Relational Integrity & Trigger Rules

1. **Users (1) <-> Accounts (1):** Enforced via `user_id ... UNIQUE REFERENCES Users(user_id)`. Balances use `DECIMAL(12,2)` with non-negative checks (`balance >= 0`, plus `ROUND(balance, 2) = balance` on SQLite).
2. **Accounts (1) <-> Transactions (0..N):** Captures deposits (`from_account IS NULL`), withdrawals (`to_account IS NULL`), and transfers (`from_account` and `to_account`), enforcing `amount > 0` and 2-decimal precision.
3. **Audit_Log Triggers & Hash Chain:**
   - `after_accounts_balance_update`: Automatically inserts a hash-chained `Audit_Log` entry on every `Accounts.balance` update (`sha256_hex` UDF on SQLite; `SHA2(..., 256)` on MySQL) and aborts if the existing chain tail is corrupt or unhashed.
   - `prevent_audit_log_update` / `prevent_audit_log_delete`: Block every `UPDATE` and `DELETE` on `Audit_Log`.
4. **Alerts Lifecycle:** Supports `open` -> `reviewed` -> `closed` transitions with reviewing/closing administrator attribution (`reviewed_by`, `closed_by`, `resolution_note`).
