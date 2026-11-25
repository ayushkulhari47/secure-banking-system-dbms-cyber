# Secure Banking System: Presentation Outline & Q&A

**Presenter:** Ayush Kulhari  
**Project Type:** Educational Banking Core & Security Controls Prototype

---

## 5-Slide Presentation Outline

### Slide 1: Problem Statement & Objectives
- **Title:** Engineering Resilience: Turning a Prototype Ledger into an Auditable Core
- **Points:**
  - *Baseline Gaps:* Early prototype lacked persistent ACID storage, salted password hashing, data-layer RBAC, exact currency arithmetic, and tamper-evident audit logging.
  - *Core Risks:* Negative-amount transfer exploits, credential cracking, brute-force attacks, TOCTOU race conditions, and silent audit modification.
  - *Objective:* Refactor into a modular `bank/` package backed by SQLite (testing) and optional MySQL (`mysql-connector-python`), with automated `pytest` verification.

### Slide 2: Technical Architecture & Defense-in-Depth
- **Title:** Modular Architecture: Application + Data Layer + SQL Triggers
- **Points:**
  - *Package Layout:* CLI in [`main.py`](../main.py), modular business/data controls in [`bank/`](../bank/), explicit provisioning/seeding in [`setup_db.py`](../setup_db.py) and [`scripts/seed_demo.py`](../scripts/seed_demo.py).
  - *Exact Currency:* Python `Decimal("0.01")` + `DECIMAL(12,2)` SQL columns + 2-decimal `CHECK` constraints.
  - *Atomic Concurrency:* `BEGIN IMMEDIATE` on SQLite and `SELECT ... FOR UPDATE` (sorted by `account_id`) on MySQL.
  - *Tamper-Evident Audit Trail:* SHA-256 hash chaining (`previous_hash`, `entry_hash`) + append-only SQL triggers on `Accounts` and `Audit_Log`.

### Slide 3: Key Vulnerabilities Remediated
- **Title:** Closing High-Impact Banking Exploits
- **Points:**
  - *Negative / Invalid Transfers:* Blocked via `validate_amount()` and `CHECK(amount > 0)`.
  - *Authentication & Lockout:* Salted `bcrypt` (cost 12), runtime `DUMMY_PASSWORD_HASH`, generic `"Invalid email or password."` failures, 3-attempt lockout, single `"Brute Force"` alert, and admin unlock.
  - *Privilege Separation:* Data-layer ownership checks + admin-only audit, alert, unlock, and approval paths.
  - *Maker-Checker Dual Control:* Transfers > `LARGE_TXN_THRESHOLD` (`Rs 50,000.00`) queue as `'pending'`, reserve outgoing funds, and block maker/recipient self-approval.

### Slide 4: Verification & Limitations
- **Title:** Automated Testing & Honest Engineering Scope
- **Points:**
  - *Automated Evidence:* 240 passing `pytest` tests exercising SQLite transactions, triggers, RBAC, `Decimal`, Maker-Checker, intrusion alerts, and backups (plus mocked MySQL tests).
  - *Explicit Boundaries:* Live MySQL was not tested in this environment; velocity tracking is process-local; SQLite/CLI are educational rather than production banking infrastructure.

### Slide 5: Operational Resilience & Lessons Learned
- **Points:**
  - Enforce authorization and validation in the data layer (`bank/`), not only the CLI UI.
  - Keep audit entries and security alerts inside the same database transaction as the triggering operation.
  - Back application logic with database triggers and constraints so direct SQL edits cannot silently corrupt balances or logs.

---

## 8 Technical Q&As

### Q1: Why use `bcrypt` instead of SHA-256 for password storage?
SHA-256 is fast and optimized for throughput, making unsalted hashes vulnerable to GPU cracking and rainbow tables. `bank/auth.py` uses `bcrypt` (`BCRYPT_ROUNDS = 12`) with per-password random salts and constant-work dummy verification for unknown emails.

### Q2: How does Maker-Checker Segregation of Duties work?
In [`main.py`](../main.py) (`do_transfer`) and [`bank/transactions.py`](../bank/transactions.py), transfers `> Rs 50,000.00` call `create_pending_transfer()` (`status = 'pending'`), reserving outgoing funds without updating balances. `approve_pending_transfer()` rejects non-admins, the maker (`from_acc["user_id"]`), and any admin recipient (`to_acc["user_id"]`), allowing only an independent admin to approve.

### Q3: How are `Audit_Log` entries protected against tampering?
[`bank/audit.py`](../bank/audit.py) computes `SHA-256(previous_hash|user_id|action|log_time)` inside the caller's active transaction and fails closed on corrupt chain tails. Additionally, SQL triggers in [`bank/db.py`](../bank/db.py) (`after_accounts_balance_update`, `prevent_audit_log_update`, `prevent_audit_log_delete`) hash-chain balance changes automatically and block `UPDATE` / `DELETE` on `Audit_Log`.

### Q4: How do you prevent double-spending and TOCTOU race conditions?
Deposits, withdrawals, transfers, and approvals acquire write transactions up front (`BEGIN IMMEDIATE` on SQLite; `FOR UPDATE` sorted by `account_id` on MySQL), subtract pending outgoing transfers via `_pending_outgoing_total()`, and rely on `CHECK(balance >= 0)` in the schema.

### Q5: How do you ensure exact monetary math?
All inputs go through `parse_money_input()` and `validate_amount()` in [`bank/security.py`](../bank/security.py) using `Decimal`, rejecting `bool`, `NaN`, `Infinity`, `<= 0`, and `> 2` decimal places, paired with `DECIMAL(12,2)` columns.

### Q6: How do failed-transaction rollbacks avoid orphan alerts or audit entries?
`audit.log_action(..., conn=conn)` and `alerts.raise_alert(..., conn=conn)` participate in the active transaction `conn`, so `safe_rollback(conn)` discards alerts, audit rows, transactions, and balance updates together on error.

### Q7: How is database configuration secured?
[`bank/config.py`](../bank/config.py) reads `DB_*` variables exclusively from the environment with no hardcoded root defaults, `scripts/seed_demo.py` handles demo seeding separately from `init_db()`, and `get_connection()` refuses silent fallback from MySQL to SQLite.

### Q8: What are the project's known limitations?
Live MySQL was not tested in this environment, CLI velocity tracking (`_TRANSACTION_TIMES` in [`main.py`](../main.py)) is process-local, SQLite is intended only for local study/testing, and this is an educational prototype without network API/TLS, MFA, or external WORM SIEM shipping.
