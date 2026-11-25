# Project Report — Secure Banking System

**Author:** Ayush Kulhari  
**Project Type:** Educational DBMS + Cybersecurity Python Prototype

---

## 1. Overview

This project builds a command-line banking ledger in Python that pairs standard account operations (account lookup, deposits, withdrawals, transfers, transaction history) with layered DBMS and application security controls.

---

## 2. Database Schema & Normalization

The relational schema in [`bank/db.py`](../bank/db.py) uses five normalized tables:
- **`Users`**: stores name, unique email, `bcrypt` password hash, role (`admin` | `user`), failed login counter, and lockout flag.
- **`Accounts`**: 1:1 user account mapping with `DECIMAL(12,2)` balance and `CHECK(balance >= 0)`.
- **`Transactions`**: ledger of `deposit`, `withdraw`, and `transfer` rows with `DECIMAL(12,2)` amounts (`CHECK(amount > 0)`) and status (`completed`, `pending`, `rejected`).
- **`Audit_Log`**: hash-chained log entries (`previous_hash`, `entry_hash`) protected by append-only SQL triggers.
- **`Alerts`**: security incidents (`Brute Force`, `Large Transaction`, `Audit Log Tampering`) tracked across `open` -> `reviewed` -> `closed`.

---

## 3. Security & Transactional Controls

- **Authentication & Lockout (`bank/auth.py`):** Salted `bcrypt` hashing (`BCRYPT_ROUNDS = 12`), constant-work dummy verification for unknown emails, generic `"Invalid email or password."` error messages, 3-attempt account lockout raising one high-severity `"Brute Force"` alert, and admin-only account unlock.
- **Exact Money & ACID Transactions (`bank/security.py`, `bank/transactions.py`, `bank/db.py`):** Strict `Decimal("0.01")` validation, `DECIMAL(12,2)` schema columns, `BEGIN IMMEDIATE` (SQLite) and ordered `FOR UPDATE` row locks (MySQL) with safe rollback on error.
- **Data-Layer RBAC & Maker-Checker (`bank/transactions.py`, `main.py`):** Ownership and admin checks enforced in `bank/`; transfers strictly above `LARGE_TXN_THRESHOLD` (`Rs 50,000.00`) enter `'pending'`, reserve outgoing funds, and require approval by an independent admin (blocking non-admins, the maker, and recipient admins). Deposits and withdrawals execute immediately without Maker-Checker.
- **Audit Hash Chain & SQL Triggers (`bank/audit.py`, `bank/db.py`, `sql/triggers.sql`):** SHA-256 hash-chained `Audit_Log` writes inside active transactions, fail-closed verification, automatic balance-update triggers on `Accounts`, and `BEFORE UPDATE` / `BEFORE DELETE` triggers rejecting direct log edits.
- **Alerts & Backups (`bank/alerts.py`, `backup_restore.py`):** Atomic alerts on lockout and large transactions, plus hot SQLite backups with `.sha256` checksum verification.

---

## 4. Database Backends & Verification

- **SQLite 3** is the default local/testing backend.
- **MySQL 8+ (`mysql-connector-python`)** is supported via environment variables (`DB_TYPE=mysql`), explicit provisioning (`setup_db.py`, `scripts/setup_mysql.py`), and least-privilege verification (`verify_least_privilege.py`), with zero silent fallback to SQLite.
- **Automated Testing:** `python -m pytest tests/ -v` runs **240 tests** against isolated SQLite databases and mocked MySQL connector tests. Live MySQL execution was not tested in this environment.
