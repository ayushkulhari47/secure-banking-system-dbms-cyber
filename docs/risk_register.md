# Risk Register & Threat Mitigation Summary

**System Name:** Secure Banking System  
**Scope:** Threat scenarios and implemented mitigations in [`bank/`](../bank/) and [`main.py`](../main.py)

---

| Risk ID | Threat Scenario | Mitigating Controls Implemented | Implementation Location |
|---|---|---|---|
| **RSK-01** | **SQL Injection (SQLi)** | All queries use parameterized placeholders (`?` / `%s`); `detect_sqli()` also logs suspicious CLI inputs. | [`bank/db.py`](../bank/db.py), [`bank/transactions.py`](../bank/transactions.py), [`bank/auth.py`](../bank/auth.py), [`bank/security.py`](../bank/security.py) |
| **RSK-02** | **Offline Credential Cracking** | Passwords hashed with salted `bcrypt` (`BCRYPT_ROUNDS = 12`); `password_meets_policy()` enforced on changes and demo seeding. | [`bank/auth.py`](../bank/auth.py), [`bank/security.py`](../bank/security.py), [`scripts/seed_demo.py`](../scripts/seed_demo.py) |
| **RSK-03** | **Online Brute Force & Enumeration** | 3-attempt lockout (`MAX_FAILED_LOGINS = 3`), single high-severity `"Brute Force"` alert on lock transition, runtime `DUMMY_PASSWORD_HASH`, and generic `"Invalid email or password."` error. | [`bank/auth.py`](../bank/auth.py), [`main.py`](../main.py) |
| **RSK-04** | **Invalid / Precision / Negative Amount Exploits** | Strict `Decimal` validation (`0.01 <= amount <= 1,000,000.00`, rejects `bool`, `NaN`, `Infinity`, `> 2` decimals) plus `DECIMAL(12,2)` and SQL `CHECK` constraints. | [`bank/security.py`](../bank/security.py), [`bank/transactions.py`](../bank/transactions.py), [`bank/db.py`](../bank/db.py) |
| **RSK-05** | **Unauthorized High-Value Transfers** | Maker-Checker dual control for transfers `> LARGE_TXN_THRESHOLD` (`Rs 50,000.00`), pending fund reservation, and Segregation of Duties (blocks non-admins, maker, recipient admin). | [`bank/transactions.py`](../bank/transactions.py), [`main.py`](../main.py) |
| **RSK-06** | **Unattended Terminal Takeover** | Monotonic inactivity `Session` timeout auto-logs out after 300 seconds (`SESSION_TIMEOUT_SECONDS`). | [`bank/security.py`](../bank/security.py), [`main.py`](../main.py) |
| **RSK-07** | **Horizontal / Vertical Access Escalation** | Data-layer ownership and admin checks inside [`bank/`](../bank/) functions as well as CLI menu guards. | [`bank/transactions.py`](../bank/transactions.py), [`bank/auth.py`](../bank/auth.py), [`bank/audit.py`](../bank/audit.py), [`bank/alerts.py`](../bank/alerts.py) |
| **RSK-08** | **Audit Log Tampering** | SHA-256 hash chaining (`previous_hash`, `entry_hash`), fail-closed chain checks, balance-change audit triggers, `BEFORE UPDATE`/`DELETE` abort triggers, and `verify_audit_log_integrity()`. | [`bank/audit.py`](../bank/audit.py), [`bank/db.py`](../bank/db.py), [`sql/triggers.sql`](../sql/triggers.sql) |
| **RSK-09** | **Input Parsing Crashes** | `safe_decimal_input()` and `safe_int_input()` handle malformed numeric input safely without crashing. | [`bank/security.py`](../bank/security.py) |
| **RSK-10** | **Partial Writes / Double-Spending Races** | Explicit `BEGIN IMMEDIATE` (SQLite) and `FOR UPDATE` sorted by `account_id` (MySQL) with `safe_rollback()` and pending reserve deductions. | [`bank/db.py`](../bank/db.py), [`bank/transactions.py`](../bank/transactions.py) |
