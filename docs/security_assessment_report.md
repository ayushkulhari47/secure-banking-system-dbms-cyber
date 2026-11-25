# Security Assessment & Remediation Summary

**System:** Secure Banking System (Python CLI, SQLite + optional MySQL path)  
**Status:** Educational prototype hardened across modular package architecture, database configuration, `bcrypt` authentication, data-layer RBAC, `Decimal` money handling, atomic transfers, atomic audit triggers, intrusion alerts, and Maker-Checker verification (**240 passed, 0 failed** on the SQLite + mocked-MySQL test suite; live MySQL was not tested in this environment).

---

## Remediated Findings Matrix

| ID | Finding | Severity | Remediation Implemented | Code Location | Test Proof |
|---|---|---|---|---|---|
| **FIND-01** | Negative / Invalid Amount Exploits | **Critical** | Strict `Decimal` validation (`parse_money_input`, `validate_amount`) rejecting `bool`, `<= 0`, `NaN`, `Infinity`, `> 2` decimal places, and `> MAX_AMOUNT`; `DECIMAL(12,2)` and SQL `CHECK` constraints. | [`bank/security.py`](../bank/security.py), [`bank/db.py`](../bank/db.py) | `tests/test_decimal_money.py`, `tests/test_security_fixes.py::TestAmountValidation` |
| **FIND-02** | Weak Password Storage | **Critical** | Salted adaptive `bcrypt` (`BCRYPT_ROUNDS = 12`) with runtime `DUMMY_PASSWORD_HASH` for constant-work unknown-email verification and enforced password complexity. | [`bank/auth.py`](../bank/auth.py), [`bank/security.py`](../bank/security.py) | `tests/test_auth_login.py`, `tests/test_security_fixes.py::TestBcryptHashing` |
| **FIND-03** | Missing Data-Layer RBAC & Ownership | **Critical** | Ownership and admin checks enforced inside [`bank/`](../bank/) data functions as well as [`main.py`](../main.py). | [`bank/transactions.py`](../bank/transactions.py), [`bank/audit.py`](../bank/audit.py), [`bank/alerts.py`](../bank/alerts.py), [`bank/auth.py`](../bank/auth.py) | `tests/test_rbac_data_layer.py` |
| **FIND-04** | Non-Atomic Transactions & Races | **High** | Explicit `BEGIN IMMEDIATE` (SQLite) and ordered `FOR UPDATE` locks (MySQL) with `safe_rollback()` and pending outgoing reserve checks. | [`bank/db.py`](../bank/db.py), [`bank/transactions.py`](../bank/transactions.py) | `tests/test_atomic_transfers.py` |
| **FIND-05** | Crash on Non-Numeric CLI Input | **High** | Exception-safe `safe_decimal_input()` and `safe_int_input()` wrappers returning `None` cleanly on malformed input. | [`bank/security.py`](../bank/security.py) | `tests/test_security_fixes.py::TestSafeInputWrappers` |
| **FIND-06** | Unlimited Brute-Force Attempts | **High** | Persistent 3-attempt lockout (`MAX_FAILED_LOGINS = 3`), single high-severity `"Brute Force"` alert on transition, and generic login failure errors. | [`bank/auth.py`](../bank/auth.py), [`main.py`](../main.py) | `tests/test_intrusion_and_unlock.py`, `tests/test_auth_login.py` |
| **FIND-07** | Mutable / Unchained Audit Trail | **High** | Atomic transaction-scoped `Audit_Log` SHA-256 hash chaining (`previous_hash`, `entry_hash`), automatic balance-change triggers, `BEFORE UPDATE`/`DELETE` abort triggers, and `verify_audit_log_integrity()`. | [`bank/audit.py`](../bank/audit.py), [`bank/db.py`](../bank/db.py) | `tests/test_atomic_audit.py`, `tests/test_audit_triggers.py` |
| **FIND-08** | Untracked Unknown-Email Probes | **High** | Failed unknown-email login attempts record `user_id = NULL` inside `Audit_Log` while returning generic `"Invalid email or password."`. | [`bank/auth.py`](../bank/auth.py) | `tests/test_database.py`, `tests/test_auth_login.py` |
| **FIND-09** | Permanent Lockout Without Recovery | **Medium** | Admin-only `unlock_user()` and `get_locked_users()` reset `is_locked = 0` and `failed_attempts = 0` with audit logging. | [`bank/auth.py`](../bank/auth.py), [`main.py`](../main.py) | `tests/test_intrusion_and_unlock.py`, `tests/test_rbac_data_layer.py` |
| **FIND-10** | Single-Point High-Value Transfers | **Medium** | Maker-Checker dual control for transfers `> LARGE_TXN_THRESHOLD` (`Rs 50,000.00`), reserving funds and blocking non-admins, makers, and recipient admins from approving. | [`bank/transactions.py`](../bank/transactions.py), [`main.py`](../main.py) | `tests/test_maker_checker.py`, `tests/test_rbac_data_layer.py` |

---

## Verification Instructions

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -r requirements.txt
python -m pytest tests/ -v
```

> [!NOTE]
> Automated tests prove the SQLite path and mocked `mysql-connector-python` behavior. Live MySQL provisioning (`setup_db.py`, `scripts/setup_mysql.py`, `verify_least_privilege.py`) requires a running MySQL instance and was not executed live in this environment.
