# Control Testing Workpaper & Evidence Report

**Target System:** Secure Banking System (Core Ledger & Security Subsystems)  
**Total Automated Tests:** 240  
**Current Test Status:** **240 passed / 0 failed** (executed against isolated SQLite test databases plus mocked `mysql-connector-python` tests)

> [!NOTE]
> Scope note: This is an educational testing summary, not an independent audit or certification. Live MySQL execution (`setup_db.py`, `scripts/setup_mysql.py`, and `verify_least_privilege.py`) requires a running MySQL server and was **not** tested live in this environment.

---

## 1. Executive Testing Summary

The `pytest` suite evaluates database constraints, `Decimal` monetary validation, `bcrypt` authentication, constant-work unknown-email handling, 3-attempt brute-force lockout, data-layer RBAC and ownership checks, ACID transaction rollback, Maker-Checker Segregation of Duties, SHA-256 audit hash chaining, append-only SQL triggers, alert workflows, and SQLite hot backup/restore integrity.

---

## 2. Automated Test Modules

| Test File | Scope Covered |
|---|---|
| [`tests/test_database.py`](../tests/test_database.py) | Schema constraints, email uniqueness, ACID rollback behavior, and `Audit_Log` basics |
| [`tests/test_security_fixes.py`](../tests/test_security_fixes.py) | Amount bounds, safe CLI wrappers, password policy, `Session` timeout, self-transfer block, `bcrypt`, RBAC |
| [`tests/test_cyber_controls.py`](../tests/test_cyber_controls.py) | Configuration constants, audit tamper detection, Maker-Checker workflow, admin unlock, alert remediation |
| [`tests/test_phase3.py`](../tests/test_phase3.py) | Password change flow, SQLi/velocity/odd-hour helpers, atomic transfers, amount validation |
| [`tests/test_config_db.py`](../tests/test_config_db.py) | Env-driven DB configuration, zero hardcoded root credentials, `mysql-connector-python` wrapper, fail-closed engine selection |
| [`tests/test_auth_login.py`](../tests/test_auth_login.py) | Runtime `DUMMY_PASSWORD_HASH` verification, generic login failure output, demo seed password policy |
| [`tests/test_rbac_data_layer.py`](../tests/test_rbac_data_layer.py) | Data-layer ownership checks, admin-only audit/alerts/unlock, Maker-Checker SoD checks |
| [`tests/test_decimal_money.py`](../tests/test_decimal_money.py) | Exact `Decimal` arithmetic, 2-decimal precision enforcement, bool/NaN/Inf rejection, SQLite `CHECK(ROUND(..., 2) = ...)` |
| [`tests/test_atomic_transfers.py`](../tests/test_atomic_transfers.py) | Fault-injected mid-transfer/approval rollbacks, pending balance reserves, `BEGIN IMMEDIATE` / MySQL `FOR UPDATE` |
| [`tests/test_atomic_audit.py`](../tests/test_atomic_audit.py) | Single-connection atomic audit inserts, rollback consistency, fail-closed chain verification |
| [`tests/test_audit_triggers.py`](../tests/test_audit_triggers.py) | SQLite balance-change triggers, `UPDATE`/`DELETE` block triggers, MySQL trigger definitions, no duplicate audit rows |
| [`tests/test_intrusion_and_unlock.py`](../tests/test_intrusion_and_unlock.py) | 3-attempt lockout transition, single Brute Force alert, admin-only unlock, atomic Large Transaction alerts |
| [`tests/test_maker_checker.py`](../tests/test_maker_checker.py) | Threshold routing (`<= 50,000.00` vs `> 50,000.00`), pending reserves, SoD, safe insufficient-fund rejection, reserve release, idempotency |
| [`tests/test_backup_restore.py`](../tests/test_backup_restore.py) | SQLite online hot backup, `.sha256` sidecar check, tampered backup rejection, atomic restore |

---

## 3. Verification Commands

```bash
python -m compileall -q bank main.py setup_db.py backup_restore.py verify_least_privilege.py scripts tests
python -m pytest tests/ -v
```
