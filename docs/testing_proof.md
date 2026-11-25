# Testing Proof (Historical Phase 0 Note + Current Test Suite)

> [!NOTE]
> The screenshots `test1.png`–`test5.png` in this folder were captured during the earliest initial prototype stage (when a single script tested basic SQL/Python behavior on online sandboxes). Since then, the codebase was refactored into `main.py` and the `bank/` package with `bcrypt` authentication, generic `"Invalid email or password."` login failures, `Decimal` money handling, data-layer RBAC, atomic audit logging/triggers, and Maker-Checker hardening.

## Current Automated Verification

Run the active automated suite locally via:

```bash
python -m pytest tests/ -v
```

Current working-copy verification executes **240 automated `pytest` tests** across SQLite test databases (and mocked `mysql-connector-python` tests):
- `tests/test_database.py`, `tests/test_security_fixes.py`, `tests/test_cyber_controls.py`, `tests/test_phase3.py`
- `tests/test_config_db.py`, `tests/test_auth_login.py`, `tests/test_rbac_data_layer.py`
- `tests/test_decimal_money.py`, `tests/test_atomic_transfers.py`, `tests/test_atomic_audit.py`
- `tests/test_audit_triggers.py`, `tests/test_intrusion_and_unlock.py`, `tests/test_maker_checker.py`
- `tests/test_backup_restore.py`

*(Live MySQL execution was not tested in this environment.)*
