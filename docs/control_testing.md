# IT Audit Control Testing Workpaper & Evidence Report

**Engagement:** Cyber Risk & IT Controls Review (IT Audit)  
**Target System:** Secure Banking System (Core Ledger & Security Subsystems)  
**Audit Standard:** ISO/IEC 27001:2022 / COBIT 2019 / SOX ITGC Testing  
**Audit Test Run:** October 2026  
**Total Automated Tests:** 74  
**Audit Test Status:** **74 Passed / 0 Failed / 0 Exceptions (100% Effective)**  

---

## 1. Executive Testing Summary
During this control testing cycle, the IT Audit team evaluated the design and operating effectiveness of the key automated controls governing the **Secure Banking System**. Testing encompassed application controls, database integrity constraints, cryptographic protection mechanisms, role-based access limits, Maker-Checker segregation of duties, and audit trail resilience.

All 74 control tests were executed through the hermetic automated testing suite (`pytest`), verifying that controls perform in strict accordance with documented security policies.

---

## 2. Detailed Control Testing Workpaper

| Control Ref | Control Name | Test Procedure Performed | Expected Result | Actual Result Observed | Operating Effectiveness | Test Evidence (Pytest Function) |
|---|---|---|---|---|---|---|
| **CTL-01** | **SQL Injection Prevention** | Attempted to submit SQL metacharacters (`' OR 1=1 --`) and raw syntax into account query parameters. | SQL statements must treat input purely as parameter data via SQLite parameterized queries (`?`). | All queries execute safely; no SQL syntax injected or unescaped. | **Effective** | [tests/test_database.py::TestSchema](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_database.py#L109) |
| **CTL-02** | **Bcrypt Password Cryptography** | Hashed test password twice and inspected hash structure and salt randomness. | Output must begin with `$2b$`, incorporate work factor 12, and generate distinct hashes for identical passwords. | Hashes format verified; identical passwords generated completely different outputs. | **Effective** | [tests/test_security_fixes.py::TestBcryptHashing](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L293) |
| **CTL-03** | **Password Complexity Policy** | Tested passwords missing uppercase, lowercase, numbers, special characters, or $<8$ chars. | Passwords violating policy are rejected with specific diagnostic violation messages. | All non-compliant passwords rejected; valid passwords approved. | **Effective** | [tests/test_security_fixes.py::TestPasswordPolicy](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L155) |
| **CTL-04** | **Brute-Force Account Lockout** | Simulated 3 consecutive failed login attempts on valid account `rahul@bank.com`. | Account locks automatically (`is_locked=1`), lockout counter increments to 3, and high-severity alert generated. | Account locked; 4th login attempt denied; alert generated. | **Effective** | [tests/test_security_fixes.py::TestBruteForceLockout](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L328) |
| **CTL-05** | **Negative Amount Exploitation Guard** | Attempted deposit/transfer with `-5000.00`, `0.00`, `NaN`, and `Infinity`. | Input rejected at application layer ([validate_amount](file:///c:/Users/itsme/Downloads/secure-banking-system/security.py#L35)) and database layer (`CHECK(amount > 0)`). | All invalid and negative values rejected with clear error message; balance unaffected. | **Effective** | [tests/test_security_fixes.py::TestAmountValidation](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L35) |
| **CTL-06** | **Safe Input Exception Handling** | Submitted string inputs (`"abc"`, `""`, `"!@#"`) into numeric input prompts. | Prompts must not raise unhandled `ValueError`; must return `None` gracefully. | `safe_float_input()` and `safe_int_input()` handled non-numeric values without crashing. | **Effective** | [tests/test_security_fixes.py::TestSafeInputWrappers](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L104) |
| **CTL-07** | **Inactivity Session Timeout** | Initialized session, waited past inactivity duration, and queried session status. | `is_expired()` returns `True`; user auto-logged out upon next menu loop. | Session expired after timeout; active refresh resets timer properly. | **Effective** | [tests/test_security_fixes.py::TestSessionInactivityTimeout](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L210) |
| **CTL-08** | **Role-Based Access Control (RBAC)** | Authenticated as standard user (`role='user'`) and attempted to access admin audit log and alert views. | Access denied with explicit error message; unauthorized access attempt logged to audit trail. | Access rejected; violation recorded in `Audit_Log`. | **Effective** | [tests/test_security_fixes.py::TestRoleBasedAccessControl](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L363) |
| **CTL-09** | **Self-Transfer Restriction** | Attempted to initiate transfer where `from_account == to_account`. | Transfer blocked with informative error before reaching database layer. | Self-transfer intercepted; zero database writes committed. | **Effective** | [tests/test_security_fixes.py::TestSelfTransferBlock](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_security_fixes.py#L262) |
| **CTL-10** | **Maker-Checker Segregation of Duties** | (a) Initiated transfer of Rs 75,000 (> threshold).<br>(b) Maker attempted self-approval.<br>(c) Independent checker approved transfer. | (a) Status set to `pending`; balances unchanged.<br>(b) Self-approval blocked with SoD violation.<br>(c) Balances debited & credited atomically upon checker approval. | (a) Transfer queued in `pending`.<br>(b) SoD violation returned.<br>(c) Independent approval executed transfer correctly. | **Effective** | [tests/test_cyber_controls.py::TestMakerCheckerWorkflow](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_cyber_controls.py#L108) |
| **CTL-11** | **Centralized Security Configuration** | Validated parameters across [config.py](file:///c:/Users/itsme/Downloads/secure-banking-system/config.py) against security baseline requirements. | All parameters (`LARGE_TXN_THRESHOLD`, `MAX_FAILED_LOGINS`, etc.) must exist, be typed, and within bounds. | All configuration constants present and validated. | **Effective** | [tests/test_cyber_controls.py::TestCentralizedConfiguration](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_cyber_controls.py#L40) |
| **CTL-12** | **Tamper-Evident Audit Hash Chaining** | Inserted audit records and verified `previous_hash` and `entry_hash` linkage. | SHA-256 hash chain links each entry to preceding record; verification passes on untampered log. | Hash chain correctly generated; `verify_audit_log_integrity()` returns `(True, None)`. | **Effective** | [tests/test_cyber_controls.py::TestTamperEvidentAuditLog](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_cyber_controls.py#L60) |
| **CTL-13** | **Audit Log Tamper Detection** | Directly altered an audit action string and altered a `previous_hash` pointer in SQLite. | `verify_audit_log_integrity()` must return `False` and return the exact corrupted `log_id`. | Tampering detected immediately; exact record IDs (e.g., `log_id=2`, `log_id=3`) flagged. | **Effective** | [tests/test_cyber_controls.py::TestTamperEvidentAuditLog](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_cyber_controls.py#L88) |
| **CTL-14** | **Admin Account Unlock Remediation** | Locked account via 3 failed logins, then invoked admin `unlock_user()`. | `is_locked` reset to 0, `failed_attempts` reset to 0; user successfully logs in. | Account unlocked; user removed from locked accounts register. | **Effective** | [tests/test_cyber_controls.py::TestAdminAccountUnlock](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_cyber_controls.py#L190) |
| **CTL-15** | **Security Alert Remediation** | Generated security alert with status `open`, then called `resolve_alert()`. | Alert status transitions to `resolved`; removed from open alerts view. | Alert status updated to `resolved`; audit record logged. | **Effective** | [tests/test_cyber_controls.py::TestSecurityAlertRemediation](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_cyber_controls.py#L225) |
| **CTL-16** | **ACID Transaction Atomicity & Rollback** | Simulated intentional error during deposit/withdraw/transfer midway through execution. | Entire multi-table transaction must roll back; balances remain unchanged. | Rollback verified; zero partial state or phantom funds created. | **Effective** | [tests/test_database.py::TestACIDDeposit](file:///c:/Users/itsme/Downloads/secure-banking-system/tests/test_database.py#L170), `TestACIDWithdraw`, `TestACIDTransfer` |

---

## 3. Test Execution Command
To re-run and independently reproduce this test evidence on any workstation:
```bash
python -m pytest tests/ -v
```
All 74 tests execute hermetically in isolated memory or temporary storage, leaving no lingering artifacts or database locks.
