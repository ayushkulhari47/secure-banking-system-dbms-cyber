# Security Assessment Report

**Document Type:** IT Security Assessment & Vulnerability Remediation Report  
**System:** Secure Banking System (Python CLI, SQLite)  
**Assessment Scope:** Full application — authentication, authorization, data integrity, transaction processing, audit logging  
**Assessment Date:** October 2026  
**Assessor:** Ayush Kulhari  
**Status:** Legacy assessment baseline. The current working copy has 123 passing SQLite tests, but the Phase 3/MySQL findings are still being closed and this document is not a production assurance report.

---

## 1. Executive Summary

An initial security assessment of the **Secure Banking System** identified **10 critical and high-severity vulnerabilities** across authentication, input handling, access control, data persistence, and audit trail integrity. All findings have been remediated across three development phases. Each fix is backed by automated pytest evidence executable on any clean clone.

| Severity | Total Found | Remediated | Remaining |
|---|---|---|---|
| **Critical** | 3 | 3 | 0 |
| **High** | 5 | 5 | 0 |
| **Medium** | 2 | 2 | 0 |
| **Total** | **10** | **10** | **0** |

---

## 2. Findings Table

| ID | Title | Severity | Description & Evidence of Vulnerability | Recommendation | Status | Fix Location | Automated Test Proof |
|---|---|---|---|---|---|---|---|
| **FIND-01** | Negative-Amount Fund Theft Exploit | **Critical** | **Where found:** `app.py` (original) — `float(input())` passed directly to balance arithmetic with no sign check. **Evidence:** `transfer(-5000)` subtracted −5000 from sender (credit) and −5000 from receiver (debit), stealing Rs 5,000 per call. | Apply multi-layer amount validation: reject ≤ 0, NaN, Inf at application layer; enforce `CHECK(amount > 0)` at database layer. | **Fixed** | `security.validate_amount()` [security.py:L33]; `CHECK(amount > 0)` [db.py SCHEMA_SQL] | `tests/test_security_fixes.py::TestAmountValidation` (10 tests) |
| **FIND-02** | Unsalted SHA-256 Password Storage | **Critical** | **Where found:** `app.py` (original) — `hashlib.sha256(password.encode()).hexdigest()` used with no salt. **Evidence:** Identical passwords produced identical hashes; susceptible to precomputed rainbow table and dictionary attacks. | Replace with adaptive password hashing (bcrypt, work factor ≥ 10) generating unique per-password random salts. | **Fixed** | `db.hash_password()` [db.py:L172], `db.verify_password()` [db.py:L201] — bcrypt work factor 12, 16-byte random salt | `tests/test_security_fixes.py::TestBcryptHashing` (6 tests) |
| **FIND-03** | No Role-Based Access Control (RBAC) | **Critical** | **Where found:** `app.py` (original) — any authenticated user could invoke `view_audit_log()`, `view_alerts()`, and `view_transactions()` for all accounts without role check. **Evidence:** Standard user (`role='user'`) could read every customer's transaction history and all security alerts. | Implement role checks at every sensitive function entry point; log unauthorized access attempts to audit trail. | **Fixed** | `app.py:view_audit_log` [L270], `app.py:view_alerts` [L287], `app.py:view_transactions` [L241] — RBAC enforced, violations logged | `tests/test_security_fixes.py::TestRBAC` (5 tests) |
| **FIND-04** | No Transaction Persistence / ACID Compliance | **High** | **Where found:** `app.py` (original) — balances stored in Python `dict`; all data lost on process exit. No transaction atomicity. **Evidence:** Deposit and withdraw operations were not atomic; a crash mid-transfer could leave one account debited without the other credited. | Migrate to a persistent ACID-compliant database; wrap every multi-table operation in explicit `BEGIN`/`COMMIT`/`ROLLBACK`. | **Fixed** | `db.py` — SQLite `isolation_level=None`, explicit `BEGIN/COMMIT/ROLLBACK` in `deposit()` [L495], `withdraw()` [L525], `transfer()` [L558] | `tests/test_database.py::TestACIDDeposit`, `TestACIDWithdraw`, `TestACIDTransfer` (6 tests) |
| **FIND-05** | Application Crash on Non-Numeric Input | **High** | **Where found:** `app.py` (original) — `float(input("amount: "))` raised unhandled `ValueError` on any non-numeric input (letters, symbols, empty string), crashing the process. **Evidence:** Entering `"abc"` as deposit amount immediately terminated the application with a traceback. | Wrap all numeric input conversions in `try/except ValueError`; return `None` and display user-friendly error without crashing. | **Fixed** | `security.safe_float_input()` [security.py:L66], `security.safe_int_input()` [security.py:L82] | `tests/test_security_fixes.py::TestSafeInputWrappers` (7 tests) |
| **FIND-06** | No Brute-Force Protection / Account Lockout | **High** | **Where found:** `app.py` (original) — no counter for failed login attempts; an attacker could make unlimited password guesses. **Evidence:** `while True` login loop with no rate limiting or lockout mechanism. | Persist a `failed_attempts` counter per account; lock account after N consecutive failures; generate high-severity security alert. | **Fixed** | `db.increment_failed_attempts()` [db.py:L215], `app.py:login` [L71-L82] — locks at `MAX_FAILED_LOGINS=3`, raises `Brute Force` alert | `tests/test_security_fixes.py::TestBruteForceLockout` (in TestRBAC), `tests/test_cyber_controls.py::TestAdminAccountUnlock::test_account_locks_after_max_failed_attempts` |
| **FIND-07** | Non-Tamper-Evident Audit Log | **High** | **Where found:** `app.py` / `db.py` (original) — audit events stored as plain rows with no integrity protection; any user with DB access could `UPDATE` or `DELETE` rows without detection. **Evidence:** Direct `UPDATE Audit_Log SET action='...'` left no trace and was undetectable. | Implement cryptographic hash chaining: each log entry includes `previous_hash` and `entry_hash = SHA256(prev \|\| user \|\| action \|\| time)`; provide a verification function. | **Fixed** | `db.log_action()` [db.py:L280], `db.compute_audit_hash()` [db.py:L271], `db.verify_audit_log_integrity()` [db.py:L315] | `tests/test_cyber_controls.py::TestTamperEvidentAuditLog` (4 tests — includes tamper detection on modified action and broken hash link) |
| **FIND-08** | Unknown-Email Login Attempts Not Logged | **High** | **Where found:** `app.py` (original) — when `get_user_by_email()` returned `None`, the application silently returned `None, None` with no audit record. **Evidence:** An attacker probing valid email addresses via login attempts left zero trace in the audit log. | Log all login attempts, including those with unknown emails (`user_id=NULL`), to the audit trail for SIEM correlation. | **Fixed** | `app.py:login` [L55] — `db.log_action(None, f"Failed login -- unknown email attempted: {email}")` | `tests/test_database.py::TestAuditLog::test_log_action_null_user_id_allowed` |
| **FIND-09** | No Account Unlock Path (Permanent Lockout DoS) | **Medium** | **Where found:** `app.py` (original) — once `is_locked=1` was set after 3 failed attempts, there was no administrator function to reset it. **Evidence:** A single brute-force attempt permanently denied legitimate account access with no recovery path, constituting a self-inflicted denial-of-service. | Implement an admin-only unlock function that resets `is_locked` and `failed_attempts` and logs the administrative action. | **Fixed** | `db.unlock_user()` [db.py:L357], `app.py:manage_locked_users` [L362] | `tests/test_cyber_controls.py::TestAdminAccountUnlock::test_admin_unlock_clears_lockout_and_resets_counter` |
| **FIND-10** | Single-Point Authority on High-Value Transfers | **Medium** | **Where found:** `app.py` (original) — any authenticated user could immediately execute transfers of unlimited amounts with no secondary approval. **Evidence:** A single compromised account could drain all customer balances in one operation. | Implement Maker-Checker dual control: transfers above a configurable threshold (`LARGE_TXN_THRESHOLD`) are held in `pending` state without debiting funds; a separate administrator/checker must approve with Segregation of Duties enforcement (maker ≠ checker). | **Fixed** | `db.create_pending_transfer()` [db.py:L629], `db.approve_pending_transfer()` [db.py:L668] — SoD check at L698; `app.py:do_transfer` [L198-L216] | `tests/test_cyber_controls.py::TestMakerCheckerWorkflow` (5 tests — pending status, SoD block, atomic approval, rejection, insufficient funds at approval) |

---

## 3. Verification Instructions

To reproduce the legacy findings and the current SQLite test evidence on a clean clone:

```bash
git clone https://github.com/ayushkulhari47/secure-banking-system-dbms-cyber.git
cd secure-banking-system-dbms-cyber
python -m venv venv && venv\Scripts\activate   # Windows
pip install -r requirements.txt
python -m pytest tests/ -v
# Current working-copy result: 123 passed, 0 failed on SQLite

This report does not prove the MySQL least-privilege grants or a production
deployment. Run `python verify_least_privilege.py` only after provisioning a
real MySQL instance with the runtime account.
```

---

## 4. ISO 27001:2022 Annex A Control Coverage

Each finding maps to one or more ISO/IEC 27001:2022 Annex A controls — see [`docs/control_mapping.md`](control_mapping.md) for the full traceability matrix.

| Finding | Primary ISO 27001:2022 Control |
|---|---|
| FIND-01 (Negative amounts) | A.8.26 — Application Security Requirements |
| FIND-02 (Weak hashing) | A.8.24 — Use of Cryptography |
| FIND-03 (No RBAC) | A.5.15 — Access Control, A.8.2 — Privileged Access Rights |
| FIND-04 (No ACID) | A.8.6 — Capacity Management; COBIT DSS01.03 |
| FIND-05 (Input crash) | A.8.28 — Secure Coding |
| FIND-06 (No lockout) | A.8.5 — Secure Authentication |
| FIND-07 (Mutable audit log) | A.8.15 — Logging, A.8.16 — Monitoring |
| FIND-08 (Unknown-email logging) | A.8.15 — Logging |
| FIND-09 (No unlock path) | A.5.18 — Access Rights (Account Unlock) |
| FIND-10 (Single-point authority) | A.5.3 — Segregation of Duties |

> [!NOTE]
> **ISO 27001:2022 Reference Note:** The control identifiers above reference the **ISO/IEC 27001:2022** standard (93 controls across 4 clauses). All controls are aligned with the 2022 structure.
