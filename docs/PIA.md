# Privacy & Data Protection Review (`PIA.md`)

**System Name:** Secure Banking System  
**Scope:** Educational review of personal data handling in [`bank/`](../bank/) and [`main.py`](../main.py) (not a legal assessment or regulatory certification).

---

## 1. Personal Data Inventory & Access Scope

| Data Element | Purpose | Table & Column | Access Level |
|---|---|---|---|
| **Full Name** | Customer/admin display name | `Users.name` ([`bank/db.py`](../bank/db.py)) | Account owner & Admins |
| **Email Address** | Unique authentication identifier | `Users.email` ([`bank/db.py`](../bank/db.py)) | Account owner & Admins |
| **Password Hash** | `bcrypt` authentication verification | `Users.password_hash` ([`bank/auth.py`](../bank/auth.py)) | Internal verification only (never displayed) |
| **Account Balance** | `DECIMAL(12,2)` ledger balance | `Accounts.balance` ([`bank/db.py`](../bank/db.py)) | Account owner & Admins |
| **Transactions** | Deposit, withdrawal, transfer history | `Transactions.*` ([`bank/transactions.py`](../bank/transactions.py)) | Account owner & Admins |
| **Audit Logs** | Security and balance-change trail | `Audit_Log.*` ([`bank/audit.py`](../bank/audit.py)) | Admins only |
| **Security Alerts** | Intrusion & large-txn incident triage | `Alerts.*` ([`bank/alerts.py`](../bank/alerts.py)) | Admins only |

---

## 2. Safeguards Implemented in Code

1. **No Cleartext Passwords:** Credentials are hashed with salted `bcrypt` (`BCRYPT_ROUNDS = 12` in [`bank/config.py`](../bank/config.py)), and password policies are enforced in [`bank/security.py`](../bank/security.py) for password changes and [`scripts/seed_demo.py`](../scripts/seed_demo.py).
2. **Minimal Unknown-Email Logging:** Failed login attempts for unknown emails record `user_id = NULL` in `Audit_Log` inside [`bank/auth.py`](../bank/auth.py), and login failure output is always `"Invalid email or password."`.
3. **Data-Layer Access Controls:** [`bank/transactions.py`](../bank/transactions.py) restricts account reads/mutations (`get_account_by_id`, `get_transactions_for_account`, `deposit`, `withdraw`, `transfer`, `create_pending_transfer`), while [`bank/audit.py`](../bank/audit.py), [`bank/alerts.py`](../bank/alerts.py), and [`bank/auth.py`](../bank/auth.py) enforce admin-only access for audit logs, alerts, locked-user lists, and unlocks.
4. **Session Timeout:** [`bank/security.py`](../bank/security.py) (`Session`) expires idle CLI sessions after 300 seconds.
5. **Audit Integrity:** Hash chaining and append-only triggers in [`bank/db.py`](../bank/db.py) protect `Audit_Log` entries against silent alteration.
