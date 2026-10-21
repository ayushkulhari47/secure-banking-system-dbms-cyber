# Privacy Impact Assessment (PIA) & Data Protection Review

**System Name:** Secure Banking System  
**Framework Alignment:** India's Digital Personal Data Protection (DPDP) Act 2023 & ISO/IEC 27701:2019 (Privacy Information Management)  
**Evaluation Date:** October 2026  
**Auditor Classification:** Cyber Risk & Regulatory Compliance Review  

---

## 1. Executive Summary & Legal Framework

Under India's **Digital Personal Data Protection Act (DPDP Act 2023)**, the banking entity acts as a **Data Fiduciary** responsible for processing personal data belonging to account holders (**Data Principals**). Section 8(5) of the DPDP Act mandates that a Data Fiduciary must protect personal data in its possession or under its control by taking reasonable security safeguards to prevent personal data breaches.

This Privacy Impact Assessment evaluates how personal data is collected, stored, processed, and safeguarded within the **Secure Banking System**.

---

## 2. Personal Data Inventory & Data Flow Mapping

The application processes both basic personal identifiers and sensitive financial transaction records:

| Data Element | DPDP Classification | Purpose of Collection | Processing Lawful Basis (DPDP Act Sec. 4/6) | Storage Location (Table & Column) | Access Level |
|---|---|---|---|---|---|
| **Full Name** | Personal Data | Customer identification & account ownership | Consent / Contractual Performance | `Users.name` ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L47)) | Authenticated User (Own data), Admin |
| **Email Address** | Personal Data (Identifier) | Unique user identifier, communication, authentication | Consent / Contractual Performance | `Users.email` ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L48)) | Authenticated User (Own data), Admin |
| **Password Hash** | Authentication Credential | Identity verification & access authorization | Legitimate Use / Security Requirement | `Users.password_hash` ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L49)) | System Internal Only (Never displayed in CLI) |
| **Account Balance** | Financial Personal Data | Fund tracking and ledger management | Contractual Performance | `Accounts.balance` ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L60)) | Authenticated User (Own account), Admin |
| **Transaction History** | Financial Personal Data | Audit trail of deposits, withdrawals, and transfers | Contractual & Statutory Compliance | `Transactions.*` ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L65-L75)) | Authenticated User (Own account), Admin |
| **Audit Logs** | Technical / Behavioral Data | Security monitoring, incident investigation, non-repudiation | Legal Obligation / Security Safeguard | `Audit_Log.*` ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L77-L84)) | Admin Only (Scoped RBAC) |

---

## 3. Principles of the DPDP Act 2023 Implemented in Code

### 3.1 Purpose Limitation (DPDP Act Sec. 4)
- Personal data collected (name, email, password) is strictly used for authenticating users and executing requested banking transactions.
- No secondary or undocumented processing (such as profiling, marketing, or external sharing) occurs.

### 3.2 Data Minimisation (DPDP Act Sec. 6)
- The database schema only collects mandatory fields required to operate a core banking ledger.
- Cleartext passwords are never retained. Passwords are transformed into salted, non-reversible hashes using `bcrypt` ([db.py:hash_password](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L172)).
- Authentication failures on unknown emails log `user_id = NULL` rather than storing unvalidated external metadata ([app.py:login](file:///c:/Users/itsme/Downloads/secure-banking-system/app.py#L52)).

### 3.3 Storage Limitation & Data Retention (DPDP Act Sec. 8(7))
- Personal data must not be retained longer than necessary to satisfy the purpose for which it was processed.
- Banking regulations (RBI Guidelines / PMLA) require transaction records to be preserved for 5 to 10 years for statutory audit trails.
- Account termination routines clear active balance records and mark accounts closed while preserving immutable hash-chained audit trails.

### 3.4 Reasonable Security Safeguards (DPDP Act Sec. 8(5))
The following technical controls prevent personal data exposure and unauthorized access:
1. **Cryptographic Protection of Credentials:** Passwords hashed with bcrypt (work factor 12) + 16-byte random salt ([db.py:hash_password](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L172)).
2. **Access Control / Need-to-Know Enforcement:** Role-Based Access Control ([app.py:view_transactions](file:///c:/Users/itsme/Downloads/secure-banking-system/app.py#L231)) prevents customers from viewing any other customer's account balance, transactions, or alerts.
3. **Session Inactivity Protection:** Auto-termination after 300 seconds ([security.py:Session](file:///c:/Users/itsme/Downloads/secure-banking-system/security.py#L141)) prevents shoulder-surfing and unauthorized physical terminal takeover.
4. **Log Tamper-Evident Integrity:** Audit trails utilize cryptographic SHA-256 hash chaining ([db.py:verify_audit_log_integrity](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L313)) to prevent covert alteration or deletion of customer records.

---

## 4. Rights of the Data Principal (DPDP Act Chapter III)

| Data Principal Right | Statutory Provision | System Capability & Technical Implementation |
|---|---|---|
| **Right to Access Information** | DPDP Act Sec. 11 | Users can view their personal account details, current balance, and historical ledger at any time via `view_balance()` and `view_transactions()` in [app.py](file:///c:/Users/itsme/Downloads/secure-banking-system/app.py#L219). |
| **Right to Correction & Updating** | DPDP Act Sec. 12 | Administrators can update customer profile information and unlock falsely locked accounts via `unlock_user()` in [db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L344). |
| **Right to Grievance Redressal** | DPDP Act Sec. 13 | Security alerts raised by the system are tracked with unique IDs (`Alerts.alert_id`) and reviewed/resolved by administrators via `resolve_alert()` in [db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L399). |

---

## 5. Privacy Risk Assessment & Remediation Summary

| Privacy Threat | Pre-Mitigation Risk | Implemented Safeguards in Code | Post-Mitigation Risk |
|---|---|---|---|
| **Cleartext Password Leakage** | Critical | Upgraded SHA-256 to salted bcrypt with adaptive work factor 12 ([db.py](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L172)). | Low |
| **Unauthorized Exposure of Financial Ledger** | High | Enforced strict account-scoped filtering on transaction history queries in [db.py:get_transactions_for_account](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L605). | Low |
| **Unattended Terminal Data Spillage** | High | Implemented monotonic session timer terminating idle user sessions after 5 minutes ([security.py](file:///c:/Users/itsme/Downloads/secure-banking-system/security.py#L141)). | Low |
| **Repudiation of Malicious Alterations** | High | Chained audit logs with SHA-256 hashes ([db.py:log_action](file:///c:/Users/itsme/Downloads/secure-banking-system/db.py#L280)), enabling mathematical proof of audit trail completeness. | Low |
