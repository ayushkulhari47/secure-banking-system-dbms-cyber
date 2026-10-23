# Secure Banking System: 5-Slide Presentation Deck & Interview Q&A

**Presenter:** Ayush Kulhari  
**Target Role:** Cyber Risk & Compliance / IT Audit Analyst (Big-4 Advisory)  

---

## 5-Slide Executive Presentation Deck

### Slide 1: Problem Statement & Objectives
- **Title:** Engineering Resilience: Modernizing a College Banking Prototype into an Auditable Financial Core
- **Bullets:**
  - *Academic Gap:* Initial codebase stored state in in-memory Python structures with unsalted SHA-256 hashes, absent RBAC, and zero persistence.
  - *Core Business Risks:* Critical financial exploits (negative transfer theft), unhandled input crashes, session hijacking, and untrusted audit trails.
  - *Target Objective:* Re-architect the application into an ISO 27001:2022 and DPDP Act 2023 aligned banking ledger backed by automated control testing.
- **Speaker Notes:**  
  *"Good morning. Today I am presenting a comprehensive cybersecurity and IT audit modernization of a banking core ledger. My objective was to take a prototypical college application and apply enterprise-grade internal controls—transforming it from a vulnerable CLI into an auditable, ACID-compliant banking system."*

---

### Slide 2: Technical Architecture & Defense-in-Depth
- **Title:** Layered Architecture: Transactional Integrity & Cryptographic Chains
- **Bullets:**
  - *ACID Persistence Layer:* Embedded SQLite with enforced foreign keys (`PRAGMA foreign_keys = ON`) and explicit transaction isolation (`BEGIN`, `COMMIT`, `ROLLBACK`).
  - *Cryptographic Storage:* Adaptive `bcrypt` (work factor 12) with per-user 16-byte random salts and timing-safe password verification.
  - *Tamper-Evident Ledger:* SHA-256 cryptographic hash chaining (`previous_hash` & `entry_hash`) enforcing non-repudiation on audit records.
  - *Dual Control Engine:* Maker-Checker separation for transactions $> \text{Rs } 50,000$, enforcing Segregation of Duties (SoD).
- **Speaker Notes:**  
  *"Our architecture is designed around defense-in-depth. We separated pure security validations in `security.py` from database persistence in `db.py`. To eliminate TOCTOU race conditions and maintain ledger consistency, balance reads and updates occur inside atomic transactions."*

---

### Slide 3: Vulnerabilities Found and Fixed
- **Title:** Threat Remediation: Closing the Attack Surface
- **Bullets:**
  - *Negative Value Theft:* Eliminated negative amount transfers via multi-layer bounds checking (`0.01 <= amount <= 1,000,000.00`) and DB `CHECK` constraints.
  - *Brute-Force & Credential Stuffing:* Enforced persistent lockout after 3 failed attempts with automatic high-severity security alert generation.
  - *Horizontal Privilege Escalation (BOLA):* Applied RBAC so account holders only access their personal ledger; audit logs and alerts are admin-restricted.
  - *Session Inactivity Risk:* Implemented monotonic session timers terminating unattended terminals after 300 seconds.
- **Speaker Notes:**  
  *"During our baseline audit, we identified 10 critical control deficiencies. The most severe was a negative transfer exploit where transferring -5,000 stole money from the recipient. We remediated this through defense-in-depth: validating inputs at the application boundary and enforcing constraints at the database layer."*

---

### Slide 4: Governance & Regulatory Compliance Mapping
- **Title:** Compliance as Code: ISO 27001:2022 & India's DPDP Act 2023
- **Bullets:**
  - *ISO 27001 Annex A Mapping:* Traceability matrix covering 16 controls across Organizational (A.5) and Technological (A.8) themes.
  - *DPDP Act 2023 Alignment:* Full Privacy Impact Assessment documenting lawful processing grounds (Sec. 4), data minimisation, and data principal rights.
  - *Automated Control Evidence:* 123 hermetic pytest tests serving as educational, repeatable evidence for the SQLite path.
  - *Operational Resilience:* Disaster recovery protocol with defined RTO ($\le 15\text{m}$) and RPO ($\le 1\text{h}$) supported by zero-downtime hot backups.
- **Speaker Notes:**  
  *"In IT audit and cyber risk consulting, code is only as good as its governance trail. We created formal compliance artifacts: a Risk & Control Matrix mapped to ISO 27001:2022, a DPDP Act Privacy Impact Assessment, and an IT Risk Register. Every control is directly backed by an automated test case."*

---

### Slide 5: Lessons Learned & Engineering Takeaways
- **Title:** Audit Insights: Practical Lessons in Controls Implementation
- **Bullets:**
  - *Defense-in-Depth is Essential:* Application-layer checks must always be backed by immutable database constraints.
  - *Segregation of Duties Requires Enforced Code Logic:* Maker-Checker dual control cannot be a procedural policy alone; software must strictly reject self-approval.
  - *Audit Trails Must Be Tamper-Evident:* Regular database tables can be altered by rogue DBAs; cryptographic hash chaining provides mathematical proof of integrity.
  - *Centralized Configuration:* Consolidating tuneable thresholds into `config.py` simplifies audit walkthroughs and change management reviews.
- **Speaker Notes:**  
  *"The biggest takeaway from this project is that security controls must be built into the system architecture rather than bolted on. In an interview setting, this project demonstrates my ability to identify operational vulnerabilities, design preventive and detective controls, and communicate risk to enterprise stakeholders."*

---

## 8 Big-4 IT Audit & Cyber Risk Interview Questions & Model Answers

### Q1: Why did you migrate from SHA-256 to bcrypt for credential storage?
> **Answer:**  
> *"SHA-256 is a general-purpose, high-speed cryptographic hash function designed for throughput, not password storage. On modern GPUs, attackers can compute billions of SHA-256 hashes per second, making unsalted hashes trivial to crack using precomputed rainbow tables or dictionary attacks.  
> We migrated to `bcrypt` with work factor 12. Bcrypt has two vital security properties: first, it automatically generates and embeds a cryptographically secure 16-byte random salt per password, ensuring identical passwords produce completely different hashes. Second, it is an adaptive, computationally expensive algorithm (~250ms per evaluation), which introduces severe cost penalties that render offline brute-force attacks infeasible."*

---

### Q2: What is Maker-Checker dual control, and how did you enforce Segregation of Duties (SoD)?
> **Answer:**  
> *"Maker-Checker—also known as the four-eyes principle or dual authorization—is a preventive internal control aligned with ISO 27001:2022 A.5.3. For high-risk operations like transactions exceeding Rs 50,000, no single individual should have end-to-end authority.  
> In our implementation, when a user initiates a large transfer, the transaction is committed with status `pending`, leaving sender and receiver balances unchanged. In `db.py:approve_pending_transfer()`, we enforce Segregation of Duties programmatically: the system inspects the account owner of `from_account` and compares it to the approving administrator. If the maker attempts to self-approve, the operation is blocked with an SoD violation, and a security alert is logged."*

---

### Q3: How does your tamper-evident audit log work, and what happens if an attacker modifies a record in SQLite?
> **Answer:**  
> *"Our audit log uses cryptographic SHA-256 hash chaining, similar to a blockchain ledger. Each row contains `previous_hash` and `entry_hash`. The entry hash is calculated as `SHA-256(previous_hash || user_id || action || log_time)`.  
> If an intruder or rogue database administrator executes an unauthorized SQL command—such as altering a transfer amount or deleting an audit entry—the hash chain breaks. When our integrity verification function `verify_audit_log_integrity()` traverses the table, it recalculates expected hashes from genesis. When a mismatch occurs, it returns `False`, pinpoints the exact corrupted `log_id`, and triggers a high-severity security incident alert."*

---

### Q4: How do you prevent TOCTOU (Time-of-Check to Time-of-Use) race conditions during financial withdrawals?
> **Answer:**  
> *"A TOCTOU race condition occurs when an application checks an account balance in one operation, and then debits it in a separate operation. In a concurrent environment, two simultaneous requests could pass the balance check and double-spend funds.  
> We eliminate this by managing transactions explicitly (`isolation_level=None`). In `db.py:withdraw()`, the `SELECT balance`, conditional validation, and `UPDATE balance` all occur inside a single atomic `BEGIN ... COMMIT` block. Furthermore, our database schema enforces a hard constraint `CHECK(balance >= 0)`. Even under thread race conditions, SQLite serializes write transactions and the database engine would reject any update that drops balance below zero."*

---

### Q5: What is the difference between Preventive, Detective, and Corrective controls, and how are they represented in your system?
> **Answer:**  
> *"In IT audit:
> - **Preventive Controls** deter an incident from occurring. Examples in our code include parameterized queries stopping SQLi, `validate_amount()` blocking negative transfers, and Maker-Checker dual control blocking unauthorized large transfers.
> - **Detective Controls** identify and alert on incidents that have occurred or are underway. Examples include our brute-force failed login counter, high-severity automated alerts, and cryptographic audit log hash verification.
> - **Corrective Controls** remediate the impact and restore normal operations after an incident. Examples include `unlock_user()` allowing admins to restore legitimate accounts, `resolve_alert()` for incident tracking, and `backup_restore.py` for disaster recovery."*

---

### Q6: How does your system align with India's Digital Personal Data Protection (DPDP) Act 2023?
> **Answer:**  
> *"Under the DPDP Act 2023, the banking entity is a Data Fiduciary. We implemented several core statutory requirements:
> 1. **Data Minimisation (Section 6):** We only collect necessary fields (name, email, password hash) and never store cleartext credentials.
> 2. **Reasonable Security Safeguards (Section 8(5)):** We implemented bcrypt password hashing, parameterized SQL queries, and session timeouts to prevent personal data breaches.
> 3. **Data Principal Rights (Sections 11–13):** Users have right to access their transaction history via scoped queries, and right to grievance redressal via tracked security alerts."*

---

### Q7: If you were evaluating this system in a SOC 1 or SOC 2 audit, what would be your testing approach?
> **Answer:**  
> *"In a SOC 1 (SSAE 18) engagement focused on Internal Controls over Financial Reporting (ICFR) or a SOC 2 review under Trust Services Criteria:
> 1. **ITGC Walkthroughs:** I would evaluate Logical Access (user provisioning, password parameters in `config.py`, lockout controls), Change Management (how thresholds are approved and modified), and Computer Operations (backup job logs and integrity checks).
> 2. **Test of Design (TOD):** Review whether the control design addresses the risk (e.g., does the SoD check actually prevent the maker from approving their own transfer?).
> 3. **Test of Operating Effectiveness (TOE):** Inspect audit logs and run automated control tests (such as the current 123 pytest assertions) to verify behavior in the tested SQLite environment; do not treat this prototype as a certification."*

---

### Q8: What are the primary architectural limitations of this system, and how would you address them in an enterprise bank?
> **Answer:**  
> *"To be transparent from an audit perspective, this prototype has four enterprise gaps:
> 1. **Interface:** It is a CLI application rather than a microservice; an enterprise bank requires REST/gRPC APIs over TLS 1.3 with OAuth 2.0 / OIDC tokens.
> 2. **MFA:** Authentication relies on passwords; enterprise banking requires out-of-band Multi-Factor Authentication (e.g., FIDO2 WebAuthn or TOTP).
> 3. **Database Scalability:** SQLite is single-host; enterprise systems require clustered PostgreSQL or Oracle DB with automated multi-region replication.
> 4. **Log Streaming:** Audit logs reside in SQLite; in production, logs should be signed and streamed via syslog/TLS to a centralized SIEM (Splunk/QRadar) with WORM immutability."*
