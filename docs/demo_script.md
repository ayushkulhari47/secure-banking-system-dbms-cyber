# 2-Minute Live Interview Demonstration Script

**System:** Secure Banking System (DBMS + Cybersecurity IT Audit Prototype)  
**Presenter:** Ayush Kulhari  
**Target Duration:** 120 Seconds  
**Objective:** Walk the interviewer through the core security controls, failure modes, Maker-Checker authorization, and tamper-evident audit log verification in real time.

---

## Pre-Demo Setup (Terminal)
Ensure dependencies are installed and fresh database seeded:
```bash
python -m pytest tests/ -q
python app.py
```

---

## Step 1: Normal Authentication & Balance Verification (20s)
*Goal: Demonstrate successful authentication, bcrypt timing-safe check, and user session initialization.*

- **Action:**
  ```text
  Email: rahul@bank.com
  Password: rahul123
  ```
- **Expected Console Output:**
  ```text
  Welcome Rahul Sharma!  Role: user
  --- Banking Menu (USER) --- [session expires in 5m 0s]
  1. View Balance
  ...
  ```
- **Action:** Enter `1` to view balance.
- **Expected Output:**
  ```text
  Account ID: 2  |  Balance: Rs25000.00
  ```
- **Action:** Enter `8` to Logout.
  ```text
  Goodbye!
  ```

---

## Step 2: Negative Amount Transfer Exploitation Blocked (20s)
*Goal: Prove that negative transfer / money-theft exploit is blocked at application and DB layers.*

- **Action:** Run `python app.py` and log in as `rahul@bank.com` / `rahul123`.
- **Action:** Enter `4` (Transfer).
  ```text
  Enter destination account ID: 1
  Enter transfer amount (Rs): -5000
  ```
- **Expected Console Output:**
  ```text
    [!] Invalid amount: Amount must be greater than Rs0.00 (got Rs-5000.00).
  ```
- **Interviewer Talking Point:**  
  *"In the original codebase, transferring -5,000 would subtract -5,000 from the sender—effectively stealing 5,000 from the receiver. We hardened this with multi-layer validation in `validate_amount()` and SQLite `CHECK(amount > 0)`."*
- **Action:** Enter `8` to Logout.

---

## Step 3: Brute-Force Detection & Automated Account Lockout (20s)
*Goal: Show persistent lockout after 3 failed attempts and high-severity alert creation.*

- **Action:** Run `python app.py`.
- **Attempt 1:**
  ```text
  Email: priya@bank.com
  Password: wrongpassword
  ```
  *Output:* `Wrong password! Attempt 1/3`
- **Attempt 2:**
  ```text
  Email: priya@bank.com
  Password: wrongpassword
  ```
  *Output:* `Wrong password! Attempt 2/3`
- **Attempt 3:**
  ```text
  Email: priya@bank.com
  Password: wrongpassword
  ```
  *Output:*
  ```text
  Too many failed attempts -- your account is now locked.
  ```
- **Attempt 4 (Verification of Lockout):**
  ```text
  Email: priya@bank.com
  Password: priya123  (correct password)
  ```
  *Output:*
  ```text
  Account is locked due to multiple failed attempts. Contact admin.
  ```

---

## Step 4: Role-Based Access Control (RBAC) Enforcement (15s)
*Goal: Prove standard users cannot access audit logs or security alerts.*

- **Action:** Log in as `rahul@bank.com` / `rahul123`.
- **Action:** Enter `6` (Audit Log - admin only).
- **Expected Console Output:**
  ```text
    [!] Access denied -- admin only.
  ```
- **Action:** Enter `7` (Security Alerts - admin only).
- **Expected Console Output:**
  ```text
    [!] Access denied -- admin only.
  ```
- **Action:** Enter `8` to Logout.

---

## Step 5: Large Transaction Quarantined for Maker-Checker Dual Control (20s)
*Goal: Show high-value transaction held in pending status without debiting sender balance.*

- **Action:** Run `python app.py` and log in as `rahul@bank.com` / `rahul123`.
- **Action:** Enter `4` (Transfer).
  ```text
  Enter destination account ID: 1
  Enter transfer amount (Rs): 60000
  ```
- **Expected Console Output:**
  ```text
    [!] Large Transaction Notice (Maker-Checker Control):
        Transfer of Rs60,000.00 exceeds policy limit of Rs50,000.00.
        Transaction #1 has been submitted with status 'pending'.
        Dual-control policy requires an administrator/checker to approve before execution.
  ```
- **Action:** Enter `1` (View Balance).
  *Output:* `Balance: Rs25000.00` *(Funds remain intact; not deducted until approval).*
- **Action:** Enter `8` to Logout.

---

## Step 6: Admin Dual Control Approval & Account Unlock Remediation (15s)
*Goal: Demonstrate administrative approval with Segregation of Duties and unlocking locked users.*

- **Action:** Run `python app.py` and log in as Admin:
  ```text
  Email: ayush@bank.com
  Password: ayush123
  ```
- **Action:** Enter `9` (Unlock User Accounts).
  *Console lists:* `User ID:3 | Name:Priya Singh | Email:priya@bank.com | Failed Attempts:3`
  *Input:* Enter `3`.
  *Output:* `[+] User #3 has been unlocked successfully.`
- **Action:** Enter `8` (Maker-Checker Approvals).
  *Console displays pending transfer #1 (Rahul Sharma -> Ayush Kulhari, Rs60,000.00).*
  *Input:* Enter `1` for Txn ID, then `A` for Approve.
  *Output:* `[!] Approval failed: Insufficient balance at time of approval. Transfer rejected.`  
  *(Demonstrates fail-safe verification: Rahul only had Rs 25,000, so the system prevented overdraft even at approval time!).*

---

## Step 7: Cryptographic Tamper-Evident Audit Log Verification (10s)
*Goal: Prove mathematical non-repudiation using SHA-256 hash chaining.*

- **Action:** From the Admin menu, enter `10` (Verify Audit Log Integrity).
- **Expected Console Output:**
  ```text
  --- Audit Log Cryptographic Integrity Verification ---
    [+] INTEGRITY PASS: All cryptographic SHA-256 hash chains match.
        No records have been modified, deleted, or inserted out of order.
  ```
- **Interviewer Talking Point:**  
  *"If an insider were to run an unauthorized SQL UPDATE on the `Audit_Log` table, the SHA-256 pointer chain breaks instantly. When `verify_audit_log_integrity()` runs, it pinpoints the exact corrupted row ID and raises a high-severity alert."*
- **Action:** Enter `11` to Logout.
