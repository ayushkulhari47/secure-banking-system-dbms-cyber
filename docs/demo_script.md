# 2-Minute Live Demonstration Script

**System:** Secure Banking System  
**Target Duration:** ~120 Seconds  
**Objective:** Walk through authentication, input validation, brute-force lockout, RBAC, Maker-Checker dual control, admin unlock, and audit hash-chain verification using the CLI.

---

## Pre-Demo Setup

Ensure your virtual environment is active, `.env` is configured from `.env.example`, and demo users have been seeded explicitly:

```bash
python -m pytest tests/ -q
python scripts/seed_demo.py
python main.py
```

*(Supply demo passwords via `DEMO_ADMIN_PASSWORD`, `DEMO_RAHUL_PASSWORD`, and `DEMO_PRIYA_PASSWORD` in `.env` or enter them interactively when `scripts/seed_demo.py` prompts. All passwords must meet `password_meets_policy()`.)*

---

## Step 1: Normal Authentication & Balance Check (~20s)
*Demonstrates `bcrypt` login verification and standard user menu scoping.*

- Run `python main.py` and enter Rahul's email (`rahul@bank.com`) and the seeded password.
- Expected menu:
  ```text
  Welcome Rahul Sharma!  Role: user

  --- Banking Menu (USER) --- [session expires in 5m 0s]
  1. View Balance
  2. Deposit
  3. Withdraw
  4. Transfer
  5. Transaction History
  6. Change Password
  7. Audit Log        (admin only)
  8. Security Alerts  (admin only)
  9. Logout
  ```
- Choose `1` -> displays `Account ID: 2  |  Balance: Rs25000.00`.

---

## Step 2: Invalid / Negative Transfer Blocked (~15s)
*Demonstrates multi-layer `Decimal` bounds validation and SQL `CHECK` constraints.*

- Choose `4` (Transfer), destination account `1`, amount `-5000`:
  ```text
    [!] Invalid amount: Amount must be greater than Rs0.00 (got Rs-5000.00).
  ```
- Choose `9` to Logout.

---

## Step 3: Brute-Force Lockout & Generic Errors (~20s)
*Demonstrates constant-work login checks, generic errors without enumeration, and 3-attempt lockout.*

- Run `python main.py` and attempt login 3 times for `priya@bank.com` with an incorrect password:
  - Attempt 1 -> `Invalid email or password.`
  - Attempt 2 -> `Invalid email or password.`
  - Attempt 3 -> `Invalid email or password.` (account locks at `is_locked = 1` and raises one high-severity `"Brute Force"` alert).
- Attempt 4 even with Priya's **correct** password still prints:
  ```text
  Invalid email or password.
  ```
  (Neither account existence nor lock status is revealed.)

---

## Step 4: RBAC Denial for Standard User (~15s)
*Demonstrates CLI and data-layer RBAC separation.*

- Log in as `rahul@bank.com`.
- Choose `7` (Audit Log - admin only) -> `  [!] Access denied -- admin only.`
- Choose `8` (Security Alerts - admin only) -> `  [!] Access denied -- admin only.`

---

## Step 5: High-Value Transfer Queued for Maker-Checker (~20s)
*Demonstrates transfers > `Rs 50,000.00` entering `pending` status without debiting funds.*

- Choose `4` (Transfer), destination `1`, amount `60000`:
  ```text
    [!] Large Transaction Notice (Maker-Checker Control):
        Transfer of Rs60,000.00 exceeds policy limit of Rs50,000.00.
        Transaction #1 has been submitted with status 'pending'.
        Dual-control policy requires an administrator/checker to approve before execution.
  ```
- Choose `1` (View Balance) -> `Account ID: 2  |  Balance: Rs25000.00` (unchanged until approved).
- Choose `9` to Logout.

---

## Step 6: Admin Consoles — Unlock & Maker-Checker (~20s)
*Demonstrates admin remediation and fail-safe Maker-Checker checks.*

- Run `python main.py` and log in as Admin (`ayush@bank.com`).
- Choose `10` (**Unlock User Accounts**) and enter Priya's user ID (`3`):
  `[+] User #3 has been unlocked successfully.`
- Choose `9` (**Maker-Checker Approvals**), select Txn `#1`, and enter `A` (Approve):
  `[!] Approval failed: Insufficient balance at time of approval. Transfer rejected.`
  *(Because Rahul only had Rs 25,000.00 for a Rs 60,000.00 transfer, approval fails safely and marks the transfer `rejected`.)*

---

## Step 7: Audit Hash-Chain Verification (~10s)
*Demonstrates cryptographic integrity checking across `Audit_Log`.*

- From the Admin menu, choose `11` (**Verify Audit Log Integrity**):
  ```text
  --- Audit Log Cryptographic Integrity Verification ---
    [+] INTEGRITY PASS: All cryptographic SHA-256 hash chains match.
        No records have been modified, deleted, or inserted out of order.
  ```
- Choose `12` to Logout.
