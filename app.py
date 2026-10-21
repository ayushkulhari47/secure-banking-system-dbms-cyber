"""
app.py  Secure Banking System  CLI front-end (Phase 2 hardened).

Phase 2 changes vs Phase 1:
  - safe_float_input / safe_int_input replace bare float()/int() calls
    so bad input (letters, empty string) never crashes the application.
  - validate_amount() rejects zero, negative, NaN, and infinite amounts.
  - Self-transfer is blocked before calling db.transfer().
  - Full RBAC: users see only their own transactions; audit log and
    alerts are admin-only; unknown-email logins are logged.
  - Session inactivity timeout (300 s default): menu loop checks
    session.is_expired() and logs the user out automatically.
  - Password policy is enforced on the verify_credentials path;
    demo seeds are labelled and bypass the policy intentionally.
  - Brute-force lockout alert is raised with severity='high'.
"""

import db
import security
from config import (
    LARGE_TXN_THRESHOLD,
    MAX_FAILED_LOGINS,
)
from security import (
    safe_float_input,
    safe_int_input,
    validate_amount,
    Session,
)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def login() -> tuple:
    """
    Authenticate the user.
    Returns (user_id, user_role) on success, (None, None) on failure.

    Security controls active:
      - Unknown email is logged with user_id=NULL (fixes Phase 0 finding).
      - is_locked checked before password comparison (fail-fast).
      - verify_password() uses bcrypt.checkpw() -- timing-safe.
      - Failed attempts are persisted to DB -- survive app restart.
      - Account is locked after MAX_FAILED_LOGINS; high-severity alert raised.
    """
    print("\n--- Login ---")
    email = input("Email: ").strip()
    password = input("Password: ").strip()

    user = db.get_user_by_email(email)

    if user is None:
        db.log_action(None, f"Failed login -- unknown email attempted: {email}")
        print("User not found!")
        return None, None

    if user["is_locked"]:
        db.log_action(user["user_id"], "Login attempt on locked account")
        print("Account is locked due to multiple failed attempts. Contact admin.")
        return None, None

    if db.verify_password(password, user["password_hash"]):
        db.reset_failed_attempts(user["user_id"])
        db.log_action(user["user_id"], "Successful login")
        print(f"\nWelcome {user['name']}!  Role: {user['role']}")
        return user["user_id"], user["role"]

    # Wrong password path.
    db.increment_failed_attempts(user["user_id"], max_attempts=MAX_FAILED_LOGINS)
    attempts_now = db.get_failed_attempts(user["user_id"])
    db.log_action(user["user_id"], f"Failed login attempt #{attempts_now}")

    if attempts_now >= MAX_FAILED_LOGINS:
        db.raise_alert(
            user["user_id"],
            "Brute Force",
            f"Account locked after {attempts_now} failed attempts",
            severity="high",
        )
        print("Too many failed attempts -- your account is now locked.")
    else:
        print(f"Wrong password! Attempt {attempts_now}/{MAX_FAILED_LOGINS}")

    return None, None


# ---------------------------------------------------------------------------
# Banking operations  (Phase 2: input-safe, amount-validated)
# ---------------------------------------------------------------------------

def do_deposit(user_id: int, session: Session) -> None:
    """
    SEC-01 + SEC-02: amount validated; safe input wrapper.
    """
    acc = db.get_account_by_user(user_id)
    if acc is None:
        print("No account found.")
        return

    amount = safe_float_input("Enter deposit amount (Rs): ")
    if amount is None:
        return  # safe_float_input already printed an error

    ok, reason = validate_amount(amount)
    if not ok:
        print(f"  [!] Invalid amount: {reason}")
        db.log_action(user_id, f"Rejected deposit attempt -- {reason}")
        return

    db.deposit(acc["account_id"], amount)
    db.log_action(user_id, f"Deposited Rs{amount:.2f}")
    updated = db.get_account_by_user(user_id)
    print(f"Rs{amount:.2f} deposited!  New balance: Rs{updated['balance']:.2f}")
    session.refresh()


def do_withdraw(user_id: int, session: Session) -> None:
    """
    SEC-01 + SEC-02: amount validated; safe input wrapper.
    """
    acc = db.get_account_by_user(user_id)
    if acc is None:
        print("No account found.")
        return

    amount = safe_float_input("Enter withdrawal amount (Rs): ")
    if amount is None:
        return

    ok, reason = validate_amount(amount)
    if not ok:
        print(f"  [!] Invalid amount: {reason}")
        db.log_action(user_id, f"Rejected withdrawal attempt -- {reason}")
        return

    success = db.withdraw(acc["account_id"], amount)
    if success:
        db.log_action(user_id, f"Withdrew Rs{amount:.2f}")
        if amount > LARGE_TXN_THRESHOLD:
            db.raise_alert(
                user_id,
                "Large Transaction",
                f"Large withdrawal of Rs{amount:.2f} detected",
                severity="high",
            )
        updated = db.get_account_by_user(user_id)
        print(f"Rs{amount:.2f} withdrawn!  New balance: Rs{updated['balance']:.2f}")
    else:
        print("Insufficient balance!")
    session.refresh()


def do_transfer(user_id: int, session: Session) -> None:
    """
    SEC-01 + SEC-02 + SEC-03 + SEC-06 (self-transfer block):
      - Safe integer input for destination account.
      - Safe float input for amount.
      - Amount validated (positive, finite, within cap).
      - Self-transfer explicitly rejected before DB call.

    Why self-transfer matters:
      The original code allowed transferring to your own account. While it
      does not steal money, it artificially inflates transaction counts and
      can be used to generate fake audit trails. It also wastes DB writes.
    """
    acc = db.get_account_by_user(user_id)
    if acc is None:
        print("No account found.")
        return

    to_acc_id = safe_int_input("Enter destination account ID: ")
    if to_acc_id is None:
        return

    # SEC-06: Block self-transfer.
    if to_acc_id == acc["account_id"]:
        print("  [!] Self-transfer is not permitted.")
        db.log_action(user_id, f"Rejected self-transfer attempt on account {acc['account_id']}")
        return

    dest = db.get_account_by_id(to_acc_id)
    if dest is None:
        print("Destination account not found!")
        return

    amount = safe_float_input("Enter transfer amount (Rs): ")
    if amount is None:
        return

    ok, reason = validate_amount(amount)
    if not ok:
        print(f"  [!] Invalid amount: {reason}")
        db.log_action(user_id, f"Rejected transfer attempt -- {reason}")
        return

    # Route to Maker-Checker dual control if amount exceeds large transaction threshold
    if amount > LARGE_TXN_THRESHOLD:
        txn_id = db.create_pending_transfer(acc["account_id"], to_acc_id, amount)
        db.log_action(
            user_id,
            f"Initiated transfer #{txn_id} of Rs{amount:.2f} to account {to_acc_id} (pending Maker-Checker approval)",
        )
        db.raise_alert(
            user_id,
            "Large Transaction Pending Approval",
            f"Transfer #{txn_id} of Rs{amount:.2f} to account {to_acc_id} queued for Maker-Checker dual control",
            severity="high",
        )
        print(f"\n  [!] Large Transaction Notice (Maker-Checker Control):")
        print(f"      Transfer of Rs{amount:,.2f} exceeds policy limit of Rs{LARGE_TXN_THRESHOLD:,.2f}.")
        print(f"      Transaction #{txn_id} has been submitted with status 'pending'.")
        print("      Dual-control policy requires an administrator/checker to approve before execution.")
        session.refresh()
        return

    success = db.transfer(acc["account_id"], to_acc_id, amount)
    if success:
        db.log_action(user_id, f"Transferred Rs{amount:.2f} to account {to_acc_id}")
        updated = db.get_account_by_user(user_id)
        print(f"Rs{amount:.2f} transferred!  New balance: Rs{updated['balance']:.2f}")
    else:
        print("Insufficient balance!")
    session.refresh()


# ---------------------------------------------------------------------------
# View functions
# ---------------------------------------------------------------------------

def view_balance(user_id: int, session: Session) -> None:
    acc = db.get_account_by_user(user_id)
    if acc:
        print(f"\nAccount ID: {acc['account_id']}  |  Balance: Rs{acc['balance']:.2f}")
    else:
        print("No account found.")
    session.refresh()


def view_transactions(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Users see only their own transactions (scoped by account_id).
          Admins see all transactions.
    """
    print("\n--- Transaction History ---")
    if role == "admin":
        rows = db.get_all_transactions()
    else:
        acc = db.get_account_by_user(user_id)
        if acc is None:
            print("No account found.")
            return
        rows = db.get_transactions_for_account(acc["account_id"])

    if not rows:
        print("No transactions found.")
        session.refresh()
        return
    for t in rows:
        print(
            f"  ID:{t['txn_id']}  Type:{t['txn_type']:<8}  "
            f"Amount:Rs{t['amount']:>10.2f}  "
            f"From:{str(t['from_account']):<5}  To:{str(t['to_account']):<5}  "
            f"Status:{t['status']}  {t['txn_time']}"
        )
    session.refresh()


def view_audit_log(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Admin-only.
    Any non-admin attempt is logged as an unauthorized access event.
    """
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        db.log_action(user_id, "RBAC violation: unauthorized attempt to view audit log")
        return
    print("\n--- Audit Log (Cryptographic Hash Chained) ---")
    rows = db.get_audit_log()
    for row in rows:
        uid = str(row["user_id"]) if row["user_id"] is not None else "UNKNOWN"
        print(f"  ID:{row['log_id']:<4} User:{uid:<8} {row['action']:<46} {row['log_time']}")
    session.refresh()


def view_alerts(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Admin-only.
    Any non-admin attempt is logged as an unauthorized access event.
    """
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        db.log_action(user_id, "RBAC violation: unauthorized attempt to view alerts")
        return
    print("\n--- Security Alerts ---")
    rows = db.get_all_alerts()
    if not rows:
        print("No alerts.")
        session.refresh()
        return
    for a in rows:
        print(
            f"  Alert:{a['alert_id']}  User:{a['user_id']}  "
            f"Severity:{a['severity']:<6}  Status:{a['status']:<8}  "
            f"Type:{a['alert_type']}  |  {a['description']}"
        )
    session.refresh()


# ---------------------------------------------------------------------------
# Phase 3 Admin Control Consoles (Maker-Checker, Unlock, Alert Resolution, Integrity)
# ---------------------------------------------------------------------------

def manage_pending_transfers(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Admin-only. Maker-Checker dual control console.
    Review, approve, or reject transactions that exceeded LARGE_TXN_THRESHOLD.
    """
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        db.log_action(user_id, "RBAC violation: unauthorized attempt to manage pending transfers")
        return

    print("\n--- Pending Transfers (Maker-Checker Dual Control) ---")
    rows = db.get_pending_transfers()
    if not rows:
        print("No pending transfers awaiting approval.")
        session.refresh()
        return

    for t in rows:
        print(
            f"  Txn #{t['txn_id']} | From Acc:{t['from_account']} ({t['sender_name']} / {t['sender_email']}) "
            f"-> To Acc:{t['to_account']} | Amount: Rs{t['amount']:,.2f} | Submitted: {t['txn_time']}"
        )

    txn_id_input = safe_int_input("\nEnter Txn ID to act on (or 0 to cancel): ")
    if not txn_id_input:
        session.refresh()
        return

    action = input("Action: [A]pprove or [R]eject? ").strip().upper()
    if action == "A":
        success, msg = db.approve_pending_transfer(txn_id_input, user_id)
        if success:
            print(f"  [+] {msg}")
        else:
            print(f"  [!] Approval failed: {msg}")
    elif action == "R":
        reason = input("Enter rejection reason (or leave blank): ").strip()
        success, msg = db.reject_pending_transfer(txn_id_input, user_id, reason or "Rejected by administrator")
        if success:
            print(f"  [+] {msg}")
        else:
            print(f"  [!] Rejection failed: {msg}")
    else:
        print("Invalid action.")
    session.refresh()


def manage_locked_users(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Admin-only.
    Account lockout remediation / admin unlock (ISO 27001 A.9.4.2).
    """
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        db.log_action(user_id, "RBAC violation: unauthorized attempt to unlock accounts")
        return

    print("\n--- Locked User Accounts ---")
    rows = db.get_locked_users()
    if not rows:
        print("No accounts are currently locked.")
        session.refresh()
        return

    for u in rows:
        print(
            f"  User ID:{u['user_id']} | Name:{u['name']} | Email:{u['email']} | "
            f"Failed Attempts:{u['failed_attempts']}"
        )

    target_id = safe_int_input("\nEnter User ID to unlock (or 0 to cancel): ")
    if not target_id:
        session.refresh()
        return

    if db.unlock_user(target_id, admin_user_id=user_id):
        print(f"  [+] User #{target_id} has been unlocked successfully.")
    else:
        print(f"  [!] User #{target_id} not found.")
    session.refresh()


def manage_alerts(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Admin-only.
    View security alerts and mark resolved (Audit incident response remediation).
    """
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        db.log_action(user_id, "RBAC violation: unauthorized attempt to manage alerts")
        return

    print("\n--- Security Alerts Console ---")
    rows = db.get_all_alerts()
    if not rows:
        print("No alerts recorded.")
        session.refresh()
        return

    for a in rows:
        print(
            f"  Alert #{a['alert_id']} | User:{a['user_id']} | "
            f"Severity:{a['severity'].upper():<6} | Status:{a['status'].upper():<8} | "
            f"Type:{a['alert_type']} | {a['description']} [{a['alert_time']}]"
        )

    open_alerts = [a for a in rows if a["status"] == "open"]
    if open_alerts:
        alert_id_input = safe_int_input("\nEnter Alert ID to resolve (or 0 to return): ")
        if alert_id_input:
            if db.resolve_alert(alert_id_input, admin_user_id=user_id):
                print(f"  [+] Alert #{alert_id_input} marked as resolved.")
            else:
                print(f"  [!] Alert #{alert_id_input} not found.")
    session.refresh()


def verify_audit_integrity_menu(user_id: int, role: str, session: Session) -> None:
    """
    RBAC: Admin-only.
    Cryptographic verification of the tamper-evident audit log chain.
    """
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        db.log_action(user_id, "RBAC violation: unauthorized attempt to verify audit log")
        return

    print("\n--- Audit Log Cryptographic Integrity Verification ---")
    is_valid, bad_id = db.verify_audit_log_integrity()
    if is_valid:
        print("  [+] INTEGRITY PASS: All cryptographic SHA-256 hash chains match.")
        print("      No records have been modified, deleted, or inserted out of order.")
    else:
        print(f"  [!] TAMPERING DETECTED at log_id={bad_id}!")
        print("      Hash pointer mismatch indicates unauthorized database modification.")
        db.raise_alert(
            user_id,
            "Audit Log Tampering",
            f"Cryptographic hash mismatch detected at audit log entry #{bad_id}",
            severity="high",
        )
    session.refresh()


# ---------------------------------------------------------------------------
# Menu  (Session timeout enforced on every iteration)
# ---------------------------------------------------------------------------

def menu(user_id: int, role: str) -> None:
    """
    Main menu loop.

    SEC-05 Session timeout:
      Before displaying the menu, check if the session has been idle for
      more than SESSION_TIMEOUT_SECONDS (300 s / 5 minutes).
      If expired, log the event and exit the menu automatically.
      session.refresh() is called inside every action function.
    """
    session = Session()  # inactivity clock starts at login

    while True:
        # SEC-05: Inactivity check on every iteration.
        if session.is_expired():
            db.log_action(user_id, "Session expired due to inactivity -- auto-logout")
            print("\n[!] Session timed out due to inactivity. Goodbye!")
            return

        mins = int(session.seconds_remaining() // 60)
        secs = int(session.seconds_remaining() % 60)
        print(f"\n--- Banking Menu ({role.upper()}) --- [session expires in {mins}m {secs}s]")
        print("1. View Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Transfer")
        print("5. Transaction History")
        if role == "admin":
            print("6. Audit Log (View)")
            print("7. Security Alerts & Remediation")
            print("8. Maker-Checker Approvals")
            print("9. Unlock User Accounts")
            print("10. Verify Audit Log Integrity")
            print("11. Logout")
        else:
            print("6. Audit Log        (admin only)")
            print("7. Security Alerts  (admin only)")
            print("8. Logout")

        choice = input("Choose: ").strip()

        if choice == "1":
            view_balance(user_id, session)
        elif choice == "2":
            do_deposit(user_id, session)
        elif choice == "3":
            do_withdraw(user_id, session)
        elif choice == "4":
            do_transfer(user_id, session)
        elif choice == "5":
            view_transactions(user_id, role, session)
        elif choice == "6":
            view_audit_log(user_id, role, session)
        elif choice == "7":
            if role == "admin":
                manage_alerts(user_id, role, session)
            else:
                view_alerts(user_id, role, session)
        elif choice == "8":
            if role == "admin":
                manage_pending_transfers(user_id, role, session)
            else:
                db.log_action(user_id, "Logged out")
                print("Goodbye!")
                break
        elif choice == "9" and role == "admin":
            manage_locked_users(user_id, role, session)
        elif choice == "10" and role == "admin":
            verify_audit_integrity_menu(user_id, role, session)
        elif choice == "11" and role == "admin":
            db.log_action(user_id, "Logged out")
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")
            # Do NOT refresh session on invalid input -- keeps the clock running.


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    db.init_db()
    user_id, role = login()
    if user_id:
        menu(user_id, role)
