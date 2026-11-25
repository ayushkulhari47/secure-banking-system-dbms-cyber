"""
main.py -- Secure Banking System CLI entry point.
"""

from collections import defaultdict
import getpass
import time

from bank import alerts, audit, auth, db, security, transactions
from bank.config import (
    LARGE_TXN_THRESHOLD,
    MAX_FAILED_LOGINS,
)
from bank.security import (
    Session,
    safe_float_input,
    safe_int_input,
    validate_amount,
)

# Process-local velocity signal. The database remains the source of truth for
# transactions; this short-window detector is an additional online signal and
# is intentionally not treated as a transaction authorization control.
_TRANSACTION_TIMES = defaultdict(list)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def login() -> tuple:
    """
    Authenticate the user.
    Returns (user_id, user_role) on success, (None, None) on failure.
    """
    print("\n--- Login ---")
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")

    if security.detect_sqli(email):
        audit.log_action(None, "SQL injection pattern detected during login")
        alerts.raise_alert(
            None,
            "SQL Injection Signal",
            "Suspicious login input pattern detected",
            severity="high",
        )

    user = auth.get_user_by_email(email)

    if user is None:
        # Run a dummy bcrypt check so unknown-email and wrong-password paths
        # have comparable work, and never disclose whether an email exists.
        auth.verify_password(password, auth.DUMMY_PASSWORD_HASH)
        audit.log_action(None, "Failed login -- invalid credentials")
        print("Invalid email or password.")
        return None, None

    if user["is_locked"]:
        audit.log_action(user["user_id"], "Login attempt on locked account")
        print("Account is locked due to multiple failed attempts. Contact admin.")
        return None, None

    if auth.verify_password(password, user["password_hash"]):
        auth.reset_failed_attempts(user["user_id"])
        audit.log_action(user["user_id"], "Successful login")
        print(f"\nWelcome {user['name']}!  Role: {user['role']}")
        return user["user_id"], user["role"]

    # Wrong password path.
    auth.increment_failed_attempts(user["user_id"], max_attempts=MAX_FAILED_LOGINS)
    attempts_now = auth.get_failed_attempts(user["user_id"])
    audit.log_action(user["user_id"], f"Failed login attempt #{attempts_now}")

    if attempts_now >= MAX_FAILED_LOGINS:
        alerts.raise_alert(
            user["user_id"],
            "Brute Force",
            f"Account locked after {attempts_now} failed attempts",
            severity="high",
        )
        print("Too many failed attempts -- your account is now locked.")
    else:
        print(f"Wrong password! Attempt {attempts_now}/{MAX_FAILED_LOGINS}")

    return None, None


def _record_transaction_signals(user_id: int, action: str) -> None:
    """Record online fraud signals after a committed financial operation."""
    now = time.monotonic()
    times = _TRANSACTION_TIMES[user_id]
    times.append(now)
    flagged, count = security.check_velocity(times)
    if flagged:
        alerts.raise_alert(
            user_id,
            "Rapid Transactions",
            f"{count} transactions detected within {security.VELOCITY_WINDOW_SECONDS} seconds",
            severity="high",
        )
    if security.is_odd_hour():
        alerts.raise_alert(
            user_id,
            "Odd-Hour Transaction",
            f"{action} submitted during configured quiet hours",
            severity="medium",
        )


# ---------------------------------------------------------------------------
# Banking operations
# ---------------------------------------------------------------------------


def do_deposit(user_id: int, session: Session) -> None:
    """Deposit validated funds into the authenticated user's account."""
    acc = transactions.get_account_by_user(user_id)
    if acc is None:
        print("No account found.")
        return

    amount = safe_float_input("Enter deposit amount (Rs): ")
    if amount is None:
        return  # safe_float_input already printed an error

    ok, reason = validate_amount(amount)
    if not ok:
        print(f"  [!] Invalid amount: {reason}")
        audit.log_action(user_id, f"Rejected deposit attempt -- {reason}")
        return

    transactions.deposit(acc["account_id"], amount)
    audit.log_action(user_id, f"Deposited Rs{amount:.2f}")
    _record_transaction_signals(user_id, "Deposit")
    updated = transactions.get_account_by_user(user_id)
    print(f"Rs{amount:.2f} deposited!  New balance: Rs{updated['balance']:.2f}")
    session.refresh()


def do_withdraw(user_id: int, session: Session) -> None:
    """Withdraw validated funds from the authenticated user's account."""
    acc = transactions.get_account_by_user(user_id)
    if acc is None:
        print("No account found.")
        return

    amount = safe_float_input("Enter withdrawal amount (Rs): ")
    if amount is None:
        return

    ok, reason = validate_amount(amount)
    if not ok:
        print(f"  [!] Invalid amount: {reason}")
        audit.log_action(user_id, f"Rejected withdrawal attempt -- {reason}")
        return

    success = transactions.withdraw(acc["account_id"], amount)
    if success:
        audit.log_action(user_id, f"Withdrew Rs{amount:.2f}")
        _record_transaction_signals(user_id, "Withdrawal")
        if amount > LARGE_TXN_THRESHOLD:
            alerts.raise_alert(
                user_id,
                "Large Transaction",
                f"Large withdrawal of Rs{amount:.2f} detected",
                severity="high",
            )
        updated = transactions.get_account_by_user(user_id)
        print(f"Rs{amount:.2f} withdrawn!  New balance: Rs{updated['balance']:.2f}")
    else:
        print("Insufficient balance!")
    session.refresh()


def do_transfer(user_id: int, session: Session) -> None:
    """Transfer validated funds or queue high-value transfers for Maker-Checker."""
    acc = transactions.get_account_by_user(user_id)
    if acc is None:
        print("No account found.")
        return

    to_acc_id = safe_int_input("Enter destination account ID: ")
    if to_acc_id is None:
        return

    # SEC-06: Block self-transfer.
    if to_acc_id == acc["account_id"]:
        print("  [!] Self-transfer is not permitted.")
        audit.log_action(
            user_id, f"Rejected self-transfer attempt on account {acc['account_id']}"
        )
        return

    dest = transactions.get_account_by_id(to_acc_id)
    if dest is None:
        print("Destination account not found!")
        return

    amount = safe_float_input("Enter transfer amount (Rs): ")
    if amount is None:
        return

    ok, reason = validate_amount(amount)
    if not ok:
        print(f"  [!] Invalid amount: {reason}")
        audit.log_action(user_id, f"Rejected transfer attempt -- {reason}")
        return

    # Route to Maker-Checker dual control if amount exceeds large transaction threshold
    if amount > LARGE_TXN_THRESHOLD:
        try:
            txn_id = transactions.create_pending_transfer(
                acc["account_id"], to_acc_id, amount
            )
        except ValueError as exc:
            print(f"  [!] Transfer not submitted: {exc}")
            audit.log_action(user_id, f"Rejected pending transfer attempt -- {exc}")
            session.refresh()
            return
        audit.log_action(
            user_id,
            f"Initiated transfer #{txn_id} of Rs{amount:.2f} to account {to_acc_id} "
            "(pending Maker-Checker approval)",
        )
        alerts.raise_alert(
            user_id,
            "Large Transaction Pending Approval",
            f"Transfer #{txn_id} of Rs{amount:.2f} to account {to_acc_id} "
            "queued for Maker-Checker dual control",
            severity="high",
        )
        _record_transaction_signals(user_id, "Pending transfer")
        print("\n  [!] Large Transaction Notice (Maker-Checker Control):")
        print(
            f"      Transfer of Rs{amount:,.2f} exceeds policy limit of "
            f"Rs{LARGE_TXN_THRESHOLD:,.2f}."
        )
        print(f"      Transaction #{txn_id} has been submitted with status 'pending'.")
        print(
            "      Dual-control policy requires an administrator/checker "
            "to approve before execution."
        )
        session.refresh()
        return

    success = transactions.transfer(acc["account_id"], to_acc_id, amount)
    if success:
        audit.log_action(user_id, f"Transferred Rs{amount:.2f} to account {to_acc_id}")
        _record_transaction_signals(user_id, "Transfer")
        updated = transactions.get_account_by_user(user_id)
        print(f"Rs{amount:.2f} transferred!  New balance: Rs{updated['balance']:.2f}")
    else:
        print("Insufficient balance!")
    session.refresh()


# ---------------------------------------------------------------------------
# View functions
# ---------------------------------------------------------------------------


def view_balance(user_id: int, session: Session) -> None:
    """Display the authenticated user's account ID and current balance."""
    acc = transactions.get_account_by_user(user_id)
    if acc:
        print(f"\nAccount ID: {acc['account_id']}  |  Balance: Rs{acc['balance']:.2f}")
    else:
        print("No account found.")
    session.refresh()


def view_transactions(user_id: int, role: str, session: Session) -> None:
    """Display transaction history scoped by role."""
    print("\n--- Transaction History ---")
    if role == "admin":
        rows = transactions.get_all_transactions(admin_user_id=user_id)
    else:
        acc = transactions.get_account_by_user(user_id)
        if acc is None:
            print("No account found.")
            return
        rows = transactions.get_transactions_for_account(acc["account_id"])

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
    """Display recent audit log entries (admin only)."""
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        audit.log_action(
            user_id, "RBAC violation: unauthorized attempt to view audit log"
        )
        return
    print("\n--- Audit Log (Cryptographic Hash Chained) ---")
    rows = audit.get_audit_log(admin_user_id=user_id)
    for row in rows:
        uid = str(row["user_id"]) if row["user_id"] is not None else "UNKNOWN"
        print(
            f"  ID:{row['log_id']:<4} User:{uid:<8} {row['action']:<46} {row['log_time']}"
        )
    session.refresh()


def view_alerts(user_id: int, role: str, session: Session) -> None:
    """Display all security alerts (admin only)."""
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        audit.log_action(
            user_id, "RBAC violation: unauthorized attempt to view alerts"
        )
        return
    print("\n--- Security Alerts ---")
    rows = alerts.get_all_alerts(admin_user_id=user_id)
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
# Change Password
# ---------------------------------------------------------------------------


def do_change_password(user_id: int, session: Session) -> None:
    """Allow an authenticated user to change their own password."""
    print("\n--- Change Password ---")
    old_pw = getpass.getpass("Current password: ")
    new_pw = getpass.getpass("New password: ")
    new_pw2 = getpass.getpass("Confirm new password: ")

    if new_pw != new_pw2:
        print("  [!] New passwords do not match. Password not changed.")
        return

    ok, reason = auth.change_password(user_id, old_pw, new_pw)
    if ok:
        print("  [+] Password changed successfully.")
        session.refresh()
    else:
        print(f"  [!] Password change failed: {reason}")


# ---------------------------------------------------------------------------
# Admin Control Consoles
# ---------------------------------------------------------------------------


def manage_pending_transfers(user_id: int, role: str, session: Session) -> None:
    """Admin-only Maker-Checker dual control console."""
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        audit.log_action(
            user_id, "RBAC violation: unauthorized attempt to manage pending transfers"
        )
        return

    print("\n--- Pending Transfers (Maker-Checker Dual Control) ---")
    rows = transactions.get_pending_transfers(admin_user_id=user_id)
    if not rows:
        print("No pending transfers awaiting approval.")
        session.refresh()
        return

    for t in rows:
        print(
            f"  Txn #{t['txn_id']} | From Acc:{t['from_account']} "
            f"({t['sender_name']} / {t['sender_email']}) "
            f"-> To Acc:{t['to_account']} | Amount: Rs{t['amount']:,.2f} | "
            f"Submitted: {t['txn_time']}"
        )

    txn_id_input = safe_int_input("\nEnter Txn ID to act on (or 0 to cancel): ")
    if not txn_id_input:
        session.refresh()
        return

    action = input("Action: [A]pprove or [R]eject? ").strip().upper()
    if action == "A":
        success, msg = transactions.approve_pending_transfer(txn_id_input, user_id)
        if success:
            print(f"  [+] {msg}")
        else:
            print(f"  [!] Approval failed: {msg}")
    elif action == "R":
        reason = input("Enter rejection reason (or leave blank): ").strip()
        success, msg = transactions.reject_pending_transfer(
            txn_id_input, user_id, reason or "Rejected by administrator"
        )
        if success:
            print(f"  [+] {msg}")
        else:
            print(f"  [!] Rejection failed: {msg}")
    else:
        print("Invalid action.")
    session.refresh()


def manage_locked_users(user_id: int, role: str, session: Session) -> None:
    """Admin-only account lockout remediation console."""
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        audit.log_action(
            user_id, "RBAC violation: unauthorized attempt to unlock accounts"
        )
        return

    print("\n--- Locked User Accounts ---")
    rows = auth.get_locked_users()
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

    if auth.unlock_user(target_id, admin_user_id=user_id):
        print(f"  [+] User #{target_id} has been unlocked successfully.")
    else:
        print(f"  [!] User #{target_id} not found.")
    session.refresh()


def manage_alerts(user_id: int, role: str, session: Session) -> None:
    """Admin-only alert triage and resolution console."""
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        audit.log_action(
            user_id, "RBAC violation: unauthorized attempt to manage alerts"
        )
        return

    print("\n--- Security Alerts Console ---")
    rows = alerts.get_all_alerts(admin_user_id=user_id)
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

    actionable = [a for a in rows if a["status"] in {"open", "reviewed"}]
    if actionable:
        alert_id_input = safe_int_input("\nEnter Alert ID to act on (or 0 to return): ")
        if alert_id_input:
            target = next(
                (a for a in actionable if a["alert_id"] == alert_id_input), None
            )
            if target is None:
                print("  [!] Alert not found or already closed.")
            elif target["status"] == "open":
                note = input("Review note (optional): ").strip()
                if alerts.review_alert(alert_id_input, user_id, note):
                    print(f"  [+] Alert #{alert_id_input} marked as reviewed.")
                else:
                    print("  [!] Alert could not be reviewed.")
            else:
                note = input("Closure note (optional): ").strip()
                if alerts.close_alert(alert_id_input, user_id, note):
                    print(f"  [+] Alert #{alert_id_input} marked as closed.")
                else:
                    print("  [!] Alert could not be closed.")
    session.refresh()


def verify_audit_integrity_menu(user_id: int, role: str, session: Session) -> None:
    """Admin-only cryptographic audit log integrity verification."""
    if role != "admin":
        print("  [!] Access denied -- admin only.")
        audit.log_action(
            user_id, "RBAC violation: unauthorized attempt to verify audit log"
        )
        return

    print("\n--- Audit Log Cryptographic Integrity Verification ---")
    is_valid, bad_id = audit.verify_audit_log_integrity()
    if is_valid:
        print("  [+] INTEGRITY PASS: All cryptographic SHA-256 hash chains match.")
        print("      No records have been modified, deleted, or inserted out of order.")
    else:
        print(f"  [!] TAMPERING DETECTED at log_id={bad_id}!")
        print(
            "      Hash pointer mismatch indicates unauthorized database modification."
        )
        alerts.raise_alert(
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
    """Main interactive CLI menu loop with inactivity timeout enforcement."""
    session = Session()

    while True:
        if session.is_expired():
            audit.log_action(user_id, "Session expired due to inactivity -- auto-logout")
            print("\n[!] Session timed out due to inactivity. Goodbye!")
            return

        mins = int(session.seconds_remaining() // 60)
        secs = int(session.seconds_remaining() % 60)
        print(
            f"\n--- Banking Menu ({role.upper()}) --- [session expires in {mins}m {secs}s]"
        )
        print("1. View Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Transfer")
        print("5. Transaction History")
        print("6. Change Password")
        if role == "admin":
            print("7.  Audit Log (View)")
            print("8.  Security Alerts & Remediation")
            print("9.  Maker-Checker Approvals")
            print("10. Unlock User Accounts")
            print("11. Verify Audit Log Integrity")
            print("12. Logout")
        else:
            print("7. Audit Log        (admin only)")
            print("8. Security Alerts  (admin only)")
            print("9. Logout")

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
            do_change_password(user_id, session)
        elif choice == "7":
            view_audit_log(user_id, role, session)
        elif choice == "8":
            if role == "admin":
                manage_alerts(user_id, role, session)
            else:
                view_alerts(user_id, role, session)
        elif choice == "9":
            if role == "admin":
                manage_pending_transfers(user_id, role, session)
            else:
                audit.log_action(user_id, "Logged out")
                print("Goodbye!")
                break
        elif choice == "10" and role == "admin":
            manage_locked_users(user_id, role, session)
        elif choice == "11" and role == "admin":
            verify_audit_integrity_menu(user_id, role, session)
        elif choice == "12" and role == "admin":
            audit.log_action(user_id, "Logged out")
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    db.init_db()
    user_id, role = login()
    if user_id:
        menu(user_id, role)

