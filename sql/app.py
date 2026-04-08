import hashlib
import datetime

users = {
    1: {"name": "Ayush Kulhari", "email": "ayush@bank.com", "password": hashlib.sha256("ayush123".encode()).hexdigest(), "role": "admin", "failed_attempts": 0, "is_locked": False},
    2: {"name": "Rahul Sharma", "email": "rahul@bank.com", "password": hashlib.sha256("rahul123".encode()).hexdigest(), "role": "user", "failed_attempts": 0, "is_locked": False},
    3: {"name": "Priya Singh", "email": "priya@bank.com", "password": hashlib.sha256("priya123".encode()).hexdigest(), "role": "user", "failed_attempts": 0, "is_locked": False}
}

accounts = {
    1: {"user_id": 1, "balance": 50000.00},
    2: {"user_id": 2, "balance": 25000.00},
    3: {"user_id": 3, "balance": 15000.00}
}

transactions = []
audit_log = []
alerts = []

def log_action(user_id, action):
    audit_log.append({"user_id": user_id, "action": action, "time": str(datetime.datetime.now())})

def raise_alert(user_id, alert_type, description):
    alerts.append({"user_id": user_id, "type": alert_type, "description": description, "status": "open"})
    print(f"\n🚨 ALERT: {alert_type} - {description}")

def login():
    print("\n--- Login ---")
    email = input("Email: ")
    password = input("Password: ")
    hashed = hashlib.sha256(password.encode()).hexdigest()
    for uid, user in users.items():
        if user["email"] == email:
            if user["is_locked"]:
                print("Account is locked due to multiple failed attempts!")
                return None
            if user["password"] == hashed:
                user["failed_attempts"] = 0
                log_action(uid, "Successful login")
                print(f"\nWelcome {user['name']}! Role: {user['role']}")
                return uid
            else:
                user["failed_attempts"] += 1
                log_action(uid, f"Failed login attempt #{user['failed_attempts']}")
                if user["failed_attempts"] >= 3:
                    user["is_locked"] = True
                    raise_alert(uid, "Brute Force", f"Account locked after {user['failed_attempts']} failed attempts")
                else:
                    print(f"Wrong password! Attempt {user['failed_attempts']}/3")
                return None
    print("User not found!")
    return None

def get_account(user_id):
    for acc_id, acc in accounts.items():
        if acc["user_id"] == user_id:
            return acc_id, acc
    return None, None

def deposit(user_id):
    acc_id, acc = get_account(user_id)
    amount = float(input("Enter deposit amount (Rs): "))
    acc["balance"] += amount
    transactions.append({"from": None, "to": acc_id, "amount": amount, "type": "deposit"})
    log_action(user_id, f"Deposited Rs{amount}")
    print(f"Rs{amount} deposited! New balance: Rs{acc['balance']}")

def withdraw(user_id):
    acc_id, acc = get_account(user_id)
    amount = float(input("Enter withdrawal amount (Rs): "))
    if acc["balance"] >= amount:
        acc["balance"] -= amount
        transactions.append({"from": acc_id, "to": None, "amount": amount, "type": "withdraw"})
        log_action(user_id, f"Withdrew Rs{amount}")
        if amount > 50000:
            raise_alert(user_id, "Large Transaction", f"Large withdrawal of Rs{amount} detected")
        print(f"Rs{amount} withdrawn! New balance: Rs{acc['balance']}")
    else:
        print("Insufficient balance!")

def transfer(user_id):
    acc_id, acc = get_account(user_id)
    to_acc_id = int(input("Enter destination account ID: "))
    amount = float(input("Enter transfer amount (Rs): "))
    if to_acc_id in accounts:
        if acc["balance"] >= amount:
            acc["balance"] -= amount
            accounts[to_acc_id]["balance"] += amount
            transactions.append({"from": acc_id, "to": to_acc_id, "amount": amount, "type": "transfer"})
            log_action(user_id, f"Transferred Rs{amount} to account {to_acc_id}")
            if amount > 50000:
                raise_alert(user_id, "Large Transaction", f"Large transfer of Rs{amount} detected")
            print(f"Rs{amount} transferred! New balance: Rs{acc['balance']}")
        else:
            print("Insufficient balance!")
    else:
        print("Destination account not found!")

def view_balance(user_id):
    acc_id, acc = get_account(user_id)
    print(f"\nAccount ID: {acc_id} | Balance: Rs{acc['balance']}")

def view_transactions():
    print("\n--- Transaction History ---")
    for t in transactions:
        print(f"Type: {t['type']} | Amount: Rs{t['amount']} | From: {t['from']} | To: {t['to']}")

def view_audit_log():
    print("\n--- Audit Log ---")
    for log in audit_log:
        print(f"User {log['user_id']}: {log['action']} at {log['time']}")

def view_alerts():
    print("\n--- Security Alerts ---")
    if not alerts:
        print("No alerts!")
    for a in alerts:
        print(f"User {a['user_id']} | {a['type']} | {a['description']} | {a['status']}")

def menu(user_id):
    while True:
        print("\n--- Banking Menu ---")
        print("1. View Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Transfer")
        print("5. Transaction History")
        print("6. Audit Log")
        print("7. Security Alerts")
        print("8. Logout")
        choice = input("Choose: ")
        if choice == "1": view_balance(user_id)
        elif choice == "2": deposit(user_id)
        elif choice == "3": withdraw(user_id)
        elif choice == "4": transfer(user_id)
        elif choice == "5": view_transactions()
        elif choice == "6": view_audit_log()
        elif choice == "7": view_alerts()
        elif choice == "8": break

user_id = login()
if user_id:
    menu(user_id)
