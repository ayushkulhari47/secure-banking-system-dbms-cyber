#!/usr/bin/env python3
"""
scripts/seed_demo.py -- Explicit command to seed demo users and accounts.

Passwords are never hardcoded in source code. Each account password is read
from its environment variable when set, or requested interactively via getpass.
"""

from decimal import Decimal
import getpass
import os
import sys

# Ensure repository root is on sys.path when invoked as `python scripts/seed_demo.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bank import auth, db, security

DEMO_ACCOUNTS = [
    {
        "name": "Ayush Kulhari",
        "email": "ayush@bank.com",
        "role": "admin",
        "balance": Decimal("50000.00"),
        "env_var": "DEMO_ADMIN_PASSWORD",
    },
    {
        "name": "Rahul Sharma",
        "email": "rahul@bank.com",
        "role": "user",
        "balance": Decimal("25000.00"),
        "env_var": "DEMO_RAHUL_PASSWORD",
    },
    {
        "name": "Priya Singh",
        "email": "priya@bank.com",
        "role": "user",
        "balance": Decimal("15000.00"),
        "env_var": "DEMO_PRIYA_PASSWORD",
    },
]


def _resolve_password(spec: dict) -> str:
    password = os.environ.get(spec["env_var"], "")
    if not password:
        password = getpass.getpass(
            f"Enter demo password for {spec['name']} ({spec['email']}, role={spec['role']}): "
        )
    if not password:
        raise ValueError(
            f"Password for {spec['email']} cannot be empty "
            f"(set {spec['env_var']} or enter it interactively)."
        )
    ok, violations = security.password_meets_policy(password)
    if not ok:
        raise ValueError(
            f"Password for {spec['email']} does not meet policy: "
            + "; ".join(violations)
        )
    return password


def seed_demo_users() -> int:
    """
    Initialize tables and insert demo users/accounts if Users is currently empty.
    Returns the number of users created.
    """
    db.init_db()
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM Users").fetchone()
        if row["cnt"] > 0:
            print("Users table is already populated; skipping demo seed.")
            return 0

        records = []
        for spec in DEMO_ACCOUNTS:
            pw_hash = auth.hash_password(_resolve_password(spec))
            records.append(
                (spec["name"], spec["email"], pw_hash, spec["role"], spec["balance"])
            )

        conn.execute("BEGIN")
        try:
            for name, email, pw_hash, role, balance in records:
                cur = conn.execute(
                    "INSERT INTO Users (name, email, password_hash, role)"
                    " VALUES (?, ?, ?, ?)",
                    (name, email, pw_hash, role),
                )
                conn.execute(
                    "INSERT INTO Accounts (user_id, balance) VALUES (?, ?)",
                    (cur.lastrowid, str(balance)),
                )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

        print(f"Seeded {len(records)} demo users and accounts.")
        return len(records)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        seed_demo_users()
    except Exception as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

