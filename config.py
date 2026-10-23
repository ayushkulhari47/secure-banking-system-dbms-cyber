"""
config.py  Centralized tuneable configuration parameters for the Secure Banking System.

Design Decision (IT Audit / Compliance Perspective):
- Centralizing tuneable security parameters satisfies ISO 27001 A.12.1.1 (Operational
  procedures and responsibilities) and ITGC Change Management guidelines.
- Instead of magic numbers scattered across code, thresholds for authentication lockouts,
  transaction caps, session timeouts, and dual-control limits are auditable in one place.
"""

import os
import sys


def load_dotenv(env_path: str = None) -> None:
    """
    Lightweight zero-dependency .env loader.
    Reads key-value pairs from .env into os.environ if not already set.
    """
    if env_path is None:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = val
    except Exception:
        pass


load_dotenv()


def resolve_db_credentials(script_name: str, env) -> tuple:
    """
    Choose which MySQL account this process connects with.

    - The running application always uses DB_USER / DB_PASSWORD (the limited
      'bank_app' account once provisioning is done).
    - Only the provisioning script setup_db.py may use the admin account
      DB_ADMIN_USER / DB_ADMIN_PASSWORD, because creating tables and users
      needs powers the application must never have.
    - MySQL provisioning requires an explicit DB_ADMIN_USER. It never silently
      reuses the runtime account for administrative work.
    """
    user = env.get("DB_USER", "root")
    password = env.get("DB_PASSWORD", "")
    if script_name == "setup_db.py":
        admin_user = env.get("DB_ADMIN_USER")
        if not admin_user:
            if env.get("DB_TYPE", "sqlite").lower() == "mysql":
                raise RuntimeError(
                    "DB_ADMIN_USER must be set when provisioning MySQL; "
                    "the runtime DB_USER cannot be used as an admin fallback."
                )
            return user, password
        return admin_user, env.get("DB_ADMIN_PASSWORD", "")
    return user, password


# ---------------------------------------------------------------------------
# Database Configuration (.env driven)
# ---------------------------------------------------------------------------
DB_TYPE: str = os.environ.get("DB_TYPE", "sqlite").lower()
DB_PATH: str = os.environ.get("DB_PATH", "banking.db")
DB_HOST: str = os.environ.get("DB_HOST", "localhost")
DB_PORT: int = int(os.environ.get("DB_PORT", "3306"))
DB_USER, DB_PASSWORD = resolve_db_credentials(
    os.path.basename(sys.argv[0]) if sys.argv else "", os.environ
)
DB_NAME: str = os.environ.get("DB_NAME", "secure_banking")

# ---------------------------------------------------------------------------
# Least-privilege grants for the MySQL runtime user 'bank_app'
# (applied by setup_db.py; checked against the real SQL in db.py by
#  tests/test_least_privilege.py)
# ---------------------------------------------------------------------------
APP_TABLE_GRANTS: dict = {
    "Users": ("SELECT", "UPDATE"),
    "Accounts": ("SELECT", "UPDATE"),
    "Transactions": ("SELECT", "INSERT", "UPDATE"),
    "Alerts": ("SELECT", "INSERT", "UPDATE"),
    "Audit_Log": ("SELECT", "INSERT"),  # append-only: no UPDATE, no DELETE
}

# ---------------------------------------------------------------------------
# Transaction Thresholds
# ---------------------------------------------------------------------------
MIN_AMOUNT: float = 0.01  # Smallest allowed currency amount (Rs)
MAX_AMOUNT: float = 1_000_000.00  # Application-layer upper cap per transaction (Rs)
LARGE_TXN_THRESHOLD: float = (
    50_000.00  # Transactions above this require Maker-Checker dual control
)

# ---------------------------------------------------------------------------
# Authentication & Access Control
# ---------------------------------------------------------------------------
MAX_FAILED_LOGINS: int = 3  # Max consecutive failed logins before account lock
MIN_PASSWORD_LENGTH: int = 8  # Password complexity minimum length
SESSION_TIMEOUT_SECONDS: int = 300  # 5 minutes session inactivity timeout

# ---------------------------------------------------------------------------
# Cryptographic Settings
# ---------------------------------------------------------------------------
BCRYPT_ROUNDS: int = 12  # Work factor for bcrypt hashing (~250ms per hash)
