"""
bank/config.py -- Centralized tuneable configuration parameters for the Secure Banking System.

Design Decision (IT Audit / Compliance Perspective):
- Centralizing tuneable security parameters satisfies ISO 27001 A.12.1.1 (Operational
  procedures and responsibilities) and ITGC Change Management guidelines.
- Database connection settings are read strictly from environment variables with
  no hardcoded default credentials.
"""

import os
import sys

BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_dotenv(env_path: str = None) -> None:
    """
    Lightweight zero-dependency .env loader.
    Reads key-value pairs from .env into os.environ if not already set.
    """
    if env_path is None:
        env_path = os.path.join(BASE_DIR, ".env")
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
    Resolve database credentials exclusively from environment variables.

    - The running application always reads DB_USER and DB_PASSWORD.
    - setup_db.py may use DB_ADMIN_USER / DB_ADMIN_PASSWORD when provided,
      or DB_USER / DB_PASSWORD otherwise.
    - Never falls back to unsafe defaults such as 'root'.
    """
    user = env.get("DB_USER", "").strip()
    password = env.get("DB_PASSWORD", "")
    if script_name == "setup_db.py":
        admin_user = env.get("DB_ADMIN_USER", "").strip()
        if admin_user:
            return admin_user, env.get("DB_ADMIN_PASSWORD", "")
        if env.get("DB_TYPE", "sqlite").strip().lower() == "mysql" and not user:
            raise RuntimeError(
                "DB_ADMIN_USER or DB_USER must be set in environment variables "
                "when provisioning MySQL."
            )
        return user, password
    return user, password


def _parse_db_port(raw_port: str) -> int:
    """Parse DB_PORT from environment, defaulting to standard port 3306 if empty."""
    cleaned = (raw_port or "").strip()
    return int(cleaned) if cleaned else 3306


# ---------------------------------------------------------------------------
# Database Configuration (environment-driven, no unsafe credential defaults)
# ---------------------------------------------------------------------------
DB_TYPE: str = os.environ.get("DB_TYPE", "sqlite").strip().lower() or "sqlite"
DB_PATH: str = os.environ.get("DB_PATH", "banking.db")
DB_HOST: str = os.environ.get("DB_HOST", "").strip()
DB_PORT: int = _parse_db_port(os.environ.get("DB_PORT", ""))
DB_NAME: str = os.environ.get("DB_NAME", "").strip()
DB_USER, DB_PASSWORD = resolve_db_credentials(
    os.path.basename(sys.argv[0]) if sys.argv else "", os.environ
)


def get_mysql_config() -> dict:
    """
    Validate and return MySQL connection parameters from module/env settings.
    Raises RuntimeError if any required parameter is missing.
    """
    missing = [
        name
        for name, value in (
            ("DB_HOST", DB_HOST),
            ("DB_NAME", DB_NAME),
            ("DB_USER", DB_USER),
            ("DB_PASSWORD", DB_PASSWORD),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing required MySQL environment configuration: " + ", ".join(missing)
        )
    return {
        "host": DB_HOST,
        "port": DB_PORT,
        "database": DB_NAME,
        "user": DB_USER,
        "password": DB_PASSWORD,
    }


# ---------------------------------------------------------------------------
# Least-privilege grants for the MySQL runtime user 'bank_app'
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
