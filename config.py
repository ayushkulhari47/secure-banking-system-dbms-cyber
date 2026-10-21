"""
config.py  Centralized tuneable configuration parameters for the Secure Banking System.

Design Decision (IT Audit / Compliance Perspective):
- Centralizing tuneable security parameters satisfies ISO 27001 A.12.1.1 (Operational
  procedures and responsibilities) and ITGC Change Management guidelines.
- Instead of magic numbers scattered across code, thresholds for authentication lockouts,
  transaction caps, session timeouts, and dual-control limits are auditable in one place.
"""

# ---------------------------------------------------------------------------
# Transaction Thresholds
# ---------------------------------------------------------------------------
MIN_AMOUNT: float = 0.01                # Smallest allowed currency amount (Rs)
MAX_AMOUNT: float = 1_000_000.00        # Application-layer upper cap per transaction (Rs)
LARGE_TXN_THRESHOLD: float = 50_000.00  # Transactions above this require Maker-Checker dual control

# ---------------------------------------------------------------------------
# Authentication & Access Control
# ---------------------------------------------------------------------------
MAX_FAILED_LOGINS: int = 3              # Max consecutive failed logins before account lock
MIN_PASSWORD_LENGTH: int = 8            # Password complexity minimum length
SESSION_TIMEOUT_SECONDS: int = 300      # 5 minutes session inactivity timeout

# ---------------------------------------------------------------------------
# Cryptographic Settings
# ---------------------------------------------------------------------------
BCRYPT_ROUNDS: int = 12                 # Work factor for bcrypt hashing (~250ms per hash)
