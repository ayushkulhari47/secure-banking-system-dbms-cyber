"""
bank/security.py -- Input validation, password policy, session timeout, and intrusion helpers.

Controls implemented:
  SEC-01  validate_amount()       -- rejects zero, negative, NaN, infinite
  SEC-02  safe_float_input()      -- wraps input() so bad input never crashes
  SEC-03  safe_int_input()        -- same for integers
  SEC-04  password_meets_policy() -- minimum complexity enforcement
  SEC-05  Session                 -- inactivity timeout detection
  SEC-07  detect_sqli() / check_velocity() / is_odd_hour()
"""

import math
import re
import time
from typing import Optional

from bank.config import (
    MIN_AMOUNT,
    MAX_AMOUNT,
    SESSION_TIMEOUT_SECONDS,
    MIN_PASSWORD_LENGTH,
)

# ---------------------------------------------------------------------------
# SEC-01  Amount validation
# ---------------------------------------------------------------------------


def validate_amount(amount: float) -> tuple:
    """
    Return (True, None) if amount is acceptable, or (False, reason_string).

    Rules enforced:
      - Not NaN  (float('nan') can appear via certain string coercions)
      - Not infinite
      - Greater than MIN_AMOUNT (blocks zero and negative values)
      - Not greater than MAX_AMOUNT (blocks unrealistic inputs)
    """
    if math.isnan(amount):
        return False, "Amount must be a valid number (NaN rejected)."
    if math.isinf(amount):
        return False, "Amount must be finite (infinity rejected)."
    if amount <= 0:
        return False, f"Amount must be greater than Rs0.00 (got Rs{amount:.2f})."
    if amount < MIN_AMOUNT:
        return False, f"Minimum transaction amount is Rs{MIN_AMOUNT:.2f}."
    if amount > MAX_AMOUNT:
        return False, f"Single transaction limit is Rs{MAX_AMOUNT:,.2f}."
    return True, None


# ---------------------------------------------------------------------------
# SEC-02 / SEC-03  Safe input wrappers
# ---------------------------------------------------------------------------


def safe_float_input(prompt: str) -> Optional[float]:
    """
    Display prompt, read a line, and return a float.
    Returns None if the input cannot be converted -- the caller decides
    what to do (typically print an error and return without crashing).
    """
    raw = input(prompt).strip()
    try:
        return float(raw)
    except ValueError:
        print(
            f"  [!] Invalid input: '{raw}' is not a number. Please enter a numeric value."
        )
        return None


def safe_int_input(prompt: str) -> Optional[int]:
    """
    Display prompt, read a line, and return an int.
    Returns None on non-integer input.
    """
    raw = input(prompt).strip()
    try:
        return int(raw)
    except ValueError:
        print(
            f"  [!] Invalid input: '{raw}' is not a whole number. Please enter an integer."
        )
        return None


# ---------------------------------------------------------------------------
# SEC-04  Password policy
# ---------------------------------------------------------------------------


def password_meets_policy(password: str) -> tuple:
    """
    Return (True, None) if the password satisfies the policy,
    or (False, list_of_violations).

    Policy (ISO 27001 A.9.4.3 -- password management):
      - Minimum 8 characters
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character from: !@#$%^&*()-_=+[]{}|;:',.<>?/`~
    """
    violations = []

    if len(password) < MIN_PASSWORD_LENGTH:
        violations.append(
            f"At least {MIN_PASSWORD_LENGTH} characters required "
            f"(got {len(password)})."
        )
    if not re.search(r"[A-Z]", password):
        violations.append("At least one uppercase letter required.")
    if not re.search(r"[a-z]", password):
        violations.append("At least one lowercase letter required.")
    if not re.search(r"\d", password):
        violations.append("At least one digit required.")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~]", password):
        violations.append("At least one special character required (!@#$%^&* etc.).")

    if violations:
        return False, violations
    return True, None


# ---------------------------------------------------------------------------
# SEC-05  Session inactivity timeout
# ---------------------------------------------------------------------------


class Session:
    """
    Tracks the time of the last user interaction.
    """

    def __init__(self, timeout_seconds: int = SESSION_TIMEOUT_SECONDS) -> None:
        self.timeout = timeout_seconds
        self._last_activity: float = time.monotonic()

    def refresh(self) -> None:
        """Reset the inactivity clock after any user action."""
        self._last_activity = time.monotonic()

    def is_expired(self) -> bool:
        """Return True if the session has been idle longer than the timeout."""
        return (time.monotonic() - self._last_activity) > self.timeout

    def seconds_remaining(self) -> float:
        """How many seconds remain before the session expires."""
        elapsed = time.monotonic() - self._last_activity
        return max(0.0, self.timeout - elapsed)


# ---------------------------------------------------------------------------
# SEC-07  Intrusion Detection Rules
# ---------------------------------------------------------------------------

# SQL injection payload patterns (OWASP Top 10 A03:2021 -- Injection)
_SQLI_PATTERNS = re.compile(
    r"('|\b(OR|AND)\b.*=.*|--|;|/\*|\*/|xp_|UNION\s+SELECT|"
    r"DROP\s+TABLE|INSERT\s+INTO|SELECT\s+\*|1\s*=\s*1|"
    r"SLEEP\s*\(|WAITFOR\s+DELAY|EXEC\s*\(|CAST\s*\()",
    re.IGNORECASE,
)

# Velocity: maximum transactions within a rolling window (intrusion signal)
VELOCITY_WINDOW_SECONDS: int = 60  # rolling window
VELOCITY_MAX_TRANSACTIONS: int = 10  # alert if exceeded in window


def detect_sqli(user_input: str) -> bool:
    """
    Return True if the string matches common SQL injection patterns.
    """
    return bool(_SQLI_PATTERNS.search(user_input))


def check_velocity(
    transaction_times: list,
    window_seconds: int = VELOCITY_WINDOW_SECONDS,
    max_allowed: int = VELOCITY_MAX_TRANSACTIONS,
) -> tuple:
    """
    Detect abnormally high transaction velocity (ISO 27001:2022 A.8.16).
    Returns (True, count) if velocity exceeds threshold, else (False, count).
    """
    now = time.monotonic()
    cutoff = now - window_seconds
    recent = [t for t in transaction_times if t >= cutoff]
    count = len(recent)
    if count > max_allowed:
        return True, count
    return False, count


def is_odd_hour(timestamp=None) -> bool:
    """Return True for transactions submitted during the configured quiet hours (23:00-05:59 UTC)."""
    from datetime import datetime, timezone

    moment = timestamp or datetime.now(timezone.utc)
    hour = moment.hour
    return hour >= 23 or hour < 6

