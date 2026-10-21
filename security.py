"""
security.py  Input validation, password policy, and session helpers.

All vulnerability-fix logic lives here so it can be imported by app.py
and independently unit-tested in tests/test_security_fixes.py.

Controls implemented (maps to Phase 3 control_mapping.md):
  SEC-01  validate_amount()    -- rejects zero, negative, NaN, infinite
  SEC-02  safe_float_input()   -- wraps input() so bad input never crashes
  SEC-03  safe_int_input()     -- same for integers
  SEC-04  password_meets_policy() -- minimum complexity enforcement
  SEC-05  is_session_expired() -- inactivity timeout detection
  SEC-06  self-transfer guard  -- checked in app.py using account IDs
"""

import math
import re
import time
from typing import Optional

from config import (
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

    Why this matters (interview answer):
      In the original code a negative transfer of e.g. -5000 would *add* money
      to the sender and *remove* money from the receiver -- a real money-theft
      exploit.  The DB CHECK(amount > 0) is a second line of defence but we
      reject at the application layer first so the user gets a clear error.
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

    Replaces bare float(input(...)) calls which crash on non-numeric input.
    """
    raw = input(prompt).strip()
    try:
        return float(raw)
    except ValueError:
        print(f"  [!] Invalid input: '{raw}' is not a number. Please enter a numeric value.")
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
        print(f"  [!] Invalid input: '{raw}' is not a whole number. Please enter an integer.")
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

    Note: This function is called during account creation and password change.
    Demo seeds bypass this check intentionally (they are labelled demo creds).
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

    Usage in app.py:
        session = Session()
        # in menu loop:
        if session.is_expired():
            logout()
        session.refresh()  # call after every valid action

    Why this matters:
      Without a timeout an unattended logged-in terminal is an open door.
      ISO 27001 A.9.4.2 requires automatic session termination after inactivity.
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
