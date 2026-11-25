"""
bank/security.py -- Input validation, password policy, session timeout, and intrusion helpers.

Controls implemented:
  SEC-01  validate_amount() / to_decimal() -- Decimal monetary validation
  SEC-02  safe_decimal_input() / safe_float_input() -- safe numeric CLI wrappers
  SEC-03  safe_int_input()        -- safe integer CLI wrapper
  SEC-04  password_meets_policy() -- minimum complexity enforcement
  SEC-05  Session                 -- inactivity timeout detection
  SEC-07  detect_sqli() / check_velocity() / is_odd_hour()
"""

from decimal import Decimal, InvalidOperation
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

MONEY_QUANTIZER = Decimal("0.01")

# ---------------------------------------------------------------------------
# SEC-01  Decimal conversion and amount validation
# ---------------------------------------------------------------------------


def parse_money_input(amount) -> Decimal:
    """
    Convert a user/caller monetary value to Decimal without silent rounding.

    Rejects booleans, None, non-numeric strings, NaN, Infinity, and unsupported types.
    Raises ValueError on invalid input.
    """
    if isinstance(amount, bool) or amount is None:
        raise ValueError("Amount must be a valid numeric value.")

    if isinstance(amount, Decimal):
        dec = amount
    elif isinstance(amount, int):
        dec = Decimal(amount)
    elif isinstance(amount, float):
        if math.isnan(amount):
            raise ValueError("Amount must be a valid number (NaN rejected).")
        if math.isinf(amount):
            raise ValueError("Amount must be finite (infinity rejected).")
        dec = Decimal(str(amount))
    elif isinstance(amount, str):
        stripped = amount.strip()
        if not stripped:
            raise ValueError("Amount must be a valid number.")
        try:
            dec = Decimal(stripped)
        except InvalidOperation as exc:
            raise ValueError("Amount must be a valid number.") from exc
    else:
        raise ValueError("Amount must be a valid numeric value.")

    if dec.is_nan():
        raise ValueError("Amount must be a valid number (NaN rejected).")
    if dec.is_infinite():
        raise ValueError("Amount must be finite (infinity rejected).")
    return dec


def db_to_decimal(value) -> Decimal:
    """
    Safely convert a monetary value fetched from the database to Decimal('0.01').
    Rejects non-numeric, non-finite, or over-precise values.
    """
    dec = parse_money_input(value)
    exp = dec.as_tuple().exponent
    if isinstance(exp, int) and exp < -2:
        raise ValueError(
            f"Database monetary value cannot exceed two decimal places: {value!r}"
        )
    return dec.quantize(MONEY_QUANTIZER)


def validate_amount(amount) -> tuple:
    """
    Return (True, None) if amount is an acceptable monetary value,
    or (False, reason_string).

    Rules enforced:
      - Numeric (Decimal, int, finite float, or numeric string; rejects bool/invalid str)
      - Not NaN or infinite
      - No more than two decimal places (never silently rounded)
      - Strictly positive and >= MIN_AMOUNT (0.01)
      - <= MAX_AMOUNT (1,000,000.00)
    """
    try:
        dec = parse_money_input(amount)
    except ValueError as exc:
        return False, str(exc)

    exp = dec.as_tuple().exponent
    if isinstance(exp, int) and exp < -2:
        return False, "Amount cannot have more than two decimal places."
    if dec <= Decimal("0"):
        return False, f"Amount must be greater than Rs0.00 (got Rs{dec:.2f})."
    if dec < MIN_AMOUNT:
        return False, f"Minimum transaction amount is Rs{MIN_AMOUNT:.2f}."
    if dec > MAX_AMOUNT:
        return False, f"Single transaction limit is Rs{MAX_AMOUNT:,.2f}."
    return True, None


# ---------------------------------------------------------------------------
# SEC-02 / SEC-03  Safe input wrappers
# ---------------------------------------------------------------------------


def safe_decimal_input(prompt: str) -> Optional[Decimal]:
    """
    Display prompt, read a line, and return a Decimal without silent rounding.
    Returns None if the input is not a valid finite decimal number.
    """
    raw = input(prompt).strip()
    try:
        dec = parse_money_input(raw)
        return dec
    except ValueError:
        print(
            f"  [!] Invalid input: '{raw}' is not a valid number. Please enter a numeric value."
        )
        return None


def safe_float_input(prompt: str) -> Optional[float]:
    """
    Display prompt, read a line, and return a float.
    Kept for backward compatibility; monetary flows should use safe_decimal_input().
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
    """Tracks the time of the last user interaction."""

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

_SQLI_PATTERNS = re.compile(
    r"('|\b(OR|AND)\b.*=.*|--|;|/\*|\*/|xp_|UNION\s+SELECT|"
    r"DROP\s+TABLE|INSERT\s+INTO|SELECT\s+\*|1\s*=\s*1|"
    r"SLEEP\s*\(|WAITFOR\s+DELAY|EXEC\s*\(|CAST\s*\()",
    re.IGNORECASE,
)

VELOCITY_WINDOW_SECONDS: int = 60
VELOCITY_MAX_TRANSACTIONS: int = 10


def detect_sqli(user_input: str) -> bool:
    """Return True if the string matches common SQL injection patterns."""
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
