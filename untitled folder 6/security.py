"""
security.py
All password-related cryptography and policy logic lives here, isolated
from the Flask routing layer (separation of concerns / defence in depth).

Algorithms & standards referenced (see report for full citations):
- Hashing: Argon2id via argon2-cffi (OWASP Password Storage Cheat Sheet,
  winner of the 2015 Password Hashing Competition).
- Strength scoring: informed by NIST SP 800-63B (favours length and
  blocklist-checking over forced complexity rules) plus entropy estimation.
- Lockout: standard brute-force mitigation (5 attempts / 15 minute cool-down).
"""

import math
import re
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

# Argon2id with explicit cost parameters (time_cost, memory_cost in KiB,
# parallelism). These are conservative defaults suitable for a web server;
# tuned to take roughly 100-300ms per hash on typical hardware.
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)


def hash_password(plain_password: str) -> str:
    """Hash a password with Argon2id. Argon2 generates and embeds a random
    salt automatically, so identical passwords never produce identical
    hashes."""
    return _ph.hash(plain_password)


def verify_password(stored_hash: str, plain_password: str) -> bool:
    try:
        _ph.verify(stored_hash, plain_password)
        return True
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """If we ever raise the cost parameters, this flags old hashes that
    should be transparently upgraded on next successful login."""
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Account lockout (brute-force protection)
# ---------------------------------------------------------------------------

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def register_failed_attempt(user):
    user.failed_attempts += 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)


def reset_failed_attempts(user):
    user.failed_attempts = 0
    user.locked_until = None


# ---------------------------------------------------------------------------
# Password strength scoring
# ---------------------------------------------------------------------------

# A small, illustrative slice of the "10k most common passwords" corpus.
# In production this would be a much larger denylist (e.g. the full
# Have I Been Pwned Pwned Passwords list checked via k-anonymity API).
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "trustno1", "superman", "qwerty123",
    "000000", "1q2w3e4r", "starwars", "freedom", "whatever",
}

MIN_LENGTH = 10


def _shannon_entropy_bits(password: str) -> float:
    """Estimate entropy in bits using pool size based on character classes
    actually used, multiplied by length (a standard simplified estimate,
    not true Shannon entropy of the string itself)."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def evaluate_password_strength(password: str, username: str = "") -> dict:
    """Returns a dict with:
        score: 0-4 (Very Weak -> Very Strong)
        label: human readable label
        percent: 0-100 for UI meter
        entropy_bits: estimated entropy
        feedback: list of actionable strings
        blocked: True if password must be rejected outright
    """
    feedback = []
    blocked = False
    pw = password or ""

    length = len(pw)
    has_lower = bool(re.search(r"[a-z]", pw))
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_digit = bool(re.search(r"[0-9]", pw))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pw))
    variety = sum([has_lower, has_upper, has_digit, has_symbol])

    # --- Hard blockers ---
    if length == 0:
        return {
            "score": 0, "label": "Empty", "percent": 0, "entropy_bits": 0,
            "feedback": ["Enter a password."], "blocked": True,
        }

    if pw.lower() in COMMON_PASSWORDS:
        blocked = True
        feedback.append("This password is in the list of most commonly breached passwords.")

    if username and username.lower() in pw.lower() and len(username) >= 3:
        blocked = True
        feedback.append("Your password must not contain your username.")

    if re.fullmatch(r"(.)\1*", pw):
        blocked = True
        feedback.append("Avoid repeating the same character.")

    if length < MIN_LENGTH:
        feedback.append(f"Use at least {MIN_LENGTH} characters (length matters more than complexity).")

    if variety < 3:
        feedback.append("Mix upper/lowercase letters, numbers and symbols.")

    # Sequential pattern check (e.g. "abcd", "1234")
    sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop"]
    pw_lower = pw.lower()
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in pw_lower:
                feedback.append("Avoid sequential characters like 'abcd' or '1234'.")
                break

    entropy = _shannon_entropy_bits(pw)

    # --- Scoring ---
    score = 0
    if not blocked:
        if length >= MIN_LENGTH:
            score += 1
        if length >= 14:
            score += 1
        if variety >= 3:
            score += 1
        if variety == 4 and length >= 12:
            score += 1
        if entropy < 28:
            score = min(score, 1)

    score = max(0, min(score, 4))

    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
    percent = int((score / 4) * 100)

    if blocked:
        score = 0
        percent = 0
        labels[0] = "Rejected"

    if not feedback and score >= 3:
        feedback.append("Good password.")

    return {
        "score": score,
        "label": labels[score],
        "percent": percent,
        "entropy_bits": round(entropy, 1),
        "feedback": feedback,
        "blocked": blocked,
    }


def is_password_acceptable(password: str, username: str = "") -> bool:
    result = evaluate_password_strength(password, username)
    return (not result["blocked"]) and result["score"] >= 2 and len(password) >= MIN_LENGTH


# ---------------------------------------------------------------------------
# Email OTP (alternative second factor to TOTP)
# ---------------------------------------------------------------------------

import hashlib
import secrets as _secrets

EMAIL_OTP_LENGTH = 6
EMAIL_OTP_VALID_MINUTES = 10
EMAIL_OTP_RESEND_COOLDOWN_SECONDS = 30
EMAIL_OTP_MAX_ATTEMPTS = 5


def generate_email_otp() -> str:
    """Cryptographically-random 6-digit numeric code (zero-padded)."""
    return f"{_secrets.randbelow(10 ** EMAIL_OTP_LENGTH):0{EMAIL_OTP_LENGTH}d}"


def hash_email_otp(code: str) -> str:
    """We only ever persist a hash of the OTP, never the plaintext. The code
    is short-lived (EMAIL_OTP_VALID_MINUTES) and attempt-limited
    (EMAIL_OTP_MAX_ATTEMPTS), so a fast hash is an acceptable trade-off here
    (unlike long-lived passwords, which use Argon2id above)."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def verify_email_otp(stored_hash: str, submitted_code: str) -> bool:
    if not stored_hash or not submitted_code:
        return False
    return _secrets.compare_digest(stored_hash, hash_email_otp(submitted_code))
