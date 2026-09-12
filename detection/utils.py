"""
detection/utils.py
==================
OTP Utilities with Attempt Limiting
=====================================

Attacks protected:
  - Credential Stuffing  : attacker can't auto-enumerate OTPs (locked after 5 wrong)
  - Phishing             : stolen password + OTP brute-force blocked by attempt limit
  - Brute Force Attack   : 6-digit OTP (1,000,000 possibilities) + 5-attempt lockout
                           = statistically impossible to crack within one OTP window

OTP Attempt Limiting logic:
  - Each wrong OTP guess increments otp_attempts in session.
  - After OTP_MAX_ATTEMPTS wrong guesses the session is locked.
  - Requesting a new OTP (resend) resets the attempt counter.
  - Successful verification resets the attempt counter.
"""

import secrets
from django.utils import timezone

# Maximum wrong OTP guesses before the session is locked.
# User must request a fresh OTP (resend) to unlock.
OTP_MAX_ATTEMPTS = 5


# ──────────────────────────────────────────────────────────────
# Generate OTP
# ──────────────────────────────────────────────────────────────
def generate_otp() -> str:
    """
    Generate a cryptographically random 6-digit OTP.
    Uses secrets.randbelow (CSPRNG) instead of random.randint
    to prevent prediction from seeded PRNG.
    """
    return str(secrets.randbelow(900000) + 100000)


# ──────────────────────────────────────────────────────────────
# Store OTP in session
# ──────────────────────────────────────────────────────────────
def set_otp_session(request, otp: str, purpose: str, user_identifier: str):
    """
    Save OTP and metadata into the server-side session.
    Resets the attempt counter so a fresh OTP starts with 5 clean attempts.
    """
    request.session['otp']          = otp
    request.session['otp_time']     = timezone.now().timestamp()
    request.session['otp_purpose']  = purpose
    request.session['otp_user']     = user_identifier
    request.session['otp_attempts'] = 0  # reset on every new OTP issuance


# ──────────────────────────────────────────────────────────────
# Verify OTP
# ──────────────────────────────────────────────────────────────
def verify_otp(request, entered_otp: str, purpose: str) -> tuple:
    """
    Verify the OTP submitted by the user.

    Returns (is_valid: bool, message: str).

    Checks (in order):
      1. Attempt limit — locked after OTP_MAX_ATTEMPTS wrong guesses.
      2. Expiry        — OTP is invalid after 2 minutes.
      3. Correctness   — constant-time comparison to prevent timing attacks.
      4. Purpose       — prevents OTP reuse across different flows
                         (e.g. using login OTP to reset password).

    On success: clears attempt counter.
    On wrong OTP: increments attempt counter.
    """
    import hmac as _hmac  # constant-time compare

    session_otp   = request.session.get("otp")
    otp_time      = request.session.get("otp_time")
    otp_purpose   = request.session.get("otp_purpose")
    otp_attempts  = request.session.get("otp_attempts", 0)

    # ── 1. Attempt limit check ─────────────────────────────────────────────
    # Attacks stopped: Credential Stuffing (OTP brute-force), Phishing
    if otp_attempts >= OTP_MAX_ATTEMPTS:
        return False, (
            f"Too many wrong OTP attempts ({OTP_MAX_ATTEMPTS}/{OTP_MAX_ATTEMPTS}). "
            "Please click 'Resend OTP' to get a new code."
        )

    # ── 2. Expiry check (2 minutes) ────────────────────────────────────────
    if not otp_time or (timezone.now().timestamp() - otp_time > 120):
        return False, "OTP expired. Please request a new OTP."

    # ── 3. Correctness check (constant-time) ───────────────────────────────
    # Using hmac.compare_digest to prevent timing-oracle attacks
    otp_match = (
        session_otp is not None
        and _hmac.compare_digest(
            str(session_otp).encode(),
            str(entered_otp).encode()
        )
    )
    if not otp_match:
        otp_attempts += 1
        request.session["otp_attempts"] = otp_attempts
        remaining = OTP_MAX_ATTEMPTS - otp_attempts
        if remaining <= 0:
            return False, (
                f"Too many wrong OTP attempts ({OTP_MAX_ATTEMPTS}/{OTP_MAX_ATTEMPTS}). "
                "Please click 'Resend OTP' to get a new code."
            )
        return False, f"Invalid OTP. {remaining} attempt(s) remaining."

    # ── 4. Purpose check ───────────────────────────────────────────────────
    if otp_purpose != purpose:
        return False, "OTP purpose mismatch. Please request a new OTP."

    # ── Success — clear attempt counter ────────────────────────────────────
    request.session["otp_attempts"] = 0
    return True, "OTP verified successfully."


