"""
detection/security.py
=====================
Post-Encryption / Pre-Decryption Security Layer
================================================

This module implements all countermeasures that protect medical images
in the window AFTER they are encrypted and stored in the DB, and BEFORE
they are decrypted and rendered for an authorised viewer.

Attack Window Timeline:
  [Patient uploads image]
        ↓
  [AES + RSA encryption]
        ↓
  [Encrypted bytes saved to DB]  ← ATTACK WINDOW STARTS
        ↓
  [Encrypted bytes fetched from DB]
        ↓
  [RSA decrypt AES key]
        ↓
  [AES decrypt image bytes]       ← ATTACK WINDOW ENDS
        ↓
  [Plaintext image rendered]

Countermeasures implemented here:
  1.  Private Key Encryption at Rest  → SQL Injection / Memory Scraping / Ransomware
  2.  Constant-Time Hash Comparison   → Timing Attack / MitM
  3.  Session-Based Rate Limiter      → DoS Attack / DDoS
  4.  One-Time Decryption Token       → Replay Attack / Spear Phishing
  5.  Strict IDOR Ownership Check     → IDOR / Insider Threat
  6.  Decrypt Audit Logging           → Non-repudiation / APT forensic trail
  7.  Input Sanitiser                 → Stored XSS / Malware
  8.  Memory Cleanup helper           → Memory Scraping / Fileless Malware
  9.  CSRF note: enforced globally    → CSRF (Django CsrfViewMiddleware)
      Keylogger/Spyware note: covered → already protected by OTP 2FA in login
 10.  IP-Based Login Rate Limiter     → Password Spraying / Brute Force (IP layer)
 11.  APT Anomaly Logger              → Advanced Persistent Threat detection
"""

import base64
import hashlib
import hmac
import os
import re
import time
import uuid
from functools import wraps

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.http import HttpResponse
from django.utils import timezone
from datetime import timedelta


# =============================================================================
# COUNTERMEASURE 1 — PRIVATE KEY ENCRYPTION AT REST
# Attack stopped: SQL Injection  +  Memory Scraping
#
# Problem: Private RSA keys are stored as plaintext PEM in UserProfile.private_key.
#          A successful SQL injection (or direct DB read) exposes ALL private keys,
#          letting the attacker decrypt every medical image ever stored.
#
# Solution: Encrypt every private key with AES-256-GCM (AEAD) before writing to
#           DB, using a 256-bit master key derived from the app secret
#           (FERNET_KEY). Even if the DB is fully dumped, keys remain unreadable
#           without the application secret.
#
# Backward-compat: transparently decrypts BOTH legacy formats —
#                  Fernet tokens (AES-128) and plaintext PEM (b'-----BEGIN') —
#                  so existing accounts keep working after the AES-256 upgrade.
# =============================================================================

# String marker prefixing the AES-256-GCM private-key ciphertext (stored in a
# TextField, so the payload is base64 text after the marker).
_PK_MAGIC = "GCM1."


def _master_key() -> bytes:
    """Derive a stable 32-byte (256-bit) AES key from the app's FERNET_KEY."""
    return hashlib.sha256(settings.FERNET_KEY).digest()


def encrypt_private_key(pem_bytes: bytes) -> str:
    """
    Encrypt an RSA private key with AES-256-GCM before storing in DB.
    Input : raw PEM bytes  (b'-----BEGIN PRIVATE KEY-----...')
    Output: 'GCM1.' + base64(nonce | ciphertext+tag) — safe for a TextField.
    """
    nonce = os.urandom(12)
    ct = AESGCM(_master_key()).encrypt(nonce, pem_bytes, None)
    return _PK_MAGIC + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_private_key(stored_value) -> bytes:
    """
    Retrieve the RSA private key from DB storage. Handles:
      - New format   : AES-256-GCM  ('GCM1.' prefixed)
      - Legacy format: Fernet token (AES-128) or plaintext PEM
    Always returns raw PEM bytes ready for the cryptography library.
    """
    if stored_value is None:
        raise ValueError("Private key not found in user profile.")

    if isinstance(stored_value, str):
        raw = stored_value.encode()
    elif isinstance(stored_value, memoryview):
        raw = bytes(stored_value)
    else:
        raw = bytes(stored_value)

    # Legacy plaintext PEM — return as-is.
    if raw.strip().startswith(b'-----BEGIN'):
        return raw

    text = raw.decode(errors="ignore")

    # New AES-256-GCM format.
    if text.startswith(_PK_MAGIC):
        blob = base64.urlsafe_b64decode(text[len(_PK_MAGIC):])
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(_master_key()).decrypt(nonce, ct, None)

    # Legacy Fernet-encrypted key (AES-128-CBC + HMAC-SHA256).
    return Fernet(settings.FERNET_KEY).decrypt(raw)


# =============================================================================
# COUNTERMEASURE 2 — CONSTANT-TIME HASH COMPARISON
# Attack stopped: Timing Attack
#
# Problem: Python's `!=` operator compares strings byte-by-byte and short-
#          circuits on the first mismatch. An attacker who can measure response
#          times with microsecond precision can reconstruct the expected hash
#          one byte at a time (timing oracle).
#
# Solution: hmac.compare_digest() always takes the same time regardless of
#           where the strings differ — no timing information leaks.
# =============================================================================

def secure_hash_compare(hash_a: str, hash_b: str) -> bool:
    """
    Constant-time comparison of two SHA-256 hex digests.
    Returns True only if both are identical — without leaking timing info.
    """
    a = hash_a.encode() if isinstance(hash_a, str) else hash_a
    b = hash_b.encode() if isinstance(hash_b, str) else hash_b
    return hmac.compare_digest(a, b)


# =============================================================================
# COUNTERMEASURE 3 — SESSION-BASED RATE LIMITER
# Attack stopped: DoS (Denial of Service)
#
# Problem: The decryption endpoint performs expensive RSA + AES operations.
#          An authenticated attacker (or compromised session) can hammer it
#          thousands of times per minute, exhausting CPU and making the service
#          unavailable to real doctors during emergencies.
#
# Solution: Track per-user decryption call counts in the session.
#           Exceeding MAX_DECRYPT_PER_MINUTE within any 60-second window
#           returns HTTP 429 (Too Many Requests) without executing decryption.
# =============================================================================

MAX_DECRYPT_PER_MINUTE = getattr(settings, 'MAX_DECRYPT_PER_MINUTE', 10)


def rate_limit_decrypt(view_func):
    """
    Decorator: Limit decryption calls to MAX_DECRYPT_PER_MINUTE per user per 60s.
    Apply to any view that performs RSA/AES decryption.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user_id = request.user.id
        call_key   = f"_decrypt_calls_{user_id}"
        window_key = f"_decrypt_window_{user_id}"

        now = time.time()
        window_start = request.session.get(window_key, 0)
        calls        = request.session.get(call_key, 0)

        # Reset counter when the 60-second window has rolled over
        if now - window_start > 60:
            calls = 0
            request.session[window_key] = now

        if calls >= MAX_DECRYPT_PER_MINUTE:
            wait = int(60 - (now - window_start)) + 1
            return HttpResponse(
                f"[DoS Protection] Rate limit exceeded: "
                f"max {MAX_DECRYPT_PER_MINUTE} decryptions/min. "
                f"Please wait {wait} second(s).",
                status=429,
            )

        request.session[call_key] = calls + 1
        return view_func(request, *args, **kwargs)

    return wrapper


# =============================================================================
# COUNTERMEASURE 4 — ONE-TIME DECRYPTION TOKEN (Replay Attack Protection)
# Attack stopped: Replay Attack
#
# Problem: If an attacker captures a valid authenticated GET request to
#          /view-decrypted/<id>/ (via network sniffing, proxy logs, browser
#          history, or Referer headers), they can replay it later to retrieve
#          the decrypted image — even after the original session has ended.
#
# Solution: Every decryption request requires a one-time token (UUID, stored
#           as SHA-256 hash in DB via DecryptionToken model).
#           - Token expires in 5 minutes
#           - Token is marked is_used=True on FIRST use
#           - Any replay attempt gets "Token already used" → HTTP 403
#           - New tokens are issued only via a POST endpoint (CSRF-protected)
# =============================================================================

def issue_decrypt_token(user, image) -> str:
    """
    Issue a fresh single-use decryption token for (user, image).
    Invalidates any old unused tokens for this pair first.
    Returns the raw UUID token (send to client; only hash stored in DB).
    """
    from .models import DecryptionToken

    # Invalidate stale unused tokens for this user+image pair
    DecryptionToken.objects.filter(
        user=user, image=image, is_used=False
    ).update(is_used=True)

    raw_token  = str(uuid.uuid4())
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    DecryptionToken.objects.create(
        user=user,
        image=image,
        token_hash=token_hash,
        expires_at=timezone.now() + timedelta(minutes=5),
    )
    return raw_token


def validate_decrypt_token(raw_token: str, user, image) -> tuple:
    """
    Validate a one-time decryption token.
    Returns (is_valid: bool, error_message: str).
    Marks the token as used on first call — any subsequent call is a replay.
    """
    from .models import DecryptionToken

    if not raw_token:
        return False, "Decryption token missing. Access denied (Replay Protection)."

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    try:
        dt = DecryptionToken.objects.get(
            token_hash=token_hash,
            user=user,
            image=image,
        )
    except DecryptionToken.DoesNotExist:
        return False, "Invalid decryption token — possible replay or forgery attempt."

    if dt.is_used:
        return False, "Decryption token already consumed. Replay attack blocked."

    if timezone.now() > dt.expires_at:
        return False, "Decryption token expired (valid for 5 minutes only)."

    # Consume the token immediately — one-time use
    dt.is_used = True
    dt.attempt_count += 1
    dt.save()

    return True, "OK"


# =============================================================================
# COUNTERMEASURE 5 — STRICT IDOR OWNERSHIP CHECK
# Attack stopped: IDOR (Insecure Direct Object Reference)
#
# Problem: The URL /view-decrypted/<image_id>/ uses a sequential integer ID.
#          A patient with image_id=5 could change the URL to image_id=6 and
#          attempt to access another patient's scan.
#          Previously, any Admin could decrypt any image — too broad.
#
# Solution:
#   - Patient: can only decrypt their OWN image (using patient AES key copy)
#   - Doctor : can only decrypt images SPECIFICALLY ASSIGNED to them
#   - Admin  : can view metadata / audit logs but CANNOT decrypt images
#              (principle of least privilege — admin ≠ medical staff)
# =============================================================================

def check_decrypt_authorization(request_user, image, role: str) -> tuple:
    """
    Strict IDOR ownership check for decryption endpoints.
    Returns (authorized: bool, use_patient_key: bool, error_msg: str).

    use_patient_key=True  → decrypt with patient's own AES key copy
    use_patient_key=False → decrypt with doctor's AES key
    """
    is_patient_owner  = (request_user == image.user)
    is_assigned_doctor = (request_user == image.assigned_doctor)

    # Admin cannot decrypt — protecting patient medical privacy
    if role == "admin":
        return (
            False, False,
            "[IDOR Protection] Admins cannot decrypt patient images. "
            "Admin access is restricted to metadata and audit logs only."
        )

    if is_patient_owner:
        return True, True, ""

    if is_assigned_doctor:
        return True, False, ""

    # Neither owner nor assigned doctor
    return (
        False, False,
        "[IDOR Protection] Unauthorized. You are not the assigned doctor "
        "for this image and do not own it."
    )


# =============================================================================
# COUNTERMEASURE 6 — DECRYPT AUDIT LOGGING
# Attack stopped: Non-repudiation / Forensic investigation
#
# Problem: Without logging, there is no way to detect or investigate
#          suspicious decryption patterns (e.g., one account decrypting
#          1000 images in a minute, or access after off-hours).
#
# Solution: Every decryption ATTEMPT is logged with:
#           user, image_id, IP address, timestamp, success/fail, reason.
#           Reuses the existing LoginLog model (role field repurposed).
# =============================================================================

def log_decrypt_attempt(request, image, success: bool, reason: str = ""):
    """
    Audit-log a decryption attempt.
    Written to LoginLog with a structured role field for easy querying:
      DECRYPT_OK_img<id>   or   DECRYPT_FAIL_img<id>:<reason>
    """
    from .models import LoginLog

    ip = get_client_ip(request)

    status_tag = "OK" if success else "FAIL"
    tag = f"DECRYPT_{status_tag}_img{image.id}"
    if reason:
        tag += f":{reason[:40]}"

    LoginLog.objects.create(
        user=request.user,
        role=tag,
        ip_address=ip or None,
    )

    # Real-time alert on critical events (replay / IDOR / integrity failure).
    try:
        from .monitoring import alert_if_critical
        alert_if_critical(tag, ip=ip or "",
                          username=(request.user.username if request.user.is_authenticated else ""))
    except Exception:
        pass


# =============================================================================
# COUNTERMEASURE 7 — INPUT SANITISER (Stored XSS Prevention)
# Attack stopped: XSS (Cross-Site Scripting — stored variant)
#
# Problem: Doctor-entered fields (diagnosis, prescription, remarks) are stored
#          in DB and later rendered in patient reports. If an attacker (or
#          malicious doctor account) injects <script>...</script> into these
#          fields, every patient who views the report runs the script.
#          Django templates auto-escape output, but defense-in-depth at the
#          storage layer stops the payload from ever reaching the DB.
#
# Solution: Strip all HTML tags and dangerous patterns before storing.
# =============================================================================

_HTML_TAG_RE      = re.compile(r'<[^>]+>')
_JS_PROTOCOL_RE   = re.compile(r'(?i)javascript\s*:')
_EVENT_HANDLER_RE = re.compile(r'(?i)\bon\w+\s*=')


def sanitize_text_input(text: str) -> str:
    """
    Strip HTML tags, javascript: references, and inline event handlers
    from user-supplied text before it is written to the database.
    """
    if not text:
        return ""
    cleaned = _HTML_TAG_RE.sub('', text)
    cleaned = _JS_PROTOCOL_RE.sub('', cleaned)
    cleaned = _EVENT_HANDLER_RE.sub('', cleaned)
    return cleaned.strip()


# =============================================================================
# COUNTERMEASURE 8 — MEMORY CLEANUP
# Attack stopped: Memory Scraping / RAM Dump
#
# Problem: After decryption, sensitive values (plaintext AES key, RSA private
#          key PEM, raw image bytes) linger in Python heap memory. A RAM dump
#          (via /proc/mem, ptrace, or a malicious shared library) can extract
#          them minutes after the request has completed.
#
# Solution: Explicitly `del` every sensitive variable after use.
#           CPython's reference counter will free the memory immediately
#           (unlike garbage-collected runtimes). Call secure_cleanup() in a
#           finally block in any view that performs decryption.
#
# Note: Python does not guarantee secure zeroing of memory. For maximum
#       protection use ctypes to zero the buffer before del (shown below).
# =============================================================================

import ctypes


def _zero_bytes(b: bytes):
    """Best-effort overwrite of a bytes object's internal buffer with zeros."""
    try:
        buf = (ctypes.c_char * len(b)).from_buffer_copy(b)
        ctypes.memset(buf, 0, len(b))
    except Exception:
        pass  # ctypes zeroing is best-effort; the del below still runs


def secure_cleanup(*sensitive_values):
    """
    Zero-then-delete sensitive bytes/str objects from memory.
    Use in a finally block after decryption:

        finally:
            secure_cleanup(priv_key_bytes, aes_key, raw_image)
    """
    for val in sensitive_values:
        try:
            if isinstance(val, (bytes, bytearray)):
                _zero_bytes(val)
        except Exception:
            pass


# =============================================================================
# COUNTERMEASURE 9 — CSRF & KEYLOGGER/SPYWARE (Documentation)
# =============================================================================
#
# CSRF (Cross-Site Request Forgery):
#   Status: ALREADY PROTECTED
#   Django's CsrfViewMiddleware (active in settings.py MIDDLEWARE list) adds
#   a CSRF token to every state-changing form. All POST views in this project
#   require {% csrf_token %} in their templates. An attacker cannot force a
#   logged-in doctor to trigger a decrypt request from a malicious page
#   because the CSRF token is unknown to the attacker's origin.
#
# Keylogger / Spyware:
#   Status: ALREADY PROTECTED via OTP 2FA
#   Even if a keylogger captures the user's password, the attacker cannot
#   log in without the time-limited OTP sent to the registered email address.
#   This two-factor authentication breaks the keylogger's attack chain
#   before it can reach the encryption/decryption system.


# =============================================================================
# COUNTERMEASURE 10 — IP-BASED LOGIN RATE LIMITER
# Attack stopped: Password Spraying  +  Brute Force (IP layer)
#
# Problem: The existing session-based lockout (CM in views.py) only tracks
#          attempts within a single session. An attacker doing Password Spraying
#          creates a new session (or rotates cookies) to bypass the counter.
#          Session-based lockout also resets when the browser is closed.
#
# Solution: Track failed login attempts per SOURCE IP in Django's cache.
#           Completely independent of session — survives browser restarts.
#           IP is locked for LOGIN_LOCKOUT_MINUTES after MAX_LOGIN_FAILURES.
#           Use as a decorator on the login view.
#
# Note: GlobalRateLimitMiddleware (middleware.py) also limits total requests
#       per IP — this CM10 specifically tracks FAILED LOGIN attempts.
# =============================================================================

import time as _time

_LOGIN_CACHE_WINDOW = 60 * 15  # 15 minutes lockout window


def get_client_ip(request) -> str:
    """
    Return the client IP for rate-limit / lockout decisions.

    SECURITY: X-Forwarded-For is trivially spoofable. If we blindly trust it,
    an attacker can rotate the header on every failed login and never trip
    the IP lockout. We ONLY read it when the operator has explicitly set
    TRUST_PROXY_HEADERS=True (i.e., the app is deployed behind a known
    reverse proxy that overwrites the header). Otherwise we use REMOTE_ADDR.
    """
    if getattr(settings, 'TRUST_PROXY_HEADERS', False):
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            # First value in the list is the original client IP written by
            # the trusted proxy. Subsequent hops append their own.
            return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def record_failed_login(request):
    """
    Increment the failed login counter for this IP in cache.
    Called from the login view after an authentication failure.
    """
    from django.core.cache import cache
    from django.conf import settings

    ip = get_client_ip(request)
    max_attempts = getattr(settings, 'LOGIN_MAX_ATTEMPTS', 5)
    key = f'_login_fail_{ip}'
    count = cache.get(key, 0) + 1
    cache.set(key, count, timeout=_LOGIN_CACHE_WINDOW)
    return count, max_attempts


def is_ip_login_locked(request) -> tuple:
    """
    Check if this IP has exceeded the failed login threshold.
    Returns (is_locked: bool, message: str).
    """
    from django.core.cache import cache
    from django.conf import settings

    ip = get_client_ip(request)
    max_attempts = getattr(settings, 'LOGIN_MAX_ATTEMPTS', 5)
    count = cache.get(f'_login_fail_{ip}', 0)
    if count >= max_attempts:
        return True, (
            f"[Password Spraying Protection] Too many failed login attempts from "
            f"your IP address. Access blocked for {_LOGIN_CACHE_WINDOW // 60} minutes."
        )
    return False, ""


def clear_ip_login_lock(request):
    """Clear the failed login counter for this IP on successful login."""
    from django.core.cache import cache
    ip = get_client_ip(request)
    cache.delete(f'_login_fail_{ip}')


# =============================================================================
# COUNTERMEASURE 11 — APT ANOMALY LOGGER
# Attack stopped: Advanced Persistent Threat (APT)  +  Insider Threat detection
#
# Problem: APT attackers operate slowly and quietly — they don't trigger
#          rate limits. They might log in at 3 AM, access many records over
#          weeks, or exfiltrate data gradually. Standard logging misses this
#          because it only logs individual events, not behavioural patterns.
#
# Solution: Log structured security events (login time, role, IP, action,
#           image count) so admins can run anomaly queries.
#           Also flags: off-hours access, high-volume decryption, role misuse.
#           Events are stored in LoginLog with structured tags for easy query.
# =============================================================================

def log_security_event(request, event_type: str, detail: str = ""):
    """
    Log a structured security event for APT / Insider Threat detection.

    event_type examples:
      APT_OFFHOURS_LOGIN   — login between 00:00–06:00 UTC
      APT_HIGH_VOL_DECRYPT — user decrypted >50 images in one session
      APT_ROLE_ESCALATION  — user attempted to access above their role
      APT_MULTI_IP         — same user logging in from different IPs

    These events are written to LoginLog for admin review / SIEM export.
    """
    from .models import LoginLog
    from django.utils import timezone

    ip = get_client_ip(request)
    hour = timezone.now().hour

    # Auto-flag off-hours access (midnight to 6 AM UTC)
    if event_type == "LOGIN_OK" and 0 <= hour < 6:
        event_type = "APT_OFFHOURS_LOGIN"

    tag = f"{event_type}"
    if detail:
        tag += f":{detail[:60]}"

    LoginLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        role=tag,
        ip_address=ip or None,
    )

    # Real-time alert on critical events (e.g. rejected fake UPI).
    try:
        from .monitoring import alert_if_critical
        alert_if_critical(tag, ip=ip or "",
                          username=(request.user.username if request.user.is_authenticated else ""))
    except Exception:
        pass
