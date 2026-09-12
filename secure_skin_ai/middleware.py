"""
secure_skin_ai/middleware.py
============================
Custom Security Middleware
==========================

Middleware 1 — SecurityHeadersMiddleware
  Injects HTTP response headers that instruct the browser to enforce
  additional protections. Covers attacks not handled by Django defaults.

  Headers added:
    Content-Security-Policy  → XSS, Malware, Fileless Malware, Tracking Pixel
    Strict-Transport-Security→ MitM, SSL stripping, Zero-Day downgrade
    Permissions-Policy       → Tracking Pixel, camera/mic fingerprinting
    Cross-Origin-Opener-Policy  → Supply Chain / cross-origin data leakage
    Cross-Origin-Resource-Policy→ Supply Chain / cross-origin data leakage

Middleware 2 — GlobalRateLimitMiddleware
  Per-IP request rate limiting applied to ALL endpoints.
  Complements the existing per-user decrypt rate limiter (CM3 in security.py).
  Uses Django's cache framework.

  Attacks stopped:
    DDoS              → flood of requests from single IP blocked at 200 req/min
    Brute Force       → secondary layer over session-based lockout in views.py
    Password Spraying → IP-level throttling across multiple usernames
    API Attack        → all API endpoints covered, not just /decrypt/
"""

import time

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse


# ============================================================================
# MIDDLEWARE 1 — SECURITY HEADERS
# Attacks stopped: XSS, Malware, Fileless Malware, MitM, Zero-Day,
#                  Tracking Pixel, Supply Chain
# ============================================================================

class SecurityHeadersMiddleware:
    """
    Add security response headers on every HTTP response.

    These are browser-enforced protections — the server tells the browser
    what it is allowed to load, execute, and transmit.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # ── Content Security Policy (CSP) ──────────────────────────────────
        # Stops: XSS payload execution, Malware script injection,
        #        Fileless Malware via eval/blob, Tracking Pixel iframes
        #
        # 'unsafe-inline' kept for script-src because Django templates use
        # inline <script> blocks. Replace with nonce/hash in production for
        # stricter enforcement.
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            # Scripts: self + CDN (Bootstrap JS, etc.)
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            # Styles: self + all CDNs used by templates
            "style-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com; "
            # Fonts: Google Fonts + Font Awesome + Bootstrap Icons
            "font-src 'self' "
            "https://fonts.gstatic.com "
            "https://cdnjs.cloudflare.com "
            "https://cdn.jsdelivr.net; "
            # Images: self + data URIs (QR codes, inline images)
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none';"
        )

        # ── Strict-Transport-Security (HSTS) ──────────────────────────────
        # Stops: MitM, SSL stripping, Zero-Day TLS downgrade attacks
        # Only sent when HTTPS is active (SECURE_SSL_REDIRECT = True in prod).
        # max-age=31536000 = 1 year; browser refuses HTTP connections for 1 year.
        if getattr(settings, 'SECURE_SSL_REDIRECT', False):
            response['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains; preload'
            )

        # ── Permissions-Policy ────────────────────────────────────────────
        # Stops: Tracking Pixel attacks, fingerprinting via camera/mic/geolocation
        # interest-cohort=() disables Google FLoC tracking.
        # payment=(self) allows Razorpay only on our own origin.
        response['Permissions-Policy'] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=(), "
            "interest-cohort=(), "
            "payment=(self), "
            "usb=(), "
            "screen-wake-lock=()"
        )

        # ── Cross-Origin Policies ─────────────────────────────────────────
        # Stops: Cross-origin data leakage, Supply Chain isolation
        # same-origin = only this site's documents/resources can embed us.
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Resource-Policy'] = 'same-origin'

        return response


# ============================================================================
# MIDDLEWARE 2 — GLOBAL IP RATE LIMITER
# Attacks stopped: DDoS, Brute Force (IP layer), Password Spraying, API Attack
# ============================================================================

# Default limit: 200 requests/minute per IP.
# Override via settings.GLOBAL_RATE_LIMIT_PER_MINUTE
_RATE_LIMIT = None
_RATE_WINDOW = 60  # seconds

# These path prefixes are excluded from rate limiting (they are static assets)
_EXEMPT_PREFIXES = ('/static/', '/media/')


def _get_limit():
    """Lazy-load limit from settings (settings not ready at import time)."""
    global _RATE_LIMIT
    if _RATE_LIMIT is None:
        _RATE_LIMIT = getattr(settings, 'GLOBAL_RATE_LIMIT_PER_MINUTE', 200)
    return _RATE_LIMIT


class GlobalRateLimitMiddleware:
    """
    Per-IP rate limiter applied to all non-static HTTP endpoints.

    Algorithm: sliding window counter stored in Django's cache backend.
    Each IP gets a counter entry. Counter resets every 60 seconds.
    Requests exceeding the limit get HTTP 429 without reaching any view.

    In development: uses LocMemCache (in-process, resets on restart).
    In production: wire to Redis via CACHES in settings for persistence.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip static / media files — no need to throttle asset downloads
        if any(request.path.startswith(p) for p in _EXEMPT_PREFIXES):
            return self.get_response(request)

        ip = self._get_client_ip(request)
        if ip and not self._is_allowed(ip):
            limit = _get_limit()
            return HttpResponse(
                f"[DDoS Protection] Too many requests from your IP.\n"
                f"Maximum {limit} requests per minute allowed.\n"
                f"Please wait 60 seconds before retrying.",
                status=429,
                content_type='text/plain',
            )

        return self.get_response(request)

    @staticmethod
    def _get_client_ip(request) -> str:
        """
        Extract real client IP. X-Forwarded-For is only trusted when
        settings.TRUST_PROXY_HEADERS is True (app behind known reverse proxy);
        otherwise the header can be spoofed to dodge rate limits.
        """
        if getattr(settings, 'TRUST_PROXY_HEADERS', False):
            forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
            if forwarded:
                return forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    @staticmethod
    def _is_allowed(ip: str) -> bool:
        """
        Return True if this IP is under the rate limit, False if exceeded.
        Sliding window: resets the counter when 60s have elapsed.
        """
        limit = _get_limit()
        cache_key = f'_global_rl_{ip}'
        now = time.time()

        entry = cache.get(cache_key)

        if entry is None:
            # First request from this IP in this window
            cache.set(cache_key, [1, now], timeout=_RATE_WINDOW + 10)
            return True

        count, window_start = entry

        if now - window_start > _RATE_WINDOW:
            # Window expired — start a fresh window
            cache.set(cache_key, [1, now], timeout=_RATE_WINDOW + 10)
            return True

        if count >= limit:
            # Limit exceeded within current window
            return False

        # Increment counter within current window
        cache.set(cache_key, [count + 1, window_start], timeout=_RATE_WINDOW + 10)
        return True
