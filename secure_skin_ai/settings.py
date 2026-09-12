from pathlib import Path
import os
from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

# ============================================
# BASE DIR
# ============================================
BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================
# LOAD ENVIRONMENT VARIABLES FROM .env
# ============================================
# Attacks protected:
#   - Cloud Misconfiguration  (secrets not hardcoded in source)
#   - Supply Chain Attack     (keys not visible in version control)
#   - Insider Threat          (developer cannot read prod secrets from repo)
load_dotenv(BASE_DIR / '.env')

# ============================================
# SECURITY — SAFE-BY-DEFAULT
# ============================================
# DEBUG defaults to False. Set DEBUG=True in a local .env for development.
DEBUG = os.environ.get('DEBUG', 'False') == 'True'

# SECRET_KEY is REQUIRED in production. A dev-only fallback is used only when
# DEBUG is True so `manage.py` works out of the box on a fresh clone.
SECRET_KEY = os.environ.get('SECRET_KEY', '')
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = 'django-insecure-dev-only-do-not-use-in-production'
    else:
        raise ImproperlyConfigured(
            "SECRET_KEY environment variable must be set when DEBUG=False. "
            "Generate one with: python -c 'from django.core.management.utils "
            "import get_random_secret_key; print(get_random_secret_key())'"
        )

# ALLOWED_HOSTS: no wildcard default — must be set explicitly in production.
# In DEBUG mode allow localhost so `runserver` works without extra config.
_hosts_env = os.environ.get('ALLOWED_HOSTS', '').strip()
if _hosts_env:
    ALLOWED_HOSTS = [h.strip() for h in _hosts_env.split(',') if h.strip()]
elif DEBUG:
    ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver']
else:
    raise ImproperlyConfigured(
        "ALLOWED_HOSTS must be set in production (comma-separated hostnames)."
    )

# ============================================
# ATTACK-SIMULATOR GATE
# ============================================
# The /attack/* routes (ransomware, spyware, trojan-upload, keylogger sink)
# are destructive by design and MUST NOT be reachable in production.
# Views raise Http404 unless this flag is explicitly True.
ATTACK_DEMO_ENABLED = os.environ.get('ATTACK_DEMO_ENABLED', 'False') == 'True'

# ============================================
# REVERSE-PROXY / X-FORWARDED-FOR HANDLING
# ============================================
# Client-IP-based rate limiting (login lockout, DDoS shield) reads
# HTTP_X_FORWARDED_FOR. That header is trivially spoofable if the app is
# reachable directly. Only trust it when the app sits behind a known reverse
# proxy (Render/NGINX/Cloudflare/etc.). Off by default.
TRUST_PROXY_HEADERS = os.environ.get('TRUST_PROXY_HEADERS', 'False') == 'True'
if TRUST_PROXY_HEADERS:
    # Django will treat the request as HTTPS when the upstream proxy sets
    # X-Forwarded-Proto: https — needed for SECURE_SSL_REDIRECT to work.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ============================================
# ENCRYPTION KEY (app master secret)
# ============================================
# Protects RSA private keys stored in DB (CM1 in detection/security.py).
# New records use AES-256-GCM with a 256-bit key derived (SHA-256) from this
# secret; legacy Fernet(AES-128) records are still decrypted transparently.
# REQUIRED in production — an empty key silently makes decryption crash for
# every legitimate user AND leaves fresh registrations with unencrypted keys.
# Generate with: python -c "from cryptography.fernet import Fernet; \
#                            print(Fernet.generate_key().decode())"
_fernet_raw = os.environ.get('FERNET_KEY', '').strip()
if not _fernet_raw:
    if DEBUG:
        # Deterministic dev key so local test users survive a restart. NEVER
        # use this in production — it is public in this source tree.
        _fernet_raw = 'PLACEHOLDER_DEV_KEY_ONLY__REPLACE_IN_PRODUCTION_1234='
    else:
        raise ImproperlyConfigured(
            "FERNET_KEY environment variable must be set in production."
        )
FERNET_KEY = _fernet_raw.encode()

# ============================================
# CSRF TRUSTED ORIGINS (for prod HTTPS)
# ============================================
# Django 4+ requires the full scheme://host in CSRF_TRUSTED_ORIGINS when
# behind a reverse proxy that terminates TLS. Populate from env.
_csrf_origins = os.environ.get('CSRF_TRUSTED_ORIGINS', '').strip()
if _csrf_origins:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in _csrf_origins.split(',') if o.strip()]

# ============================================
# INSTALLED APPS
# ============================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'detection',
]

# ============================================
# MIDDLEWARE
# ============================================
# Order matters:
#   1. GlobalRateLimitMiddleware  — block DDoS floods BEFORE any view runs
#   2. SecurityHeadersMiddleware  — attach security headers to ALL responses
#   3. Django built-ins           — session, CSRF, auth, clickjacking
MIDDLEWARE = [
    # ── Custom: IP-level rate limiting (DDoS, Brute Force, Password Spraying)
    'secure_skin_ai.middleware.GlobalRateLimitMiddleware',
    # ── Custom: Security response headers (CSP, HSTS, Permissions-Policy)
    'secure_skin_ai.middleware.SecurityHeadersMiddleware',
    # ── Django built-ins
    'django.middleware.security.SecurityMiddleware',
    # ── WhiteNoise: serve collected static files in production
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# ============================================
# URLS
# ============================================
ROOT_URLCONF = 'secure_skin_ai.urls'

# ============================================
# TEMPLATES
# ============================================
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'detection.context_processors.feature_flags',
            ],
        },
    },
]

# ============================================
# WSGI
# ============================================
WSGI_APPLICATION = 'secure_skin_ai.wsgi.application'

# ============================================
# DATABASE
# ============================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ============================================
# CACHE (used by GlobalRateLimitMiddleware + login lockout)
# ============================================
# Must be shared across all gunicorn workers so a single attacker can't
# multiply the "5 attempts" limit by the number of processes.
#
#   REDIS_URL set          → Redis (recommended for prod)
#   REDIS_URL not set + prod → DatabaseCache (works across workers, no infra)
#   REDIS_URL not set + dev  → LocMemCache (fast, single-process)
_redis_url = os.environ.get('REDIS_URL', '').strip()
if _redis_url:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': _redis_url,
        }
    }
elif DEBUG:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'secure-skin-ai-cache',
        }
    }
else:
    # Requires: python manage.py createcachetable  (runs once at deploy time)
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
            'LOCATION': 'django_cache_table',
        }
    }

# ============================================
# PASSWORD VALIDATION
# ============================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ============================================
# INTERNATIONALIZATION
# ============================================
LANGUAGE_CODE = 'en-us'
# Display timezone. USE_TZ=True keeps DB in UTC (correct/portable);
# TIME_ZONE controls what users see. Override via env for other regions.
TIME_ZONE = os.environ.get('TIME_ZONE', 'Asia/Kolkata')
USE_I18N = True
USE_TZ = True

# ============================================
# STATIC FILES
# ============================================
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# WhiteNoise: compressed, hashed static file serving in production so we do
# not need a separate CDN. Falls back to Django's finder in DEBUG.
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# ============================================
# MEDIA FILES
# ============================================
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# ============================================
# LOGIN SETTINGS
# ============================================
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'

# ============================================
# SESSION SECURITY
# ============================================
SESSION_COOKIE_AGE = 3600           # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True      # JS cannot read session cookie (XSS mitigation)

# ── HTTPS settings ──────────────────────────────────────────────────────────
# Attacks stopped: MitM, Zero-Day TLS downgrade, SSL stripping
#
# Set to True in production (when HTTPS is active).
# SecurityHeadersMiddleware will then also add HSTS header automatically.
# Keep False for local HTTP development.
# In production every cookie/redirect goes over HTTPS by default — a plain-HTTP
# cookie could be intercepted (MitM / SSL stripping). In DEBUG mode these
# default False so `runserver` on HTTP still works.
SECURE_SSL_REDIRECT   = os.environ.get('SECURE_SSL_REDIRECT',   'False' if DEBUG else 'True') == 'True'
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False' if DEBUG else 'True') == 'True'
CSRF_COOKIE_SECURE    = os.environ.get('CSRF_COOKIE_SECURE',    'False' if DEBUG else 'True') == 'True'

# HSTS — instruct browsers to refuse HTTP for the next year (only when HTTPS
# is active; enabling on HTTP would lock legitimate visitors out).
if SECURE_SSL_REDIRECT:
    SECURE_HSTS_SECONDS           = 31536000   # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD           = True

# Extra session hygiene — cookies must not leak across sites (login CSRF).
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE    = 'Lax'
CSRF_COOKIE_HTTPONLY    = True

# ============================================
# SECURITY HEADERS (Django built-in layer)
# ============================================
# Clickjacking protection — deny embedding in iframes (also enforced in CSP)
X_FRAME_OPTIONS = "DENY"

# XSS filter header for older browsers (modern browsers use CSP instead)
SECURE_BROWSER_XSS_FILTER = True

# Prevent MIME-type sniffing (drive-by download / content injection)
# Attacks stopped: Tracking Pixel, Malware content injection
SECURE_CONTENT_TYPE_NOSNIFF = True

# Referrer-Policy — limit data sent to external sites
# Attacks stopped: Tracking Pixel (limits URL leakage in Referer header)
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"

# ============================================
# BRUTE FORCE / RATE LIMITING
# ============================================
LOGIN_MAX_ATTEMPTS      = int(os.environ.get('LOGIN_MAX_ATTEMPTS', 5))
LOGIN_LOCKOUT_MINUTES   = int(os.environ.get('LOGIN_LOCKOUT_MINUTES', 15))

# Global IP-level rate limit (GlobalRateLimitMiddleware in middleware.py)
# Attacks stopped: DDoS, Password Spraying, API flood
GLOBAL_RATE_LIMIT_PER_MINUTE = int(os.environ.get('GLOBAL_RATE_LIMIT_PER_MINUTE', 200))

# ============================================
# POST-ENCRYPTION SECURITY (detection/security.py)
# ============================================
# CM3 — DoS: max RSA/AES decrypt calls per user per 60-second window
MAX_DECRYPT_PER_MINUTE = int(os.environ.get('MAX_DECRYPT_PER_MINUTE', 10))
# CM4 — Replay Attack: one-time token TTL (minutes)
DECRYPT_TOKEN_TTL_MINUTES = 5

# ============================================
# EMAIL (OTP SYSTEM)
# ============================================
# OTP delivery protects against: Phishing, Credential Stuffing, Brute Force
EMAIL_BACKEND       = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST          = 'smtp.gmail.com'
EMAIL_PORT          = 587
EMAIL_USE_TLS       = True
EMAIL_HOST_USER     = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')

# ============================================
# SECURITY MONITORING / REAL-TIME ALERTS
# ============================================
# Real-time SOC dashboard + email alerts on critical security events.
# SECURITY_ALERT_EMAIL: where alerts are sent (defaults to the OTP sender).
# SECURITY_ALERTS_ENABLED: master switch for outbound alert emails.
SECURITY_ALERTS_ENABLED = os.environ.get('SECURITY_ALERTS_ENABLED', 'True') == 'True'
SECURITY_ALERT_EMAIL    = os.environ.get('SECURITY_ALERT_EMAIL', '') or EMAIL_HOST_USER
# Minutes between repeat emails for the same event-type + IP (anti-spam throttle).
SECURITY_ALERT_THROTTLE_MIN = int(os.environ.get('SECURITY_ALERT_THROTTLE_MIN', '10'))

# ============================================
# RAZORPAY PAYMENT GATEWAY
# ============================================
RAZORPAY_KEY_ID     = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')

# ============================================
# DOCTOR REGISTRATION CODE
# ============================================
# Required to self-register as a doctor. NO default in production — a known
# default would let anyone create a doctor account. In DEBUG a placeholder
# is used so the local dev flow still works.
DOCTOR_CODE = os.environ.get('DOCTOR_CODE', '').strip()
if not DOCTOR_CODE:
    if DEBUG:
        DOCTOR_CODE = 'DEV-DOCTOR-CODE'
    else:
        raise ImproperlyConfigured(
            "DOCTOR_CODE environment variable must be set in production. "
            "Choose a long random string; share only with authorized doctors."
        )

# ============================================
# DEFAULT AUTO FIELD
# ============================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
