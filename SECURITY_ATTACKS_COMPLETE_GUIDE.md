# Secure Skin AI - Complete Security Attacks & Protections Guide

**Project:** Secure Skin AI - Django Medical Image Processing Platform  
**Date:** 2026-05-01  
**Purpose:** Demonstrate all attack vectors and their corresponding protections

---

## Table of Contents

1. [CSRF - Cross Site Request Forgery](#1-csrf---cross-site-request-forgery)
2. [XSS - Cross Site Scripting](#2-xss---cross-site-scripting)
3. [SQL Injection](#3-sql-injection)
4. [Brute Force Attack](#4-brute-force-attack)
5. [Click Jacking](#5-click-jacking)
6. [Malicious File Upload](#6-malicious-file-upload)
7. [MITM - Man In The Middle Attack](#7-mitm---man-in-the-middle-attack)
8. [IDOR - Insecure Direct Object Reference](#8-idor---insecure-direct-object-reference)
9. [Ransomware Attack](#9-ransomware-attack)
10. [Session Hijacking](#10-session-hijacking)
11. [Summary Table](#summary-table)

---

## 1. CSRF - Cross Site Request Forgery

### What is CSRF?
Attacker tricks authenticated users into submitting unintended requests on a trusted site.

### BEFORE Protection - Demonstration Steps

**Step 1:** Create an attacker page
```html
<!-- Save as C:\attack\csrf_attack.html -->
<!DOCTYPE html>
<html>
<head><title>Free Skin Analysis!</title></head>
<body>
    <h1>Click for Free Skin Report!</h1>
    <!-- Hidden form that auto-submits -->
    <form id="csrf" action="http://127.0.0.1:8001/change-email/" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

**Step 2:** Start the server
```bash
python manage.py runserver 8001
```

**Step 3:** Login as a legitimate user
- Go to: http://127.0.0.1:8001/login/
- Login with valid credentials

**Step 4:** Open the attacker page in another tab
- Open: `file:///C:/attack/csrf_attack.html`

**Step 5:** Verify the attack worked
- Check if email was changed without user consent

**Screenshot Location:** 
- **BEFORE:** Show the attacker page with hidden form + victim's account page showing changed email

---

### AFTER Protection - Re-enable CSRF

**Protection Location:** `secure_skin_ai/settings.py:65`
```python
'django.middleware.csrf.CsrfViewMiddleware',
```

**All forms already have CSRF tokens:**
- `templates/login.html:69` - `{% csrf_token %}`
- `templates/upload.html:75` - `{% csrf_token %}`
- `templates/register.html:60` - `{% csrf_token %}`
- All other POST forms

**Step 1:** Verify CSRF middleware is active (already enabled)

**Step 2:** Try the same attack again
- Open attacker page while logged in

**What You See:**
```
403 Forbidden
CSRF verification failed. Request aborted.
```

**Screenshot Location:**
- **AFTER:** Show 403 Forbidden page when attacker tries CSRF

---

## 2. XSS - Cross Site Scripting

### What is XSS?
Attacker injects malicious scripts that execute in victims' browsers.

### BEFORE Protection - Demonstration Steps

**Step 1:** Comment out input sanitization in `detection/views.py`

Find the `upload_report` function (around line 829) and comment out:
```python
# Comment out these lines:
# diagnosis    = sanitize_text_input(request.POST.get("diagnosis", ""))
# prescription = sanitize_text_input(request.POST.get("prescription", ""))
# remarks      = sanitize_text_input(request.POST.get("remarks", ""))

# Change to:
diagnosis    = request.POST.get("diagnosis", "")
prescription = request.POST.get("prescription", "")
remarks      = request.POST.get("remarks", "")
```

**Step 2:** Restart server
```bash
python manage.py runserver 8001
```

**Step 3:** Login as a doctor
- Navigate to: http://127.0.0.1:8001/upload-report/<image_id>/

**Step 4:** Inject XSS payload in the diagnosis field
```html
<script>alert('XSS Attack! Document.cookie='+document.cookie)</script>
```

**Step 5:** Submit and view the report as a patient
- Patient opens the report
- Script executes in their browser

**Screenshot Location:**
- **BEFORE:** Show the alert popup appearing when patient views report + browser console showing cookie theft

---

### AFTER Protection - Re-enable XSS Protection

**Protection 1 - Input Sanitization:** `detection/security.py:368`

**Step 1:** Uncomment sanitization in `detection/views.py:829-833`:
```python
diagnosis    = sanitize_text_input(request.POST.get("diagnosis", ""))
prescription = sanitize_text_input(request.POST.get("prescription", ""))
remarks      = sanitize_text_input(request.POST.get("remarks", ""))
```

**Protection 2 - Django Auto-escaping:** Built into templates
**Protection 3 - CSP Header:** `secure_skin_ai/middleware.py:64-85`

**Step 2:** Restart server
```bash
python manage.py runserver 8001
```

**Step 3:** Try the same XSS injection

**What You See:**
- Script tags are stripped
- Text displays as literal text: `&lt;script&gt;alert('XSS')&lt;/script&gt;`
- No alert popup appears

**Screenshot Location:**
- **AFTER:** Show the script tags displayed as plain text with no execution

---

## 3. SQL Injection

### What is SQL Injection?
Attacker manipulates SQL queries by injecting malicious SQL code through input fields.

### BEFORE Protection - Demonstration Steps

**Step 1:** Create a vulnerable version of login (for demo only)

Create `detection/vulnerable_views.py`:
```python
from django.db import connection

def vulnerable_login(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        
        cursor = connection.cursor()
        # VULNERABLE - string concatenation
        query = f"SELECT * FROM auth_user WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return HttpResponse("Login Success!")
        return HttpResponse("Login Failed")
```

**Step 2:** Add URL route in `secure_skin_ai/urls.py`:
```python
path('vulnerable-login/', detection.views.vulnerable_login),
```

**Step 3:** Start server
```bash
python manage.py runserver 8001
```

**Step 4:** Try SQL injection at: http://127.0.0.1:8001/vulnerable-login/
- Username: `' OR '1'='1' --`
- Password: `anything`

**Screenshot Location:**
- **BEFORE:** Show successful login with SQL injection payload

---

### AFTER Protection - Use Django ORM

**Protection Location:** `detection/views.py:192-256`

**Current Protected Code:**
```python
# Line 214 - Uses Django ORM (parameterized queries)
user = authenticate(request, username=username, password=password)
```

**What You See:**
- Django ORM uses parameterized queries
- Payload is treated as literal string, not SQL code
- Query returns 0 rows - login denied

**Screenshot Location:**
- **AFTER:** Show "Invalid username or password" message when using SQL injection on protected login

---

## 4. Brute Force Attack

### What is Brute Force?
Attacker tries thousands of password combinations to gain unauthorized access.

### BEFORE Protection - Demonstration Steps

**Step 1:** Comment out brute force protection in `detection/views.py`

Find `login_view` function and comment out lines **204-212**:
```python
# Comment out:
# ── Session-based brute-force counter ───────────────────────────────
# attempts = request.session.get("login_attempts", 0)
# locked_until = request.session.get("login_locked_until", 0)
# now_ts = timezone.now().timestamp()
# if locked_until and now_ts < locked_until:
#     remaining_min = int((locked_until - now_ts) / 60) + 1
#     messages.error(request, f"Too many failed attempts. Try again in {remaining_min} minute(s).")
#     return render(request, "login.html", {"next": next_url})
```

Comment out lines **217-231**:
```python
# if user is None:
#     # attempts += 1
#     # request.session["login_attempts"] = attempts
#     # max_attempts = getattr(settings, "LOGIN_MAX_ATTEMPTS", 5)
#     # lockout_min = getattr(settings, "LOGIN_LOCKOUT_MINUTES", 15)
#     # if attempts >= max_attempts:
#     #     request.session["login_locked_until"] = now_ts + lockout_min * 60
#     #     request.session["login_attempts"] = 0
#     #     messages.error(request, f"Account locked for {lockout_min} minutes...")
#     # else:
#     #     messages.error(request, f"Invalid username or password. ({attempts}/{max_attempts} attempts)")
#     messages.error(request, "Invalid username or password.")
#     return render(request, "login.html", {"next": next_url})
```

**Step 2:** Comment out IP-based protection (lines **198-202**):
```python
# ip_locked, ip_msg = is_ip_login_locked(request)
# if ip_locked:
#     messages.error(request, ip_msg)
#     return render(request, "login.html", {"next": next_url})
```

**Step 3:** Comment out counter reset (lines **233-236**):
```python
# request.session.pop("login_attempts", None)
# request.session.pop("login_locked_until", None)
# clear_ip_login_lock(request)
```

**Step 4:** Restart server on different port
```bash
python manage.py runserver 8001
```

**Step 5:** Try wrong password repeatedly
- Go to: http://127.0.0.1:8001/login/
- Enter a real username with wrong password 10+ times

**What You See:**
- Just says "Invalid username or password." every time
- No lockout, no counter, no warning

**Screenshot Location:**
- **BEFORE:** Show 10+ failed attempts with no lockout message (capture the login page after multiple attempts)

---

### AFTER Protection - Re-enable All Defenses

**Protection 1 - Session-based Lockout:** `detection/views.py:204-231`
**Protection 2 - IP-based Lockout:** `detection/security.py:477-517`
**Protection 3 - OTP 2FA:** `detection/views.py:238-250`

**Step 1:** Uncomment ALL brute force protection code in `detection/views.py`:
- Lines 198-202 (IP check)
- Lines 204-212 (session lockout check)
- Lines 217-231 (failed attempt counter)
- Lines 233-236 (success reset)

**Step 2:** Restart server
```bash
python manage.py runserver 8001
```

**Step 3:** Enter wrong password 5 times for the same username

**What You See on 5th attempt:**
```
Account locked for 15 minutes due to too many failed attempts.
```

**Screenshot Location:**
- **AFTER:** Show the account locked message on 5th failed attempt

---

## 5. Click Jacking

### What is Click Jacking?
Attacker embeds the site in an invisible iframe and tricks users into clicking something different.

### BEFORE Protection - Demonstration Steps

**Step 1:** Create attacker page
```html
<!-- Save as C:\attack\clickjack_attack.html -->
<!DOCTYPE html>
<html>
<head>
    <style>
        iframe {
            width: 100%;
            height: 500px;
            border: none;
            opacity: 0.5;
            position: relative;
        }
        .overlay {
            position: absolute;
            top: 200px;
            left: 300px;
            width: 200px;
            height: 50px;
            background: rgba(255,0,0,0.5);
            color: white;
            text-align: center;
            line-height: 50px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Click the Red Box to Win $1000!</h1>
    <div class="overlay">CLICK HERE</div>
    <iframe src="http://127.0.0.1:8001/login/"></iframe>
</body>
</html>
```

**Step 2:** Temporarily disable clickjacking protection

In `secure_skin_ai/settings.py:186`, change:
```python
# Change from:
X_FRAME_OPTIONS = "DENY"

# To:
X_FRAME_OPTIONS = "ALLOWALL"  # Temporary for demo
```

**Step 3:** Restart server
```bash
python manage.py runserver 8001
```

**Step 4:** Login as a user in one browser window

**Step 5:** Open the attacker page in another window
- The login page appears inside the iframe
- Clicking "CLICK HERE" actually clicks buttons on the embedded page

**Screenshot Location:**
- **BEFORE:** Show the iframe with the embedded login page + overlay trick

---

### AFTER Protection - Re-enable Clickjacking Defense

**Protection 1 - X-Frame-Options:** `secure_skin_ai/settings.py:186`
**Protection 2 - CSP frame-ancestors:** `secure_skin_ai/middleware.py:81`

**Step 1:** Restore settings in `secure_skin_ai/settings.py:186`:
```python
X_FRAME_OPTIONS = "DENY"
```

**Step 2:** Verify CSP header in `secure_skin_ai/middleware.py:81`:
```python
"frame-ancestors 'none'; "
```

**Step 3:** Restart server
```bash
python manage.py runserver 8001
```

**Step 4:** Try to load the site in iframe

**What You See:**
- Browser console error:
  ```
  Refused to display 'http://127.0.0.1:8001/login/' in a frame because it set 'X-Frame-Options' to 'deny'.
  ```
- Iframe shows "This site cannot be displayed in a frame"

**Screenshot Location:**
- **AFTER:** Show the browser error message in console + blank/blocked iframe

---

## 6. Malicious File Upload

### What is Malicious File Upload?
Attacker uploads executable files disguised as images to compromise the server.

### BEFORE Protection - Demonstration Steps

**Step 1:** Create a malicious file
```python
# Save as C:\attack\trojan_test.jpg
# This is actually Python code disguised as JPG

# Content of trojan_test.jpg:
#!/usr/bin/env python3
import os
os.system("echo BACKDOOR EXECUTED >> C:/attack/backdoor_executed.txt")
```

**Step 2:** Check current upload validation in `detection/views.py:618-684`

The current code at **line 674** uses:
```python
image_type=image_file.content_type or "image/jpeg",
```

**Step 3:** For demo, temporarily remove any validation
- No file type checking
- No magic byte validation

**Step 4:** Start server
```bash
python manage.py runserver 8001
```

**Step 5:** Login as patient and upload the malicious file
- Go to: http://127.0.0.1:8001/upload/
- Select `trojan_test.jpg` (the Python script)
- Submit the form

**What You See:**
- File is accepted and stored in database
- No validation of actual file content

**Screenshot Location:**
- **BEFORE:** Show the malicious .jpg file being uploaded successfully + file stored in media/uploads/

---

### AFTER Protection - Enable File Validation

**Protection Location:** `detection/attack_simulations.py:219-260`

**Step 1:** Add validation to `detection/views.py` in `patient_upload` function (after line 626):

```python
# Add file validation helper function first (import from attack_simulations):
from detection.attack_simulations import trojan_validate_upload_PROTECTED

# Then in patient_upload, after line 627, add:
if not image_file:
    messages.error(request, "Please select an image.")
    return redirect("patient_upload")

# Add validation (after line 632):
is_valid, msg = trojan_validate_upload_PROTECTED(image_file)
if not is_valid:
    messages.error(request, msg)
    return redirect("patient_upload")
```

**Step 2:** Restart server
```bash
python manage.py runserver 8001
```

**Step 3:** Try uploading the same malicious file

**What You See:**
```
File extension '.py' not allowed. Only JPG/PNG/GIF accepted.
OR
Invalid file type. Magic bytes do not match image format.
```

**Screenshot Location:**
- **AFTER:** Show the error message when trying to upload malicious file

---

## 7. MITM - Man In The Middle Attack

### What is MITM?
Attacker intercepts communication between client and server to steal or modify data.

### BEFORE Protection - Demonstration Steps

**Step 1:** Disable HTTPS settings in `secure_skin_ai/settings.py`:

```python
# Lines 178-180 - Set all to False:
SECURE_SSL_REDIRECT    = False
SESSION_COOKIE_SECURE  = False
CSRF_COOKIE_SECURE     = False
```

**Step 2:** Start server on HTTP
```bash
python manage.py runserver 8001
```

**Step 3:** Use network sniffer (Wireshark or Fiddler) to capture traffic
- Start packet capture on port 8001
- Login to the application
- Observe plaintext cookies and session data

**What You See:**
- Session cookie visible in plaintext
- All data transmitted unencrypted over HTTP

**Screenshot Location:**
- **BEFORE:** Show Wireshark/Fiddler capture with plaintext session cookie

---

### AFTER Protection - Enable HTTPS and Encryption

**Protection 1 - Hybrid Encryption:** `detection/views.py:640-675`
**Protection 2 - HTTPS Settings:** `secure_skin_ai/settings.py:178-180`
**Protection 3 - HSTS Header:** `secure_skin_ai/middleware.py:91-94`

**Step 1:** Enable HTTPS settings in `secure_skin_ai/settings.py`:
```python
SECURE_SSL_REDIRECT    = True   # Force HTTPS
SESSION_COOKIE_SECURE  = True   # Cookies only over HTTPS
CSRF_COOKIE_SECURE     = True   # CSRF cookie secure
```

**Step 2:** Verify encryption is active in `detection/views.py`:
- Line 649: `image_hash = generate_hash(raw)` - SHA-256 hash
- Line 652-653: AES encryption
- Line 656: RSA encryption of AES key

**Step 3:** For production, obtain SSL certificate and configure HTTPS

**What You See:**
- All traffic encrypted via TLS/SSL
- Even if intercepted, data is encrypted with AES-256 + RSA-2048
- HSTS header forces browsers to use HTTPS only

**Screenshot Location:**
- **AFTER:** Show Wireshark capture with only encrypted TLS traffic + browser padlock icon

---

## 8. IDOR - Insecure Direct Object Reference

### What is IDOR?
Attacker accesses resources belonging to other users by manipulating object IDs.

### BEFORE Protection - Demonstration Steps

**Step 1:** Create two patient accounts:
- Patient A (username: patientA, password: test123)
- Patient B (username: patientB, password: test123)

**Step 2:** Upload an image as Patient B
- Note the image ID from the URL (e.g., /view-decrypted/5/)

**Step 3:** Login as Patient A

**Step 4:** Manually change URL to access Patient B's image
- Change from: http://127.0.0.1:8001/view-decrypted/4/
- To: http://127.0.0.1:8001/view-decrypted/5/

**Step 5:** For demo, temporarily comment out IDOR check in `detection/views.py:698-708`:
```python
# Comment out:
# authorized, use_patient_key, error_msg = check_decrypt_authorization(request.user, image, role)
# if not authorized:
#     messages.error(request, error_msg)
#     return redirect("dashboard")
```

**Step 6:** Try accessing the other user's image

**What You See:**
- Patient A can view Patient B's private medical image
- No authorization check performed

**Screenshot Location:**
- **BEFORE:** Show Patient A successfully viewing Patient B's medical record

---

### AFTER Protection - Enable Strict Ownership Check

**Protection Location:** `detection/security.py:278-309` and `detection/views.py:698-708`

**Step 1:** Uncomment IDOR check in `detection/views.py:698-708`:
```python
# ── CM5: Strict IDOR ownership check ──────────────────────────────────
authorized, use_patient_key, error_msg = check_decrypt_authorization(request.user, image, role)
if not authorized:
    messages.error(request, error_msg)
    return redirect("dashboard")
```

**Step 2:** Restart server
```bash
python manage.py runserver 8001
```

**Step 3:** Login as Patient A and try to access Patient B's image URL

**What You See:**
```
[IDOR Protection] Unauthorized. You are not the assigned doctor
for this image and do not own it.
```

**Screenshot Location:**
- **AFTER:** Show the 403 Forbidden or unauthorized error message

---

## 9. Ransomware Attack

### What is Ransomware?
Malware that encrypts files and demands payment for decryption.

### BEFORE Protection - Demonstration Steps

**Step 1:** Check `detection/attack_simulations.py:59-86` for ransomware simulation

**Step 2:** Upload a test image as a patient
- Go to: http://127.0.0.1:8001/upload/
- Upload a sample image

**Step 3:** Note the file location in `media/uploads/`

**Step 4:** Run the ransomware simulation script:
```python
# In Django shell or standalone script
from detection.attack_simulations import ransomware_encrypt_file

# Encrypt the uploaded image
ransomware_encrypt_file("media/uploads/test_image.jpg")
```

**Step 5:** Check the file
- Original file is now `.locked`
- Original is deleted
- File is unreadable

**What You See:**
- File renamed to `test_image.jpg.locked`
- Original file deleted
- Log entry in `attack_logs/ransomware_victims.txt`

**Screenshot Location:**
- **BEFORE:** Show the .locked file + ransomware log showing successful encryption

---

### AFTER Protection - Encryption Already in Place

**Protection:** The application uses encryption at rest, so ransomware cannot re-encrypt already encrypted data

**Step 1:** Verify encryption is active in `detection/views.py:646-675`:
- Line 649: SHA-256 hash computed
- Line 652-653: AES-256 encryption
- Line 656: RSA encryption of AES key

**Step 2:** Try ransomware simulation on encrypted data
- Encrypted data is already ciphertext
- XOR "encryption" just produces different ciphertext
- Original can be recovered from database backup

**What You See:**
- Database contains encrypted blobs (already ciphertext)
- File system storage is protected
- Backup/restore possible via database

**Screenshot Location:**
- **AFTER:** Show encrypted data in database that ransomware cannot meaningfully encrypt

---

## 10. Session Hijacking

### What is Session Hijacking?
Attacker steals session cookie to impersonate a legitimate user.

### BEFORE Protection - Demonstration Steps

**Step 1:** Disable session security in `secure_skin_ai/settings.py`:

```python
# Line 168-170 - Change to:
SESSION_COOKIE_AGE = 86400           # 24 hours (too long)
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Persistent session
SESSION_COOKIE_HTTPONLY = False      # JS can read cookie
```

**Step 2:** Start server
```bash
python manage.py runserver 8001
```

**Step 3:** Login as a user

**Step 4:** Open browser console and run:
```javascript
console.log(document.cookie);
```

**Step 5:** Copy the session cookie and use in another browser/incognito window

**What You See:**
- Session cookie is readable via JavaScript
- Can be stolen via XSS attack
- Session persists for 24 hours

**Screenshot Location:**
- **BEFORE:** Show document.cookie output with session ID + successful hijacked session

---

### AFTER Protection - Enable Session Security

**Protection Location:** `secure_skin_ai/settings.py:168-170`

**Step 1:** Restore secure settings:
```python
SESSION_COOKIE_AGE = 3600              # 1 hour only
SESSION_EXPIRE_AT_BROWSER_CLOSE = True # Expire on browser close
SESSION_COOKIE_HTTPONLY = True         # JavaScript cannot read
```

**Step 2:** Restart server
```bash
python manage.py runserver 8001
```

**Step 3:** Try to read cookie via JavaScript

**What You See:**
- `document.cookie` does NOT show session cookie
- Session expires after 1 hour
- Session expires when browser closes

**Screenshot Location:**
- **AFTER:** Show empty or no session cookie in document.cookie output

---

## Summary Table

| # | Attack | Protection Mechanism | File Location | Status |
|---|--------|---------------------|---------------|--------|
| 1 | **CSRF** | CsrfViewMiddleware + csrf_token tags | settings.py:65, All templates | ✅ Protected |
| 2 | **XSS** | Input sanitization + Django auto-escape + CSP | security.py:368, middleware.py:64 | ✅ Protected |
| 3 | **SQL Injection** | Django ORM (parameterized queries) | views.py:214 | ✅ Protected |
| 4 | **Brute Force** | Session lockout (5 attempts) + IP lockout + OTP 2FA | views.py:204-236, security.py:477-517 | ✅ Protected |
| 5 | **Click Jacking** | X-Frame-Options: DENY + CSP frame-ancestors | settings.py:186, middleware.py:81 | ✅ Protected |
| 6 | **Malicious File Upload** | Extension + Magic byte validation | attack_simulations.py:219-260 | ✅ Protected |
| 7 | **MITM** | Hybrid AES-256 + RSA-2048 encryption + HSTS | views.py:646-675, middleware.py:91 | ✅ Protected |
| 8 | **IDOR** | Strict ownership authorization check | security.py:278-309, views.py:698 | ✅ Protected |
| 9 | **Ransomware** | Database encryption + backup | views.py:649-675 | ✅ Protected |
| 10 | **Session Hijacking** | HttpOnly + 1hr expiry + browser close | settings.py:168-170 | ✅ Protected |
| 11 | **DDoS** | Global IP rate limiter (200 req/min) | middleware.py:141-212 | ✅ Protected |
| 12 | **Replay Attack** | One-time decryption tokens (5 min TTL) | security.py:201-260 | ✅ Protected |
| 13 | **Timing Attack** | Constant-time hash comparison | security.py:122-130 | ✅ Protected |
| 14 | **DoS (Decrypt)** | Per-user rate limit (10 decrypt/min) | security.py:149-182 | ✅ Protected |
| 15 | **APT/Insider Threat** | Structured audit logging | security.py:534-565 | ✅ Protected |

---

## Quick Reference - All Protection Files

### Core Security Files

| File | Purpose | Key Lines |
|------|---------|-----------|
| `secure_skin_ai/settings.py` | Django security settings | 55-69, 168-197, 202-207 |
| `secure_skin_ai/middleware.py` | Custom security headers + rate limiting | 43-213 |
| `detection/security.py` | Post-encryption security layer | All (CM1-CM11) |
| `detection/views.py` | View-level protections | 192-256, 618-684, 692-750 |
| `detection/attack_simulations.py` | File upload validation + attack demos | 219-260, 59-156 |

### Key Settings to Configure

```python
# secure_skin_ai/settings.py

# Brute Force Protection
LOGIN_MAX_ATTEMPTS = 5           # Line 202
LOGIN_LOCKOUT_MINUTES = 15       # Line 203

# Global Rate Limiting
GLOBAL_RATE_LIMIT_PER_MINUTE = 200  # Line 207

# Session Security
SESSION_COOKIE_AGE = 3600           # Line 168
SESSION_COOKIE_HTTPONLY = True      # Line 170

# HTTPS (Production)
SECURE_SSL_REDIRECT = True          # Line 178
SESSION_COOKIE_SECURE = True        # Line 179
CSRF_COOKIE_SECURE = True           # Line 180

# Clickjacking Protection
X_FRAME_OPTIONS = "DENY"            # Line 186
```

---

## Screenshot Checklist

### Before Protection Screenshots (10 total)
1. CSRF - Attacker page with hidden form
2. XSS - Alert popup on patient report view
3. SQL Injection - Successful login with `' OR '1'='1`
4. Brute Force - 10+ failed attempts with no lockout
5. Click Jacking - Site embedded in iframe
6. Malicious Upload - Trojan .jpg file accepted
7. MITM - Wireshark showing plaintext cookies
8. IDOR - Patient A viewing Patient B's record
9. Ransomware - File encrypted with .locked extension
10. Session Hijack - document.cookie showing session ID

### After Protection Screenshots (10 total)
1. CSRF - 403 Forbidden on attacker request
2. XSS - Script tags displayed as text (no execution)
3. SQL Injection - "Invalid credentials" message
4. Brute Force - "Account locked for 15 minutes"
5. Click Jacking - Browser error "Refused to display in frame"
6. Malicious Upload - "File type not allowed" error
7. MITM - Encrypted TLS traffic only + padlock icon
8. IDOR - "Unauthorized access" error message
9. Ransomware - Already encrypted data unaffected
10. Session Hijack - Empty document.cookie output

---

**Document Version:** 1.0  
**Last Updated:** 2026-05-01  
**Author:** Security Analysis for Secure Skin AI Project
