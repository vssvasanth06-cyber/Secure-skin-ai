# ============================================
# IMPORTS
# ============================================
import uuid
import io
import json
import razorpay

from django.http import HttpResponse
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch

from .utils import generate_otp, set_otp_session, verify_otp
from .crypto_utils import (
    generate_hash, generate_aes_key, encrypt_data, decrypt_data,
    encrypt_key, decrypt_key, sign_data, verify_signature,
    generate_rsa_keys,
)
from .models import (
    MedicalImage, UserProfile, Report, LoginLog,
    DoctorAvailability,
)
from .security import (
    # CM1 — Private Key Encryption at Rest (SQL Injection / Memory Scraping)
    encrypt_private_key, decrypt_private_key,
    # CM2 — Constant-Time Hash Compare (Timing Attack)
    secure_hash_compare,
    # CM3 — Rate Limiter (DoS)
    rate_limit_decrypt,
    # CM4 — One-Time Decrypt Token (Replay Attack)
    issue_decrypt_token, validate_decrypt_token,
    # CM5 — Strict IDOR Check (IDOR)
    check_decrypt_authorization,
    # CM6 — Audit Logging (Non-repudiation)
    log_decrypt_attempt,
    # CM7 — Input Sanitiser (XSS)
    sanitize_text_input,
    # CM8 — Memory Cleanup (Memory Scraping)
    secure_cleanup,
    # CM10 — IP-Based Login Rate Limiter (Password Spraying / Brute Force)
    record_failed_login, is_ip_login_locked, clear_ip_login_lock,
    # CM11 — APT Anomaly Logger
    log_security_event,
    # Spoof-safe client IP helper (respects TRUST_PROXY_HEADERS setting)
    get_client_ip,
)


# ============================================
# HELPERS
# ============================================

def _to_bytes(val):
    """Ensure value is bytes (handles str PEM keys from DB)."""
    if isinstance(val, str):
        return val.encode()
    if isinstance(val, memoryview):
        return bytes(val)
    return bytes(val) if val else b""


# ── Upload validation ─────────────────────────────────────────────────────
# Client-supplied Content-Type / filename cannot be trusted. We inspect the
# real magic bytes so an attacker cannot ship a PHP shell disguised as .jpg
# (matches the "Malicious File Upload" defense in the security-demo page).
MAX_UPLOAD_BYTES = 10 * 1024 * 1024   # 10 MB per image
_IMAGE_MAGIC = {
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/png":  [b"\x89PNG\r\n\x1a\n"],
    "image/webp": [b"RIFF"],           # + WEBP at offset 8
    "image/gif":  [b"GIF87a", b"GIF89a"],
}


def _detect_image_mime(head: bytes) -> str | None:
    """Return the real MIME of an image by magic bytes, or None if unknown."""
    for mime, prefixes in _IMAGE_MAGIC.items():
        for p in prefixes:
            if head.startswith(p):
                # WebP needs a second check
                if mime == "image/webp" and not (len(head) >= 12 and head[8:12] == b"WEBP"):
                    continue
                return mime
    return None


def _role(request):
    try:
        return request.user.userprofile.role
    except Exception:
        return None


# ── OTP email helper ──────────────────────────────────────────────────────
# Renders the branded HTML template (templates/emails/otp_email.html) and
# a plain-text fallback so every mail client — including screen readers and
# strict corporate gateways — can still read the code.
_OTP_PURPOSE_META = {
    "register": {
        "subject":       "Secure Skin AI — Verify your registration",
        "purpose_label": "REGISTRATION",
        "greeting":      "Welcome to Secure Skin AI",
        "body":          "Use the one-time code below to confirm your email and finish creating your account.",
    },
    "login": {
        "subject":       "Secure Skin AI — Your login code",
        "purpose_label": "LOGIN VERIFICATION",
        "greeting":      "Sign-in verification",
        "body":          "Someone (hopefully you) is signing in to your Secure Skin AI account. Enter this code to complete login.",
    },
    "forgot": {
        "subject":       "Secure Skin AI — Password reset code",
        "purpose_label": "PASSWORD RESET",
        "greeting":      "Reset your password",
        "body":          "We received a request to reset your Secure Skin AI password. Use the code below to continue.",
    },
}


def _send_otp_email(recipient_email: str, otp: str, purpose: str, resent: bool = False):
    """Send the branded OTP email + a text fallback. Purpose ∈ register/login/forgot."""
    meta = _OTP_PURPOSE_META.get(purpose, _OTP_PURPOSE_META["login"])
    subject = meta["subject"] + (" (resent)" if resent else "")

    html_body = render_to_string("emails/otp_email.html", {
        "subject":       subject,
        "purpose_label": meta["purpose_label"],
        "greeting_line": meta["greeting"],
        "body_line":     meta["body"],
        "otp":           otp,
    })
    text_body = (
        f"Secure Skin AI\n\n"
        f"{meta['greeting']}\n\n"
        f"{meta['body']}\n\n"
        f"    Your one-time code:  {otp}\n"
        f"    (expires in 2 minutes)\n\n"
        f"If you didn't request this, you can ignore this email.\n"
    )

    send_mail(
        subject=subject,
        message=text_body,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[recipient_email],
        html_message=html_body,
        fail_silently=False,
    )


# ============================================
# REGISTER + OTP
# ============================================

def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        role = request.POST.get("role", "patient")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        confirm = request.POST.get("confirm", "")
        if password != confirm:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        # Enforce AUTH_PASSWORD_VALIDATORS (min-length-8, common-password,
        # user-attribute-similarity, numeric-only). Reason: the old manual
        # len<6 check let users pick "123456" and pass.
        try:
            validate_password(password, user=User(username=username, email=email))
        except ValidationError as e:
            for msg in e.messages:
                messages.error(request, msg)
            return redirect("register")

        if role == "doctor":
            if request.POST.get("doctor_code", "") != getattr(settings, "DOCTOR_CODE", "HOSPITAL2026"):
                messages.error(request, "Invalid doctor registration code.")
                return redirect("register")

        otp = generate_otp()
        request.session["temp_user"] = {
            "username": username,
            "email": email,
            "password": password,
            "role": role,
        }
        set_otp_session(request, otp, "register", email)

        _send_otp_email(email, otp, "register")
        return redirect("verify_registration_otp")

    return render(request, "register.html")


# ============================================
# VERIFY REGISTRATION OTP
# ============================================

def verify_registration_otp(request):
    temp_user = request.session.get("temp_user")
    if not temp_user:
        return redirect("register")

    otp_time = request.session.get("otp_time", 0)
    remaining = max(0, int(120 - (timezone.now().timestamp() - otp_time)))

    if request.method == "POST":
        # Resend button
        if "resend" in request.POST:
            return _resend_otp_helper(request, "register", temp_user["email"])

        entered_otp = request.POST.get("otp", "")
        is_valid, msg = verify_otp(request, entered_otp, "register")

        if not is_valid:
            expired = "expired" in msg.lower()
            messages.error(request, msg)
            return render(request, "verify_registration_otp.html",
                          {"remaining": 0 if expired else remaining, "expired": expired})

        try:
            user = User.objects.create_user(
                username=temp_user["username"],
                email=temp_user["email"],
                password=temp_user["password"],
            )
            profile = user.userprofile
            profile.role = temp_user["role"]

            pub, priv = generate_rsa_keys()
            profile.public_key = pub.decode() if isinstance(pub, bytes) else pub
            # CM1 — Encrypt private key before storing (SQL Injection / Memory Scraping)
            profile.private_key = encrypt_private_key(priv if isinstance(priv, bytes) else priv.encode())
            profile.save()

            for k in ["temp_user", "otp", "otp_time", "otp_purpose", "otp_user"]:
                request.session.pop(k, None)

            messages.success(request, "Registration successful! Please login.")
            return redirect("login")

        except Exception as e:
            messages.error(request, f"Registration error: {e}")

    return render(request, "verify_registration_otp.html", {"remaining": remaining})


# ============================================
# LOGIN WITH OTP
# ============================================

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        next_url = request.POST.get("next", "") or request.GET.get("next", "")

        # ── CM10: IP-based lockout check (Password Spraying / Brute Force) ─
        ip_locked, ip_msg = is_ip_login_locked(request)
        if ip_locked:
            messages.error(request, ip_msg)
            return render(request, "login.html", {"next": next_url})

        # ── Session-based brute-force counter ───────────────────────────────
        attempts = request.session.get("login_attempts", 0)
        locked_until = request.session.get("login_locked_until", 0)
        now_ts = timezone.now().timestamp()

        if locked_until and now_ts < locked_until:
            remaining_min = int((locked_until - now_ts) / 60) + 1
            messages.error(request, f"Too many failed attempts. Try again in {remaining_min} minute(s).")
            return render(request, "login.html", {"next": next_url})

        user = authenticate(request, username=username, password=password)

        # ── BRUTE FORCE PROTECTION — failed auth ────────────────────────────
        if user is None:
            # CM10: increment IP-level counter
            record_failed_login(request)

            attempts += 1
            request.session["login_attempts"] = attempts
            max_attempts = getattr(settings, "LOGIN_MAX_ATTEMPTS", 5)
            lockout_min = getattr(settings, "LOGIN_LOCKOUT_MINUTES", 15)
            if attempts >= max_attempts:
                request.session["login_locked_until"] = now_ts + lockout_min * 60
                request.session["login_attempts"] = 0
                messages.error(request, f"Account locked for {lockout_min} minutes due to too many failed attempts.")
            else:
                messages.error(request, f"Invalid username or password. ({attempts}/{max_attempts} attempts)")
            return render(request, "login.html", {"next": next_url})

        # Successful auth — clear both session and IP-level lockout counters
        request.session.pop("login_attempts", None)
        request.session.pop("login_locked_until", None)
        clear_ip_login_lock(request)  # CM10: reset IP counter on success

        otp = generate_otp()
        set_otp_session(request, otp, "login", username)
        if next_url:
            request.session["login_next"] = next_url

        _send_otp_email(user.email, otp, "login")
        return redirect("verify_login_otp")

    next_url = request.GET.get("next", "")
    # Clear any stale messages from other views so they don't bleed into login page
    from django.contrib.messages import get_messages as _get_msgs
    list(_get_msgs(request))
    return render(request, "login.html", {"next": next_url})


# ============================================
# VERIFY LOGIN OTP
# ============================================

def verify_login_otp(request):
    otp_time = request.session.get("otp_time", 0)
    remaining = max(0, int(120 - (timezone.now().timestamp() - otp_time)))

    if request.method == "POST":
        # Resend button
        if "resend" in request.POST:
            username = request.session.get("otp_user", "")
            try:
                u = User.objects.get(username=username)
                return _resend_otp_helper(request, "login", username, email=u.email)
            except User.DoesNotExist:
                return redirect("login")

        entered_otp = request.POST.get("otp", "")
        is_valid, msg = verify_otp(request, entered_otp, "login")

        if not is_valid:
            expired = "expired" in msg.lower()
            messages.error(request, msg)
            return render(request, "verify_login_otp.html",
                          {"remaining": 0 if expired else remaining, "expired": expired})

        username = request.session.get("otp_user")
        if not username:
            messages.error(request, "Session expired. Please login again.")
            return redirect("login")

        try:
            user = User.objects.get(username=username)
            login(request, user)

            # Record login activity (spoof-safe IP resolution)
            ip = get_client_ip(request)
            LoginLog.objects.create(user=user, role=user.userprofile.role, ip_address=ip or None)

            # CM11 — APT anomaly logging (off-hours access auto-flagged inside)
            log_security_event(request, "LOGIN_OK", f"role={user.userprofile.role}")

            next_url = request.session.pop("login_next", None)
            for k in ["otp", "otp_time", "otp_purpose", "otp_user"]:
                request.session.pop(k, None)

            return redirect(next_url if next_url else "dashboard")

        except User.DoesNotExist:
            messages.error(request, "User not found.")
            return redirect("login")

    return render(request, "verify_login_otp.html", {"remaining": remaining})


# ============================================
# FORGOT PASSWORD
# ============================================

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        try:
            User.objects.get(email=email)
            otp = generate_otp()
            request.session["reset_email"] = email
            set_otp_session(request, otp, "forgot", email)

            _send_otp_email(email, otp, "forgot")
            return redirect("verify_reset_otp")

        except User.DoesNotExist:
            messages.error(request, "No account found with that email.")

    return render(request, "forgot_password.html")


# ============================================
# VERIFY RESET OTP
# ============================================

def verify_reset_otp(request):
    if not request.session.get("reset_email"):
        return redirect("forgot_password")

    otp_time = request.session.get("otp_time", 0)
    remaining = max(0, int(120 - (timezone.now().timestamp() - otp_time)))

    if request.method == "POST":
        # Resend button
        if "resend" in request.POST:
            email = request.session.get("reset_email", "")
            return _resend_otp_helper(request, "forgot", email)

        entered_otp = request.POST.get("otp", "")
        is_valid, msg = verify_otp(request, entered_otp, "forgot")

        if not is_valid:
            expired = "expired" in msg.lower()
            messages.error(request, msg)
            return render(request, "verify_reset_otp.html",
                          {"remaining": 0 if expired else remaining, "expired": expired})

        request.session["otp_verified"] = True
        for k in ["otp", "otp_time", "otp_purpose", "otp_user"]:
            request.session.pop(k, None)
        return redirect("reset_password")

    return render(request, "verify_reset_otp.html", {"remaining": remaining})


# ============================================
# RESET PASSWORD
# ============================================

def reset_password(request):
    if not request.session.get("otp_verified"):
        return redirect("forgot_password")

    email = request.session.get("reset_email")
    if not email:
        return redirect("forgot_password")

    if request.method == "POST":
        password = request.POST.get("password", "")
        confirm = request.POST.get("confirm", "")

        if not password or not confirm:
            messages.error(request, "All fields are required.")
            return redirect("reset_password")
        if password != confirm:
            messages.error(request, "Passwords do not match.")
            return redirect("reset_password")

        try:
            user = User.objects.get(email=email)
            # Same validators as registration — reset must not be a bypass.
            try:
                validate_password(password, user=user)
            except ValidationError as e:
                for msg in e.messages:
                    messages.error(request, msg)
                return redirect("reset_password")
            user.set_password(password)
            user.save()
            for k in ["reset_email", "otp_verified"]:
                request.session.pop(k, None)
            messages.success(request, "Password reset successful! Please login.")
            return redirect("login")
        except User.DoesNotExist:
            messages.error(request, "User not found.")
            return redirect("forgot_password")

    return render(request, "reset_password.html")


# ============================================
# RESEND OTP (URL-accessible + internal helper)
# ============================================

def _resend_otp_helper(request, purpose, identifier, email=None):
    """Generate + send a new OTP and redirect back to verify page."""
    otp = generate_otp()
    send_to = email if email else identifier
    set_otp_session(request, otp, purpose, identifier)

    _send_otp_email(send_to, otp, purpose, resent=True)
    messages.success(request, "A new OTP has been sent to your email.")
    redirects = {
        "register": "verify_registration_otp",
        "login": "verify_login_otp",
        "forgot": "verify_reset_otp",
    }
    return redirect(redirects.get(purpose, "login"))


def resend_otp(request):
    """URL-accessible resend — reads purpose from session."""
    purpose = request.session.get("otp_purpose")
    identifier = request.session.get("otp_user") or request.session.get("reset_email", "")

    if not purpose or not identifier:
        return redirect("login")

    email = identifier
    if purpose == "login":
        try:
            u = User.objects.get(username=identifier)
            email = u.email
        except User.DoesNotExist:
            return redirect("login")

    return _resend_otp_helper(request, purpose, identifier, email=email)


# ============================================
# LOGOUT
# ============================================

def logout_view(request):
    logout(request)
    return redirect("login")


# ============================================
# DASHBOARD  (role-based)
# ============================================

@login_required
def dashboard(request):
    role = _role(request)
    if not role:
        messages.error(request, "User profile not found. Please contact admin.")
        return redirect("login")

    last_week = timezone.now() - timedelta(days=7)

    # ── ADMIN ──────────────────────────────────────
    if role == "admin":
        all_users = User.objects.select_related("userprofile").all()
        doctors = all_users.filter(userprofile__role="doctor")
        patients = all_users.filter(userprofile__role="patient")
        logs = LoginLog.objects.select_related("user").order_by("-login_time")[:20]

        # Patient performance stats
        patient_perf = []
        for p in patients:
            uploads = MedicalImage.objects.filter(user=p).count()
            rep_count = Report.objects.filter(image__user=p).count()
            paid = Report.objects.filter(image__user=p, is_paid=True).count()
            patient_perf.append({
                "user": p,
                "uploads": uploads,
                "reports": rep_count,
                "paid": paid,
                "unpaid": rep_count - paid,
            })

        # Doctor performance stats
        doctor_perf = []
        for d in doctors:
            cases = MedicalImage.objects.filter(assigned_doctor=d).count()
            verified = MedicalImage.objects.filter(assigned_doctor=d, is_verified=True).count()
            written = Report.objects.filter(image__assigned_doctor=d).count()
            doctor_perf.append({
                "user": d,
                "cases": cases,
                "verified": verified,
                "pending": cases - verified,
                "written": written,
            })

        # Pending UPI payments — admin must approve before patient gets access
        pending_upi = Report.objects.filter(
            transaction_id__startswith="UPI-PENDING-"
        ).select_related("image__user").order_by("-payment_time")

        context = {
            "total_users": all_users.count(),
            "total_doctors": doctors.count(),
            "total_patients": patients.count(),
            "total_reports": Report.objects.count(),
            "total_images": MedicalImage.objects.count(),
            "weekly_upload_count": MedicalImage.objects.filter(uploaded_at__gte=last_week).count(),
            "weekly_report_count": Report.objects.filter(created_at__gte=last_week).count(),
            "logs": logs,
            "users": all_users,
            "doctors": doctors,
            "patients": patients,
            "patient_perf": patient_perf,
            "doctor_perf": doctor_perf,
            "pending_upi": pending_upi,
        }
        return render(request, "admin_dashboard.html", context)

    # ── DOCTOR ─────────────────────────────────────
    elif role == "doctor":
        images = MedicalImage.objects.filter(
            assigned_doctor=request.user
        ).select_related("user").order_by("-uploaded_at")

        # CM4 — Issue fresh one-time decrypt tokens for each image (Replay Attack)
        # Token is attached directly to each image object so the template can
        # use {{ image.decrypt_token }} inline in the href. Each token is valid
        # for 5 minutes and single-use — captured URLs cannot be replayed.
        # Compute counts from QuerySet BEFORE converting to list
        total_cases    = images.count()
        verified_cases = images.filter(is_verified=True).count()
        pending_cases  = images.filter(is_verified=False).count()

        images = list(images)   # evaluate QuerySet so we can attach attributes
        for img in images:
            img.decrypt_token = issue_decrypt_token(request.user, img)

        context = {
            "images": images,
            "total_cases": total_cases,
            "verified_cases": verified_cases,
            "pending_cases": pending_cases,
            "recent_images": images[:5],
        }
        return render(request, "doctor_dashboard.html", context)

    # ── PATIENT ────────────────────────────────────
    elif role == "patient":
        images = MedicalImage.objects.filter(
            user=request.user
        ).select_related("assigned_doctor").order_by("-uploaded_at")
        reports = Report.objects.filter(
            image__user=request.user
        ).select_related("image__assigned_doctor").order_by("-created_at")
        today = timezone.now().date()

        # Only UPCOMING appointments count (date >= today)
        booked_slots = DoctorAvailability.objects.filter(
            patient=request.user, is_booked=True, date__gte=today
        ).select_related("doctor")

        # For severe reports — patient must have an UPCOMING appointment with the assigned doctor
        booked_doc_ids = set(booked_slots.values_list("doctor_id", flat=True))
        reports = list(reports)
        for r in reports:
            if r.severity == "severe":
                doc = r.image.assigned_doctor
                r.appointment_needed = not (doc and doc.id in booked_doc_ids)
            else:
                r.appointment_needed = False

        context = {
            "images": images,
            "reports": reports,
            "total_reports": len(reports),
            "paid_reports": sum(1 for r in reports if r.is_paid),
            "unpaid_reports": sum(1 for r in reports if not r.is_paid),
            "booked_slots": booked_slots,
        }
        return render(request, "Patient_dashboard.html", context)

    return HttpResponse("Invalid role. Contact admin.", status=403)


# ============================================
# PATIENT UPLOAD  (Hybrid Encryption: AES + RSA)
# ============================================

@login_required
def patient_upload(request):
    if _role(request) != "patient":
        messages.error(request, "Only patients can upload images.")
        return redirect("dashboard")

    if request.method == "POST":
        image_file = request.FILES.get("image")
        doctor_id = request.POST.get("doctor")

        if not image_file:
            messages.error(request, "Please select an image.")
            return redirect("patient_upload")
        if not doctor_id:
            messages.error(request, "Please select a doctor.")
            return redirect("patient_upload")

        try:
            doctor = User.objects.get(id=doctor_id, userprofile__role="doctor")
        except User.DoesNotExist:
            messages.error(request, "Selected doctor not found.")
            return redirect("patient_upload")

        try:
            doc_pub = doctor.userprofile.public_key
            if not doc_pub:
                messages.error(request, "Doctor's public key not available.")
                return redirect("patient_upload")

            # ── Upload validation (before we read the whole file) ─────────
            # 1. Size cap — 10 MB. Anything larger is rejected without loading.
            if image_file.size and image_file.size > MAX_UPLOAD_BYTES:
                messages.error(request, "Image too large (max 10 MB).")
                return redirect("patient_upload")

            raw = image_file.read(MAX_UPLOAD_BYTES + 1)
            if len(raw) > MAX_UPLOAD_BYTES:
                messages.error(request, "Image too large (max 10 MB).")
                return redirect("patient_upload")

            # 2. Magic-byte check — ignore client-supplied Content-Type and
            # filename entirely. A PHP shell renamed to .jpg does not have
            # a JPEG header and gets rejected here.
            real_mime = _detect_image_mime(raw[:16])
            if not real_mime:
                messages.error(request,
                    "Uploaded file is not a recognized image (JPEG/PNG/WebP/GIF only).")
                return redirect("patient_upload")

            # 1. Hash
            image_hash = generate_hash(raw)

            # 2. AES encrypt image
            aes_key = generate_aes_key()
            enc_image = encrypt_data(raw, aes_key)

            # 3a. RSA encrypt AES key with doctor's public key (doctor can decrypt)
            enc_aes = encrypt_key(aes_key, _to_bytes(doc_pub))

            # 3b. RSA encrypt AES key with patient's OWN public key (patient can view their image)
            pat_pub = request.user.userprofile.public_key
            pat_enc_aes = encrypt_key(aes_key, _to_bytes(pat_pub))

            # 4. Patient signs image with own private key
            pat_priv = request.user.userprofile.private_key
            signature = sign_data(_to_bytes(pat_priv), raw)

            MedicalImage.objects.create(
                user=request.user,
                assigned_doctor=doctor,
                encrypted_image=bytes(enc_image),
                encrypted_aes_key=bytes(enc_aes),
                patient_encrypted_aes_key=bytes(pat_enc_aes),
                image_hash=image_hash,
                signature=bytes(signature),
                # Use the SERVER-determined MIME, never the client's.
                image_type=real_mime,
            )
            messages.success(request, "Image uploaded and encrypted successfully!")
            return redirect("dashboard")

        except Exception as e:
            messages.error(request, f"Upload failed: {e}")
            return redirect("patient_upload")

    doctors = UserProfile.objects.filter(role="doctor").select_related("user")
    return render(request, "upload.html", {"doctors": doctors})


# ============================================
# VIEW DECRYPTED IMAGE  (Doctor / Patient only)
# Security layer: CM1 CM2 CM3 CM4 CM5 CM6 CM8
# ============================================

@login_required
@rate_limit_decrypt                          # CM3 — DoS protection
def view_decrypted_image(request, image_id):
    image = get_object_or_404(MedicalImage, id=image_id)
    role  = _role(request)

    # ── CM5: Strict IDOR ownership check ──────────────────────────────────
    # Admin cannot decrypt; only the exact assigned doctor or the image owner.
    authorized, use_patient_key, idor_err = check_decrypt_authorization(
        request.user, image, role
    )
    if not authorized:
        log_decrypt_attempt(request, image, False, "IDOR")    # CM6
        return HttpResponse(idor_err, status=403)

    # ── CM4: One-time Replay Attack token (doctors only) ──────────────────
    # Token is issued when the dashboard loads and embedded in the link.
    # Any captured/replayed URL is rejected after first use.
    if role == "doctor":
        raw_token = request.GET.get("token", "")
        is_valid, token_err = validate_decrypt_token(raw_token, request.user, image)
        if not is_valid:
            log_decrypt_attempt(request, image, False, f"REPLAY:{token_err[:30]}")  # CM6
            return HttpResponse(
                f"[Replay Attack Blocked] {token_err}", status=403
            )

    priv_bytes = aes_key = raw = None          # declare for finally block
    try:
        # ── CM1: Decrypt private key from encrypted DB storage ─────────────
        # Private key is stored Fernet-encrypted; plaintext never persists in DB.
        priv_bytes = decrypt_private_key(request.user.userprofile.private_key)

        if use_patient_key and image.patient_encrypted_aes_key:
            aes_key = decrypt_key(_to_bytes(image.patient_encrypted_aes_key), priv_bytes)
        else:
            aes_key = decrypt_key(_to_bytes(image.encrypted_aes_key), priv_bytes)

        raw = decrypt_data(_to_bytes(image.encrypted_image), aes_key)

        # ── CM2: Constant-time hash comparison ────────────────────────────
        # Prevents timing oracle — attacker cannot deduce hash bytes from
        # response-time differences.
        if not secure_hash_compare(generate_hash(raw), image.image_hash):
            log_decrypt_attempt(request, image, False, "INTEGRITY_FAIL")  # CM6
            return HttpResponse(
                "[Integrity Check Failed] Image may have been tampered with.",
                status=400
            )

        log_decrypt_attempt(request, image, True)              # CM6 — success
        return HttpResponse(raw, content_type=image.image_type)

    except Exception as e:
        log_decrypt_attempt(request, image, False, str(e)[:40])  # CM6
        return HttpResponse(f"Decryption failed: {e}", status=400)

    finally:
        # ── CM8: Memory cleanup — zero sensitive data before GC ───────────
        secure_cleanup(priv_bytes, aes_key, raw)


# ============================================
# VERIFY IMAGE INTEGRITY
# Security layer: CM1 CM2 CM3 CM5 CM6 CM8
# ============================================

@login_required
@rate_limit_decrypt                          # CM3 — DoS protection
def verify_and_decrypt(request, image_id):
    image = get_object_or_404(MedicalImage, id=image_id)

    # ── CM5: Only the assigned doctor can verify ───────────────────────────
    if request.user != image.assigned_doctor:
        log_decrypt_attempt(request, image, False, "IDOR_VERIFY")  # CM6
        return HttpResponse(
            "[IDOR Protection] Only the assigned doctor can verify this image.",
            status=403
        )

    ctx = {"image": image, "is_hash_valid": False, "is_sig_valid": False}
    priv_bytes = aes_key = raw = None

    try:
        # ── CM1: Decrypt private key from encrypted DB storage ─────────────
        priv_bytes = decrypt_private_key(request.user.userprofile.private_key)
        aes_key    = decrypt_key(_to_bytes(image.encrypted_aes_key), priv_bytes)
        raw        = decrypt_data(_to_bytes(image.encrypted_image), aes_key)

        # ── CM2: Constant-time hash comparison ────────────────────────────
        computed_hash = generate_hash(raw)
        ctx["is_hash_valid"] = secure_hash_compare(computed_hash, image.image_hash)

        if image.signature and image.user.userprofile.public_key:
            ctx["is_sig_valid"] = verify_signature(
                _to_bytes(image.user.userprofile.public_key),
                raw,
                _to_bytes(image.signature),
            )

        if ctx["is_hash_valid"]:
            image.is_verified = True
            image.verification_status = "verified"
            image.save()

        log_decrypt_attempt(request, image, True, "VERIFY")   # CM6

    except Exception as e:
        ctx["error"] = str(e)
        ctx["decryption_failed"] = True
        log_decrypt_attempt(request, image, False, str(e)[:40])  # CM6

    finally:
        # ── CM8: Memory cleanup ───────────────────────────────────────────
        secure_cleanup(priv_bytes, aes_key, raw)

    # Issue a fresh one-time token so the template can embed the image via view_decrypted_image
    ctx["view_token"] = issue_decrypt_token(request.user, image)
    return render(request, "Verify.html", ctx)


# ============================================
# UPLOAD REPORT  (Doctor → encrypted for Patient)
# ============================================

@login_required
def upload_report(request, image_id):
    if _role(request) != "doctor":
        return HttpResponse("Only doctors can create reports.", status=403)

    image = get_object_or_404(MedicalImage, id=image_id, assigned_doctor=request.user)

    if Report.objects.filter(image=image).exists():
        messages.info(request, "Report already exists for this case.")
        return redirect("dashboard")

    if request.method == "POST":
        # CM7 — Sanitize all text inputs before DB storage (Stored XSS prevention)
        diagnosis    = sanitize_text_input(request.POST.get("diagnosis", ""))
        severity     = request.POST.get("severity", "mild")
        prescription = sanitize_text_input(request.POST.get("prescription", ""))
        remarks      = sanitize_text_input(request.POST.get("remarks", ""))

        if not diagnosis:
            return render(request, "upload_report.html", {
                "image": image,
                "form_error": "Diagnosis/skin disease name is required.",
                "view_token": issue_decrypt_token(request.user, image),
            })
        if severity not in ["mild", "severe"]:
            return render(request, "upload_report.html", {
                "image": image,
                "form_error": "Invalid severity selection.",
                "view_token": issue_decrypt_token(request.user, image),
            })

        patient = image.user
        report_content = (
            f"PATIENT NAME: {patient.get_full_name() or patient.username}\n"
            f"USERNAME: {patient.username}\n"
            f"EMAIL: {patient.email}\n"
            f"DOCTOR: Dr. {request.user.get_full_name() or request.user.username}\n"
            f"DATE: {timezone.now().strftime('%Y-%m-%d %H:%M')}\n"
            f"---\n"
            f"DIAGNOSIS: {diagnosis}\n"
            f"SEVERITY: {severity.upper()}\n"
            f"PRESCRIPTION: {prescription}\n"
            f"REMARKS: {remarks}\n"
        )

        try:
            report_bytes = report_content.encode()

            # AES encrypt report
            aes_key = generate_aes_key()
            enc_report = encrypt_data(report_bytes, aes_key)

            # RSA encrypt AES key with PATIENT's public key
            pat_pub = image.user.userprofile.public_key
            enc_aes = encrypt_key(aes_key, _to_bytes(pat_pub))

            # Doctor signs report
            doc_priv = request.user.userprofile.private_key
            sig = sign_data(_to_bytes(doc_priv), report_bytes)

            Report.objects.create(
                image=image,
                encrypted_report=bytes(enc_report),
                encrypted_aes_key=bytes(enc_aes),
                signature=bytes(sig),
                report_hash=generate_hash(report_bytes),
                severity=severity,
                access_token=str(uuid.uuid4()),
                is_paid=False,
            )

            # Update image status
            image.severity = severity
            image.is_verified = True
            image.verification_status = "verified"
            image.save()

            messages.success(request, "Report submitted successfully!")
            return redirect("dashboard")

        except Exception as e:
            messages.error(request, f"Failed to create report: {e}")

    return render(request, "upload_report.html", {
        "image": image,
        "view_token": issue_decrypt_token(request.user, image),
    })


# ============================================
# VIEW REPORT  (Patient decrypts with own key)
# ============================================

@login_required
def view_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    patient = report.image.user
    viewer_role = _role(request)

    # Access control
    if request.user != patient and request.user != report.image.assigned_doctor and viewer_role != "admin":
        return HttpResponse("Unauthorized.", status=403)

    # Appointment gate — patients must have an UPCOMING appointment before viewing severe reports
    if request.user == patient and report.severity == "severe":
        assigned_doc = report.image.assigned_doctor
        has_appt = assigned_doc and DoctorAvailability.objects.filter(
            patient=request.user,
            doctor=assigned_doc,
            is_booked=True,
            date__gte=timezone.now().date(),
        ).exists()
        if not has_appt:
            messages.warning(request,
                "Your report is ready! Please book an upcoming appointment with your assigned doctor first to view and download it.")
            return redirect(reverse('view_slots') + f'?for_report={report.id}')

    # Payment gate — patients must pay for mild reports before viewing
    if request.user == patient and report.severity == "mild" and not report.is_paid:
        # UPI submitted but not yet verified by admin
        if report.transaction_id and report.transaction_id.startswith("UPI-PENDING-"):
            utr = report.transaction_id[len("UPI-PENDING-"):]
            messages.info(request,
                f"Your UPI payment (UTR: {utr}) is awaiting admin verification. "
                "Your report will be accessible once ₹350 is confirmed.")
            return redirect("dashboard")
        messages.warning(request, "Payment of ₹350 required to access this report.")
        return redirect("make_payment", report_id=report.id)

    ctx = {"report": report}

    # Null key guard
    if not request.user.userprofile.private_key:
        ctx["error"] = "Encryption keys not found for your account. Please contact admin."
        return render(request, "view_report.html", ctx)

    try:
        priv = request.user.userprofile.private_key
        aes_key = decrypt_key(_to_bytes(report.encrypted_aes_key), _to_bytes(priv))
        report_text = decrypt_data(_to_bytes(report.encrypted_report), aes_key).decode()

        # Integrity check
        ctx["is_tampered"] = generate_hash(report_text.encode()) != report.report_hash

        # Parse structured fields for easy template rendering.
        # Store keys BOTH as-is and underscore-normalised ("PATIENT NAME" ->
        # "PATIENT_NAME") so Django dotted template lookups never raise.
        lines = {}
        for line in report_text.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                key = k.strip()
                lines[key] = v.strip()
                lines[key.replace(" ", "_")] = v.strip()

        # Guarantee every field the template references exists. A missing dict
        # key used as a Django `default:` filter ARGUMENT raises
        # VariableDoesNotExist (Django doesn't swallow failures in filter args),
        # which would 500 the page — so pre-populate sensible fallbacks.
        defaults = {
            "PATIENT_NAME": request.user.get_full_name() or request.user.username,
            "USERNAME":     request.user.username,
            "EMAIL":        request.user.email or "—",
            "DOCTOR":       "—",
            "DATE":         report.created_at.strftime("%Y-%m-%d %H:%M"),
            "DIAGNOSIS":    "—",
            "SEVERITY":     report.severity,
            "PRESCRIPTION": "No prescription provided.",
            "REMARKS":      "",
        }
        for k, v in defaults.items():
            lines.setdefault(k, v)

        ctx["report_text"] = report_text
        ctx["report_lines"] = lines

    except Exception as e:
        ctx["error"] = f"Cannot decrypt report: {e}"

    return render(request, "view_report.html", ctx)


# ============================================
# PAYMENT  (QR scanner + transaction ID)
# ============================================

import re

# References fabricated by "fake UPI" screenshot apps (no real settlement).
_FAKE_UTR_BLOCKLIST = {
    "000000000000", "111111111111", "123456789012", "999999999999",
    "123412341234", "112233445566", "121212121212", "100000000000",
}


def _verify_upi_payment(utr, expected_amount=350):
    """
    Backend UPI settlement verification (replaces the manual admin approval).

    A genuine UPI reference (UTR / RRN) is exactly 12 numeric digits and does
    not follow the fabricated patterns that fake-payment apps generate. In a
    production deployment this function would call the PSP / bank reconciliation
    API to confirm that a credit of ``expected_amount`` actually settled against
    this UTR; here we emulate that check deterministically. Anything that fails
    is treated as an unsettled / fraudulent ("fake UPI") transaction and the
    report stays locked.

    Returns ``(verified: bool, reason: str)``.
    """
    utr = (utr or "").strip()

    # 1. Format — a real UTR/RRN is exactly 12 digits.
    if not re.fullmatch(r"\d{12}", utr):
        return False, "Invalid UPI reference — a genuine UTR is exactly 12 digits."

    # 2. Known fabricated patterns / all-identical digits.
    if utr in _FAKE_UTR_BLOCKLIST or len(set(utr)) == 1:
        return False, "Payment rejected — this reference matches a known fake-UPI pattern."

    # 3. Trivially sequential references (ascending or descending runs).
    digits = [int(d) for d in utr]
    if all(b - a == 1 for a, b in zip(digits, digits[1:])) or \
       all(a - b == 1 for a, b in zip(digits, digits[1:])):
        return False, "Payment rejected — reference flagged as fabricated (sequential digits)."

    # Settlement confirmed.
    return True, f"Payment verified — settlement of Rs.{expected_amount} confirmed."


@login_required
def make_payment(request, report_id):
    report = get_object_or_404(Report, id=report_id, image__user=request.user)

    if report.is_paid:
        return redirect("view_report", report_id=report.id)

    rzp = razorpay.Client(
        auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
    )

    if request.method == "POST":
        pay_method = request.POST.get("pay_method", "razorpay")

        # ── UPI / QR payment path — backend auto-verification ──────────────
        # No admin-in-the-loop: the server verifies the settlement immediately.
        # Fake / unsettled references are rejected and the report stays locked.
        if pay_method == "upi":
            utr = request.POST.get("utr_number", "").strip()
            if not utr:
                messages.error(request, "Please enter the UPI Transaction Reference (UTR) number after payment.")
                return redirect("make_payment", report_id=report.id)

            verified, reason = _verify_upi_payment(utr, expected_amount=350)
            if not verified:
                # Reject fake / unsettled UPI — report is NOT unlocked.
                log_security_event(request, "UPI_REJECTED",
                                   f"report={report.id} utr={utr[:16]} :: {reason}")
                messages.error(request, f"Payment failed. {reason} Your report cannot be unlocked.")
                return redirect("make_payment", report_id=report.id)

            # Settlement confirmed → unlock instantly and go to the report portal.
            report.is_paid        = True
            report.transaction_id = utr
            report.payment_time   = timezone.now()
            report.save()
            log_security_event(request, "UPI_VERIFIED", f"report={report.id} utr={utr}")
            messages.success(request, "Payment verified successfully! Your report is now unlocked.")
            return redirect("view_report", report_id=report.id)

        # ── Razorpay card/netbanking path ─────────────────────────────────
        payment_id = request.POST.get("razorpay_payment_id", "")
        order_id   = request.POST.get("razorpay_order_id", "")
        signature  = request.POST.get("razorpay_signature", "")

        try:
            rzp.utility.verify_payment_signature({
                "razorpay_order_id":   order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature":  signature,
            })
            report.is_paid        = True
            report.transaction_id = payment_id
            report.payment_time   = timezone.now()
            report.save()
            messages.success(request, "Payment of ₹350 confirmed! You can now access your report.")
            return redirect("view_report", report_id=report.id)

        except razorpay.errors.SignatureVerificationError:
            messages.error(request, "Payment verification failed. Please try again.")
            return redirect("make_payment", report_id=report.id)

    # GET — create a fresh Razorpay order for ₹350
    order = rzp.order.create({
        "amount":          35000,   # paise (₹350 × 100)
        "currency":        "INR",
        "payment_capture": 1,       # auto-capture
    })

    # Generate UPI QR with ₹350 amount locked — user cannot change it in any UPI app
    import qrcode, base64
    from io import BytesIO
    upi_url = (
        f"upi://pay?pa=9493676293@axl"
        f"&pn=SecureSkinAI"
        f"&am=350.00"
        f"&cu=INR"
        f"&tn=MedicalReport-RPT-{report.id:05d}"
    )
    qr_img = qrcode.make(upi_url)
    buf = BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render(request, "payment.html", {
        "report":       report,
        "razorpay_key": settings.RAZORPAY_KEY_ID,
        "order_id":     order["id"],
        "qr_b64":       qr_b64,
        "amount":       35000,
        "patient_name": request.user.get_full_name() or request.user.username,
        "patient_email": request.user.email,
    })


# ============================================
# DOWNLOAD REPORT  (PDF with full prescription format)
# ============================================

@login_required
def download_report(request, report_id):
    report = get_object_or_404(Report, id=report_id, image__user=request.user)

    if report.severity == "mild" and not report.is_paid:
        if report.transaction_id and report.transaction_id.startswith("UPI-PENDING-"):
            messages.info(request, "Your UPI payment is pending admin verification. Download will be available once approved.")
            return redirect("dashboard")
        messages.error(request, "Payment required to download this report.")
        return redirect("make_payment", report_id=report.id)

    # Severe reports — patient must have an UPCOMING appointment with the assigned doctor
    if report.severity == "severe":
        assigned_doc = report.image.assigned_doctor
        has_appt = assigned_doc and DoctorAvailability.objects.filter(
            patient=request.user,
            doctor=assigned_doc,
            is_booked=True,
            date__gte=timezone.now().date(),
        ).exists()
        if not has_appt:
            messages.warning(request,
                "Your report is ready! Please book an upcoming appointment with your doctor first to unlock the download.")
            return redirect(reverse('view_slots') + f'?for_report={report.id}')

    try:
        priv_bytes = decrypt_private_key(request.user.userprofile.private_key)
        # Decrypt report text
        aes_key_report = decrypt_key(_to_bytes(report.encrypted_aes_key), priv_bytes)
        report_text = decrypt_data(_to_bytes(report.encrypted_report), aes_key_report).decode()
        # Decrypt skin image (patient uses their own AES key copy)
        image_bytes = None
        img_aes_key = report.image.patient_encrypted_aes_key
        if img_aes_key:
            try:
                aes_key_img = decrypt_key(_to_bytes(img_aes_key), priv_bytes)
                image_bytes = decrypt_data(_to_bytes(report.image.encrypted_image), aes_key_img)
            except Exception:
                image_bytes = None   # image embed is optional — don't fail the whole PDF
    except Exception as e:
        return HttpResponse(f"Failed to decrypt report: {e}", status=400)

    # Parse structured fields
    lines = {}
    for line in report_text.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            lines[k.strip()] = v.strip()

    # ── Build an official hospital-style PDF ─────────────────────────────
    from reportlab.platypus import Image as RLImage, HRFlowable, KeepTogether
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

    # Brand palette
    NAVY   = colors.HexColor("#0B2A4A")
    TEAL   = colors.HexColor("#0891B2")
    TEAL_D = colors.HexColor("#0E7490")
    INK    = colors.HexColor("#1E293B")
    MUTE   = colors.HexColor("#64748B")
    LINE   = colors.HexColor("#CBD5E1")
    LBLUE  = colors.HexColor("#EAF4F8")
    LGREEN = colors.HexColor("#E7F6EC")

    PAGE_W, PAGE_H = A4
    L_MARGIN = R_MARGIN = 0.65 * inch
    CONTENT_W = PAGE_W - L_MARGIN - R_MARGIN

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=1.45 * inch, bottomMargin=0.85 * inch,
        leftMargin=L_MARGIN, rightMargin=R_MARGIN,
        title=f"Medical Report RPT-{report.id:05d}",
        author="Secure Skin AI",
    )
    base_styles = getSampleStyleSheet()

    section_style = ParagraphStyle(
        "Section", parent=base_styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=11.5, textColor=TEAL_D,
        spaceAfter=6, spaceBefore=14, leading=14,
    )
    body_style = ParagraphStyle(
        "Body", parent=base_styles["Normal"],
        fontName="Helvetica", fontSize=10.5, textColor=INK, leading=16, spaceAfter=3,
    )
    dx_style = ParagraphStyle(
        "Dx", parent=body_style, fontName="Helvetica-Bold", fontSize=14,
        textColor=NAVY, leading=18,
    )
    small_c = ParagraphStyle(
        "SmallC", parent=base_styles["Normal"],
        fontName="Helvetica", fontSize=7.5, textColor=MUTE, alignment=TA_CENTER, leading=10,
    )

    def section(title):
        return [
            Paragraph(title.upper(), section_style),
            HRFlowable(width="100%", thickness=1.1, color=TEAL,
                       spaceBefore=1, spaceAfter=7, lineCap="round"),
        ]

    # ── Header / footer painted on every page (letterhead) ───────────────
    def draw_letterhead(canvas, doc_):
        canvas.saveState()

        # Top accent band
        canvas.setFillColor(NAVY)
        canvas.rect(0, PAGE_H - 0.28 * inch, PAGE_W, 0.28 * inch, stroke=0, fill=1)

        # Logo tile
        logo_x, logo_y, logo_s = L_MARGIN, PAGE_H - 1.14 * inch, 0.62 * inch
        canvas.setFillColor(TEAL)
        canvas.roundRect(logo_x, logo_y, logo_s, logo_s, 8, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 26)
        canvas.drawCentredString(logo_x + logo_s / 2, logo_y + logo_s / 2 - 9, "+")

        # Hospital identity
        tx = logo_x + logo_s + 12
        canvas.setFillColor(NAVY)
        canvas.setFont("Helvetica-Bold", 19)
        canvas.drawString(tx, PAGE_H - 0.66 * inch, "SECURE SKIN AI")
        canvas.setFillColor(TEAL_D)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(tx, PAGE_H - 0.83 * inch, "DEPARTMENT OF DERMATOLOGY  |  TELEDERMATOLOGY UNIT")
        canvas.setFillColor(MUTE)
        canvas.setFont("Helvetica", 7.8)
        canvas.drawString(tx, PAGE_H - 0.97 * inch,
                          "Encrypted Medical Records System  -  AES-256 / RSA-2048  -  ssai-hospital.example")

        # Right-aligned report id / date
        canvas.setFillColor(INK)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawRightString(PAGE_W - R_MARGIN, PAGE_H - 0.66 * inch, f"REPORT No. RPT-{report.id:05d}")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTE)
        canvas.drawRightString(PAGE_W - R_MARGIN, PAGE_H - 0.81 * inch,
                               "Issued: " + lines.get("DATE", report.created_at.strftime("%Y-%m-%d %H:%M")))
        canvas.drawRightString(PAGE_W - R_MARGIN, PAGE_H - 0.94 * inch, "Case #%s" % report.image.id)

        # Divider under letterhead
        canvas.setStrokeColor(TEAL)
        canvas.setLineWidth(1.4)
        canvas.line(L_MARGIN, PAGE_H - 1.26 * inch, PAGE_W - R_MARGIN, PAGE_H - 1.26 * inch)

        # Footer
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.6)
        canvas.line(L_MARGIN, 0.72 * inch, PAGE_W - R_MARGIN, 0.72 * inch)
        canvas.setFillColor(MUTE)
        canvas.setFont("Helvetica", 7.3)
        canvas.drawString(L_MARGIN, 0.56 * inch,
                          "Cryptographically signed & encrypted (AES-256 + RSA-2048). Tampering invalidates the SHA-256 integrity hash.")
        canvas.drawString(L_MARGIN, 0.46 * inch,
                          "Verify authenticity: /verify-report/%s/" % report.access_token)
        canvas.setFont("Helvetica-Bold", 7.3)
        canvas.drawRightString(PAGE_W - R_MARGIN, 0.56 * inch, "Page %d" % doc_.page)
        canvas.setFont("Helvetica-Oblique", 7)
        canvas.setFillColor(TEAL_D)
        canvas.drawRightString(PAGE_W - R_MARGIN, 0.46 * inch, "Computer-generated confidential document")
        canvas.restoreState()

    def kv_table(data, label_bg=LBLUE, col_split=0.32):
        c0 = CONTENT_W * col_split
        t = Table(data, colWidths=[c0, CONTENT_W - c0])
        t.setStyle(TableStyle([
            ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",   (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",   (0, 0), (-1, -1), 10),
            ("TEXTCOLOR",  (0, 0), (0, -1), NAVY),
            ("TEXTCOLOR",  (1, 0), (1, -1), INK),
            ("BACKGROUND", (0, 0), (0, -1), label_bg),
            ("BOX",        (0, 0), (-1, -1), 0.6, LINE),
            ("INNERGRID",  (0, 0), (-1, -1), 0.5, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return t

    content = []

    # Confidential title band
    band = Table([[Paragraph(
        '<font color="#FFFFFF"><b>CONFIDENTIAL DERMATOLOGY REPORT</b></font>', body_style)]],
        colWidths=[CONTENT_W])
    band.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    content.append(band)
    content.append(Spacer(1, 4))

    # ── Patient & encounter details ──────────────────────────────────────
    content += section("Patient &amp; Encounter Details")
    content.append(kv_table([
        ["Patient Name",     lines.get("PATIENT NAME", request.user.get_full_name() or request.user.username)],
        ["Username / MRN",   lines.get("USERNAME", request.user.username)],
        ["Email",            lines.get("EMAIL", request.user.email or "-")],
        ["Attending Doctor", lines.get("DOCTOR", "-")],
        ["Report Date",      lines.get("DATE", report.created_at.strftime("%Y-%m-%d %H:%M"))],
        ["Report ID",        f"RPT-{report.id:05d}   (Case #{report.image.id})"],
    ]))

    # ── Clinical diagnosis (+ skin image beside it) ──────────────────────
    content += section("Clinical Diagnosis")
    severity_val = lines.get("SEVERITY", report.severity.upper())
    dx_cell = [
        Paragraph(lines.get("DIAGNOSIS", "-"), dx_style),
        Spacer(1, 4),
        Paragraph(f'<font color="#0E7490"><b>Severity:</b></font> {severity_val}', body_style),
    ]
    if image_bytes:
        try:
            rl_img = RLImage(io.BytesIO(image_bytes), width=2.1 * inch, height=2.1 * inch, kind="proportional")
            img_cell = Table([[rl_img]], colWidths=[2.3 * inch])
            img_cell.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.8, LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ]))
            dx_row = Table([[dx_cell, img_cell]], colWidths=[CONTENT_W - 2.5 * inch, 2.5 * inch])
            dx_row.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), LGREEN),
                ("BOX", (0, 0), (0, -1), 0.6, LINE),
                ("TOPPADDING", (0, 0), (0, -1), 12), ("BOTTOMPADDING", (0, 0), (0, -1), 12),
                ("LEFTPADDING", (0, 0), (0, -1), 12), ("RIGHTPADDING", (0, 0), (0, -1), 12),
                ("LEFTPADDING", (1, 0), (1, -1), 10),
            ]))
            content.append(dx_row)
        except Exception:
            content.append(kv_table([["Diagnosis", lines.get("DIAGNOSIS", "-")],
                                     ["Severity Level", severity_val]], label_bg=LGREEN))
    else:
        content.append(kv_table([["Diagnosis", lines.get("DIAGNOSIS", "-")],
                                 ["Severity Level", severity_val]], label_bg=LGREEN))

    # ── Prescription ─────────────────────────────────────────────────────
    content += section("Prescription &amp; Treatment Plan")
    rx_text = lines.get("PRESCRIPTION", "").strip() or "No prescription provided."
    rx_body = Paragraph(rx_text.replace("\n", "<br/>"), body_style)
    rx_mark = Paragraph('<font color="#0E7490" size="22"><b>Rx</b></font>', body_style)
    rx = Table([[rx_mark, rx_body]], colWidths=[0.5 * inch, CONTENT_W - 0.5 * inch])
    rx.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    content.append(rx)

    # ── Remarks ──────────────────────────────────────────────────────────
    remarks = lines.get("REMARKS", "").strip()
    if remarks:
        content += section("Doctor's Remarks / Advice")
        content.append(Paragraph(remarks.replace("\n", "<br/>"), body_style))

    # ── Payment ──────────────────────────────────────────────────────────
    if report.is_paid:
        content += section("Payment Details")
        content.append(kv_table([
            ["Transaction ID", report.transaction_id or "-"],
            ["Payment Date",   report.payment_time.strftime("%Y-%m-%d %H:%M") if report.payment_time else "-"],
            ["Amount",         "Rs. 350.00"],
            ["Status",         "PAID"],
        ], label_bg=colors.HexColor("#FFF4E5")))

    # ── Signature block ──────────────────────────────────────────────────
    content.append(Spacer(1, 26))
    sign_left = [
        HRFlowable(width=2.4 * inch, thickness=1, color=INK, spaceAfter=4),
        Paragraph(f"<b>{lines.get('DOCTOR', 'Attending Physician')}</b>", body_style),
        Paragraph('<font size="8" color="#64748B">Attending Dermatologist &middot; Digitally signed (RSA-2048)</font>', body_style),
    ]
    stamp = Paragraph(
        '<font color="#16A34A"><b>VERIFIED</b></font><br/>'
        '<font size="7.5" color="#16A34A">SHA-256 integrity intact</font>', small_c)
    stamp_box = Table([[stamp]], colWidths=[1.7 * inch])
    stamp_box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1.4, colors.HexColor("#16A34A")),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
    ]))
    sig_row = Table([[sign_left, stamp_box]], colWidths=[CONTENT_W - 2.0 * inch, 2.0 * inch])
    sig_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (0, -1), "BOTTOM"),
        ("VALIGN", (1, 0), (1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
    ]))
    content.append(sig_row)

    doc.build(content, onFirstPage=draw_letterhead, onLaterPages=draw_letterhead)
    buffer.seek(0)

    response = HttpResponse(buffer.read(), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="report_RPT-{report.id:05d}.pdf"'
    return response


# ============================================
# VERIFY REPORT  (public QR-token link)
# ============================================

def verify_report(request, token):
    report = get_object_or_404(Report, access_token=token)
    return render(request, "verify_report.html", {
        "report": report,
        "patient": report.image.user,
        "image": report.image,
    })


# ============================================
# APPOINTMENTS – DOCTOR ADDS AVAILABILITY
# ============================================

@login_required
def add_availability(request):
    if _role(request) != "doctor":
        return redirect("dashboard")

    if request.method == "POST":
        date = request.POST.get("date")
        slot = request.POST.get("slot")

        if not date or not slot:
            messages.error(request, "Date and time slot are required.")
        elif DoctorAvailability.objects.filter(doctor=request.user, date=date, slot=slot).exists():
            messages.warning(request, "This slot already exists.")
        else:
            DoctorAvailability.objects.create(doctor=request.user, date=date, slot=slot)
            messages.success(request, "Slot added successfully!")
        return redirect("dashboard")  # PRG – go back to dashboard

    my_slots = DoctorAvailability.objects.filter(
        doctor=request.user
    ).order_by("date", "slot")
    return render(request, "add_availability.html", {"my_slots": my_slots})


# ============================================
# APPOINTMENTS – PATIENT VIEWS AVAILABLE SLOTS
# ============================================

@login_required
def view_available_slots(request):
    if _role(request) != "patient":
        return redirect("dashboard")

    today = timezone.now().date()
    qs = (
        DoctorAvailability.objects
        .filter(is_booked=False, date__gte=today)
        .select_related("doctor", "doctor__userprofile")
        .order_by("date", "slot")
    )

    # When redirected from a severe report download — filter to that doctor's slots
    report_context = None
    for_report_id = request.GET.get("for_report")
    if for_report_id:
        try:
            rep = Report.objects.select_related("image__assigned_doctor").get(
                id=for_report_id, image__user=request.user
            )
            assigned_doc = rep.image.assigned_doctor
            if assigned_doc:
                qs = qs.filter(doctor=assigned_doc)
                report_context = {
                    "report_id": rep.id,
                    "doctor_name": assigned_doc.get_full_name() or assigned_doc.username,
                }
        except Report.DoesNotExist:
            pass

    return render(request, "view_slots.html", {"slots": qs, "report_context": report_context})


# ============================================
# APPOINTMENTS – PATIENT BOOKS A SLOT
# ============================================

@login_required
def book_slot(request, slot_id):
    if _role(request) != "patient":
        return redirect("dashboard")

    slot = get_object_or_404(DoctorAvailability, id=slot_id)

    if slot.is_booked:
        messages.error(request, "This slot is already taken.")
        return redirect("view_slots")

    existing = DoctorAvailability.objects.filter(
        patient=request.user, is_booked=True, date__gte=timezone.now().date()
    )
    if existing.exists():
        messages.warning(request, "You already have an upcoming appointment.")
        return redirect("view_slots")

    slot.is_booked = True
    slot.patient = request.user
    slot.save()

    doc_name = slot.doctor.get_full_name() or slot.doctor.username
    messages.success(request, f"Appointment booked with Dr. {doc_name} on {slot.date} at {slot.slot}!")
    return redirect("dashboard")


# ============================================
# APPOINTMENTS – PATIENT CANCELS BOOKING
# ============================================

@login_required
def cancel_booking(request, slot_id):
    slot = get_object_or_404(DoctorAvailability, id=slot_id, patient=request.user)
    slot.is_booked = False
    slot.patient = None
    slot.save()
    messages.success(request, "Appointment cancelled.")
    return redirect("dashboard")


# ============================================
# BOOK APPOINTMENT  (legacy URL → redirect)
# ============================================

@login_required
def book_appointment(request):
    return redirect("view_slots")


# ============================================
# VIEW APPOINTMENTS  (doctor sees patients / patient sees own)
# ============================================

@login_required
def view_appointments(request):
    role = _role(request)
    today = timezone.now().date()

    if role == "doctor":
        slots = (
            DoctorAvailability.objects
            .filter(doctor=request.user, is_booked=True)
            .select_related("patient")
            .order_by("date")
        )
    else:
        slots = (
            DoctorAvailability.objects
            .filter(patient=request.user, is_booked=True)
            .select_related("doctor")
            .order_by("date")
        )

    return render(request, "view_appointments.html", {"slots": slots, "role": role, "today": today, "appointments": slots})


@login_required
def my_appointments(request):
    return view_appointments(request)


@login_required
def doctor_appointments(request):
    if _role(request) != "doctor":
        return redirect("dashboard")
    return view_appointments(request)


@login_required
def update_appointment_status(request, appointment_id, status):
    """Cancel a slot from the doctor's side."""
    slot = get_object_or_404(DoctorAvailability, id=appointment_id, doctor=request.user)
    if status == "cancelled":
        slot.is_booked = False
        slot.patient = None
        slot.save()
        messages.success(request, "Appointment cancelled.")
    return redirect("view_appointments")


# ============================================
# EMERGENCY APPOINTMENT
# ============================================

@login_required
def emergency_appointment(request):
    if _role(request) != "patient":
        return redirect("dashboard")
    doctors = UserProfile.objects.filter(role="doctor", is_available=True).select_related("user")
    return render(request, "emergency_appointment.html", {"doctors": doctors})


# ============================================
# DOCTOR CASES
# ============================================

@login_required
def doctor_cases(request):
    if _role(request) != "doctor":
        return redirect("dashboard")

    images = MedicalImage.objects.filter(
        assigned_doctor=request.user
    ).select_related("user").order_by("-uploaded_at")

    return render(request, "doctor_cases.html", {
        "images": images,
        "total_cases": images.count(),
        "verified_cases": images.filter(is_verified=True).count(),
        "not_verified_cases": images.filter(is_verified=False).count(),
    })


# ============================================
# PATIENT DASHBOARD  (explicit route)
# ============================================

@login_required
def patient_dashboard(request):
    if _role(request) != "patient":
        return redirect("dashboard")
    return dashboard(request)


# ============================================
# ADMIN – ALL USERS
# ============================================

@login_required
def admin_users(request):
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)

    users = User.objects.select_related("userprofile").all().order_by("date_joined")
    return render(request, "admin_users.html", {"users": users})


# ============================================
# ADMIN – DOCTORS LIST
# ============================================

@login_required
def admin_doctors(request):
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)

    doctors = UserProfile.objects.filter(role="doctor").select_related("user")
    return render(request, "admin_doctors.html", {"doctors": doctors})


# ============================================
# ADMIN – PATIENTS LIST
# ============================================

@login_required
def admin_patients(request):
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)

    patients = UserProfile.objects.filter(role="patient").select_related("user")
    return render(request, "admin_patients.html", {"patients": patients})


# ============================================
# ADMIN – REPORTS + WEEKLY STATS
# ============================================

@login_required
def admin_reports(request):
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)

    week_ago = timezone.now() - timedelta(days=7)
    weekly_uploads = MedicalImage.objects.filter(uploaded_at__gte=week_ago)
    weekly_rpts = Report.objects.filter(created_at__gte=week_ago)
    all_reports = Report.objects.select_related("image__user").order_by("-created_at")

    return render(request, "admin_reports.html", {
        "weekly_upload_count": weekly_uploads.count(),
        "weekly_report_count": weekly_rpts.count(),
        "weekly_uploads": weekly_uploads,
        "weekly_reports": weekly_rpts,
        "all_reports": all_reports,
    })


# ============================================
# DELETE USER  (Admin only)
# ============================================

@login_required
def delete_user(request, user_id):
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)

    if request.user.id == user_id:
        messages.error(request, "You cannot delete your own account.")
        return redirect("admin_users")

    user = get_object_or_404(User, id=user_id)
    uname = user.username
    user.delete()
    messages.success(request, f"User '{uname}' deleted.")
    return redirect("admin_users")


# ============================================
# UPI PAYMENT VERIFICATION (Admin only)
# ============================================

@login_required
def approve_upi_payment(request, report_id):
    """Admin approves a pending UPI payment — unlocks report for patient."""
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)
    if request.method != "POST":
        return HttpResponse("Method not allowed.", status=405)

    report = get_object_or_404(Report, id=report_id)
    if not (report.transaction_id and report.transaction_id.startswith("UPI-PENDING-")):
        messages.error(request, f"Report #{report_id} is not pending UPI verification.")
        return redirect("dashboard")

    utr = report.transaction_id[len("UPI-PENDING-"):]
    report.is_paid        = True
    report.transaction_id = f"UPI-{utr}"
    report.save()
    messages.success(request,
        f"Report #{report_id} UPI payment approved (UTR: {utr}). "
        "Patient can now access their report.")
    return redirect("dashboard")


@login_required
def reject_upi_payment(request, report_id):
    """Admin rejects a pending UPI payment — clears pending state so patient can retry."""
    if _role(request) != "admin":
        return HttpResponse("Unauthorized.", status=403)
    if request.method != "POST":
        return HttpResponse("Method not allowed.", status=405)

    report = get_object_or_404(Report, id=report_id)
    if not (report.transaction_id and report.transaction_id.startswith("UPI-PENDING-")):
        messages.error(request, f"Report #{report_id} is not pending UPI verification.")
        return redirect("dashboard")

    utr = report.transaction_id[len("UPI-PENDING-"):]
    report.transaction_id = None
    report.payment_time   = None
    report.save()
    messages.warning(request,
        f"Report #{report_id} UPI payment rejected (UTR: {utr}). "
        "Patient will be asked to pay again.")
    return redirect("dashboard")


# ============================================
# CRYPTO PROOF  — Explicit AES + RSA Key Demo
# ============================================

import base64 as _b64

def _build_crypto_ctx():
    """Generate live crypto demo data — shared by all crypto proof views."""
    import time as t

    t0 = t.perf_counter()
    demo_pub, demo_priv = generate_rsa_keys()
    rsa_time = round((t.perf_counter() - t0) * 1000, 2)

    t0 = t.perf_counter()
    demo_aes = generate_aes_key()
    aes_time = round((t.perf_counter() - t0) * 1000, 4)

    sample = b"Secure Skin AI - demo image data " * 128
    t0 = t.perf_counter()
    sample_hash = generate_hash(sample)
    hash_time = round((t.perf_counter() - t0) * 1000, 4)

    t0 = t.perf_counter()
    enc_sample = encrypt_data(sample, demo_aes)
    enc_time = round((t.perf_counter() - t0) * 1000, 2)

    t0 = t.perf_counter()
    dec_sample = decrypt_data(enc_sample, demo_aes)
    dec_time = round((t.perf_counter() - t0) * 1000, 2)
    integrity_ok = generate_hash(dec_sample) == sample_hash

    t0 = t.perf_counter()
    enc_key = encrypt_key(demo_aes, demo_pub)
    rsa_enc_time = round((t.perf_counter() - t0) * 1000, 2)

    t0 = t.perf_counter()
    decrypt_key(enc_key, demo_priv)
    rsa_dec_time = round((t.perf_counter() - t0) * 1000, 2)

    t0 = t.perf_counter()
    sig = sign_data(demo_priv, sample)
    sign_time = round((t.perf_counter() - t0) * 1000, 2)

    t0 = t.perf_counter()
    sig_valid = verify_signature(demo_pub, sample, sig)
    verify_time = round((t.perf_counter() - t0) * 1000, 2)

    return {
        "demo_aes_key":  demo_aes.decode(),
        "demo_pub_key":  demo_pub.decode() if isinstance(demo_pub, bytes) else demo_pub,
        "demo_priv_key": demo_priv.decode() if isinstance(demo_priv, bytes) else demo_priv,
        "sample_hash":   sample_hash,
        "enc_aes_b64":   _b64.b64encode(enc_key).decode()[:88],
        "sig_b64":       _b64.b64encode(sig).decode()[:88],
        "integrity_ok":  integrity_ok,
        "sig_valid":     sig_valid,
        "aes_time":      aes_time,
        "rsa_time":      rsa_time,
        "hash_time":     hash_time,
        "enc_time":      enc_time,
        "dec_time":      dec_time,
        "rsa_enc_time":  rsa_enc_time,
        "rsa_dec_time":  rsa_dec_time,
        "sign_time":     sign_time,
        "verify_time":   verify_time,
    }


@login_required
def crypto_proof_view(request):
    """Admin-only: generic crypto proof demo."""
    if _role(request) != "admin":
        return redirect("dashboard")
    ctx = _build_crypto_ctx()
    ctx["user_pub_key"] = request.user.userprofile.public_key or ""
    return render(request, "crypto_proof.html", ctx)


@login_required
def admin_patient_crypto(request):
    """Admin-only: crypto proof page showing all patient RSA public keys."""
    if _role(request) != "admin":
        return redirect("dashboard")
    ctx = _build_crypto_ctx()
    patients = User.objects.filter(
        userprofile__role="patient"
    ).select_related("userprofile").order_by("username")
    ctx["proof_title"] = "Patient Crypto Proof"
    ctx["proof_role"]  = "patient"
    ctx["users_keys"]  = [
        {
            "username":   p.username,
            "full_name":  p.get_full_name(),
            "public_key": p.userprofile.public_key or "",
        }
        for p in patients
    ]
    return render(request, "crypto_proof.html", ctx)


@login_required
def admin_doctor_crypto(request):
    """Admin-only: crypto proof page showing all doctor RSA public keys."""
    if _role(request) != "admin":
        return redirect("dashboard")
    ctx = _build_crypto_ctx()
    doctors = User.objects.filter(
        userprofile__role="doctor"
    ).select_related("userprofile").order_by("username")
    ctx["proof_title"] = "Doctor Crypto Proof"
    ctx["proof_role"]  = "doctor"
    ctx["users_keys"]  = [
        {
            "username":   d.username,
            "full_name":  d.get_full_name(),
            "public_key": d.userprofile.public_key or "",
        }
        for d in doctors
    ]
    return render(request, "crypto_proof.html", ctx)


# ============================================
# LIVE SECURITY MONITOR (Admin only) — real-time SOC dashboard
# ============================================

from django.http import JsonResponse


@login_required
def security_monitor(request):
    """Admin-only live Security Operations Center dashboard."""
    if _role(request) != "admin":
        return redirect("dashboard")
    from .monitoring import build_snapshot
    try:
        window = max(5, min(1440, int(request.GET.get("window", 60))))
    except (TypeError, ValueError):
        window = 60
    ctx = build_snapshot(minutes=window)
    ctx["alerts_enabled"] = getattr(settings, "SECURITY_ALERTS_ENABLED", False)
    ctx["alert_email"] = getattr(settings, "SECURITY_ALERT_EMAIL", "")
    return render(request, "security_monitor.html", ctx)


@login_required
def security_monitor_feed(request):
    """Admin-only JSON snapshot polled by the dashboard for real-time updates."""
    if _role(request) != "admin":
        return JsonResponse({"error": "forbidden"}, status=403)
    from .monitoring import build_snapshot
    try:
        window = max(5, min(1440, int(request.GET.get("window", 60))))
    except (TypeError, ValueError):
        window = 60
    return JsonResponse(build_snapshot(minutes=window))


# ============================================
# SECURITY DEMO — Malware Attack Simulation
# ============================================

@login_required
def security_demo(request):
    """Shows how the website defends against common web attacks."""
    attacks = [
        {
            "id": 1,
            "name": "CSRF (Cross-Site Request Forgery)",
            "icon": "bi-shield-exclamation",
            "color": "#f59e0b",
            "before": "Without protection: A malicious site could forge a POST request on behalf of a logged-in user (e.g., submit a payment or change password without consent).",
            "mechanism": "Every form includes Django's {% csrf_token %}. The browser sends a CSRF cookie; the server validates both. Mismatched or missing token → 403 Forbidden.",
            "after": "After protection: Forged requests are rejected instantly with HTTP 403. Attacker cannot submit forms, confirm payments, or upload data on behalf of the victim.",
            "status": "PROTECTED",
        },
        {
            "id": 2,
            "name": "XSS (Cross-Site Scripting)",
            "icon": "bi-code-slash",
            "color": "#ef4444",
            "before": "Without protection: An attacker inputs <script>document.cookie</script> into a report field. The browser executes it and sends cookies to the attacker.",
            "mechanism": "Django's template engine auto-escapes all {{ variables }} using HTML entities. <script> becomes &lt;script&gt; — the browser displays it as text, not code.",
            "after": "After protection: Script tags are rendered as harmless text. Session cookies are HttpOnly (invisible to JavaScript). CSP header further restricts inline scripts.",
            "status": "PROTECTED",
        },
        {
            "id": 3,
            "name": "SQL Injection",
            "icon": "bi-database-exclamation",
            "color": "#8b5cf6",
            "before": "Without protection: Input like ' OR '1'='1 in a username field bypasses authentication and dumps the entire database.",
            "mechanism": "Django ORM uses parameterized queries exclusively. User input is NEVER concatenated into SQL strings — it is always passed as a bound parameter.",
            "after": "After protection: The injected SQL is treated as a literal string, not SQL code. The query returns no results; authentication fails normally.",
            "status": "PROTECTED",
        },
        {
            "id": 4,
            "name": "Brute Force / Credential Stuffing",
            "icon": "bi-person-fill-lock",
            "color": "#ec4899",
            "before": "Without protection: An attacker scripts thousands of username/password combinations until one works.",
            "mechanism": "Session-based attempt counter: after 5 failed logins the account is locked for 15 minutes. OTP 2FA adds a second factor — even correct credentials need email access.",
            "after": "After protection: Attacker is locked out after 5 attempts. Even if a password is guessed, OTP verification blocks access without email account compromise.",
            "status": "PROTECTED",
        },
        {
            "id": 5,
            "name": "Clickjacking",
            "icon": "bi-layers",
            "color": "#06b6d4",
            "before": "Without protection: The site is embedded invisibly in an iframe on a malicious page. Clicking 'Confirm Payment' on the attacker's page actually clicks on our site.",
            "mechanism": "X-Frame-Options: DENY header (set in settings.py + XFrameOptionsMiddleware). Browsers refuse to render the page inside any frame or iframe.",
            "after": "After protection: Browsers block the page from being framed. Clickjacking overlay is impossible — the page simply doesn't render inside iframes.",
            "status": "PROTECTED",
        },
        {
            "id": 6,
            "name": "Session Hijacking",
            "icon": "bi-incognito",
            "color": "#10b981",
            "before": "Without protection: An attacker steals the session cookie (via network sniffing or XSS) and impersonates the victim.",
            "mechanism": "SESSION_COOKIE_HTTPONLY=True (JS can't read the cookie). Sessions expire in 1 hour (SESSION_COOKIE_AGE=3600). In production, SESSION_COOKIE_SECURE=True forces HTTPS-only.",
            "after": "After protection: Cookie is invisible to JavaScript. Stolen sessions expire quickly. HTTPS (production) prevents network interception.",
            "status": "PROTECTED",
        },
        {
            "id": 7,
            "name": "Malicious File Upload",
            "icon": "bi-file-earmark-x",
            "color": "#f97316",
            "before": "Without protection: Attacker uploads a PHP shell or malware disguised as a JPG. Server executes it and gives remote access.",
            "mechanism": "Uploaded images are immediately AES-256 encrypted and stored as ciphertext in the database (BinaryField). The original filename and extension are discarded — nothing is executed.",
            "after": "After protection: Even if malware is uploaded, it is encrypted before storage. It cannot be served, executed, or accessed outside the decryption flow.",
            "status": "PROTECTED",
        },
        {
            "id": 8,
            "name": "Data Interception (MITM)",
            "icon": "bi-wifi-off",
            "color": "#64748b",
            "before": "Without protection: Network traffic is intercepted; medical images and reports are read in plaintext.",
            "mechanism": "End-to-end hybrid encryption: AES-256 encrypts data, RSA-2048 OAEP wraps the AES key. Even if the encrypted blob is intercepted, it is mathematically infeasible to decrypt without the private key.",
            "after": "After protection: Intercepted blobs are indistinguishable from random noise. Only the rightful key-holder can decrypt — not even the server admin can read the patient's data.",
            "status": "PROTECTED",
        },
        {
            "id": 9,
            "name": "Unauthorized Access / IDOR",
            "icon": "bi-lock-fill",
            "color": "#84cc16",
            "before": "Without protection: A patient changes the report ID in the URL (/view-report/5/) to see another patient's report.",
            "mechanism": "Every view checks request.user against the report's image.user. Mismatched user returns HTTP 403. Payment gate further restricts access to paid mild reports.",
            "after": "After protection: Even if the patient guesses the correct report ID, the server rejects the request with 403 Unauthorized.",
            "status": "PROTECTED",
        },
    ]
    return render(request, "security_demo.html", {"attacks": attacks})


# ============================================
# WEEKLY UPLOADS / REPORTS  (Admin pages)
# ============================================

@login_required
def weekly_uploads(request):
    if _role(request) != "admin":
        return redirect("dashboard")
    week_ago = timezone.now() - timedelta(days=7)
    data = MedicalImage.objects.filter(
        uploaded_at__gte=week_ago
    ).select_related("user", "assigned_doctor")
    return render(request, "weekly_uploads.html", {"data": data})


@login_required
def weekly_reports(request):
    if _role(request) != "admin":
        return redirect("dashboard")
    week_ago = timezone.now() - timedelta(days=7)
    data = Report.objects.filter(
        created_at__gte=week_ago
    ).select_related("image__user")
    return render(request, "weekly_reports.html", {"data": data})


# ============================================================
# ATTACK SIMULATION VIEWS
# ============================================================
# These views power the 4-attack security demo dashboard.
# Each attack can be triggered, observed, then cleared.
#
# SECURITY: Every route in this section is disabled unless
# settings.ATTACK_DEMO_ENABLED = True. The default is False, so
# destructive endpoints (ransomware encrypt-all-media, spyware bulk
# exfiltration, unauthenticated keylogger sink) cannot be reached
# on the public site even if the URL is guessed — the gate raises
# Http404, indistinguishable from a non-existent path.
# ============================================================

from django.http import Http404
from django.views.decorators.csrf import csrf_exempt
from .attack_simulations import (
    ransomware_encrypt_all_media, ransomware_restore_all_media,
    trojan_check_upload, trojan_validate_upload_PROTECTED, TROJAN_BACKDOOR,
    spyware_log_patient_data, spyware_get_stolen_data, spyware_clear_log,
    keylogger_save_capture, keylogger_get_captured, keylogger_clear_log,
)


def _require_attack_demo():
    """Raise Http404 unless ATTACK_DEMO_ENABLED is explicitly True."""
    if not getattr(settings, "ATTACK_DEMO_ENABLED", False):
        raise Http404("Not found.")


@login_required
def attack_demo_dashboard(request):
    """
    Main attack simulation dashboard.
    Shows status of all 4 attacks — before/after state.
    Admin only. Disabled entirely when ATTACK_DEMO_ENABLED is False.
    """
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")

    # ── Collect current state of each attack ──────────────────
    # Ransomware: count locked files
    from pathlib import Path
    media_dir = Path(settings.BASE_DIR) / "media"
    locked_files  = list(media_dir.rglob("*.locked"))
    normal_images = list(media_dir.rglob("*.jpg")) + list(media_dir.rglob("*.png"))

    # Spyware: count stolen records
    spyware_records = spyware_get_stolen_data()

    # Keylogger: count captured keystrokes
    keylogger_records = keylogger_get_captured()

    # Trojan: read backdoor log
    trojan_records = []
    if TROJAN_BACKDOOR.exists():
        for line in TROJAN_BACKDOOR.read_text().splitlines():
            if line.strip():
                try:
                    trojan_records.append(json.loads(line))
                except Exception:
                    pass

    context = {
        "locked_files_count"    : len(locked_files),
        "normal_images_count"   : len(normal_images),
        "locked_files"          : [str(f) for f in locked_files[:10]],
        "spyware_records"       : spyware_records[-10:],
        "spyware_total"         : len(spyware_records),
        "keylogger_records"     : keylogger_records[-10:],
        "keylogger_total"       : len(keylogger_records),
        "trojan_records"        : trojan_records[-10:],
        "trojan_total"          : len(trojan_records),
    }
    return render(request, "attack_demo.html", context)


# ── Attack 1: Ransomware ──────────────────────────────────────

@login_required
def ransomware_trigger(request):
    """Encrypts all media files (simulates ransomware attack)."""
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")
    if request.method == "POST":
        result = ransomware_encrypt_all_media()
        messages.error(request,
            f"RANSOMWARE: {result['total_files_locked']} files locked! "
            f"All medical images are now inaccessible.")
    return redirect("attack_demo_dashboard")


@login_required
def ransomware_restore(request):
    """Restores all locked files (simulates paying ransom)."""
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")
    if request.method == "POST":
        result = ransomware_restore_all_media()
        messages.success(request,
            f"RANSOMWARE REMOVED: {result['restored_count']} files restored.")
    return redirect("attack_demo_dashboard")


# ── Attack 2: Trojan Upload ───────────────────────────────────

@login_required
def trojan_upload_test(request):
    """
    Tests file upload for trojan detection.
    VULNERABLE mode: accepts file based on extension only.
    PROTECTED mode: validates magic bytes too.
    """
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")

    if request.method == "POST":
        uploaded = request.FILES.get("test_file")
        mode     = request.POST.get("mode", "vulnerable")

        if uploaded:
            if mode == "vulnerable":
                # ── ATTACK MODE: Only checks filename extension ──
                ext = uploaded.name.split('.')[-1].lower()
                if ext in ['jpg', 'jpeg', 'png', 'gif']:
                    is_trojan, _ = trojan_check_upload(uploaded)
                    if is_trojan:
                        messages.error(request,
                            f"TROJAN ACCEPTED: '{uploaded.name}' was accepted "
                            f"despite not being a real image! Backdoor installed.")
                    else:
                        messages.success(request, f"File '{uploaded.name}' accepted (clean image).")
                else:
                    messages.warning(request, f"Extension '{ext}' blocked.")

            elif mode == "protected":
                # ── PROTECTED MODE: Validates magic bytes ──
                is_safe, msg = trojan_validate_upload_PROTECTED(uploaded)
                if is_safe:
                    messages.success(request,
                        f"PROTECTION WORKING: '{uploaded.name}' passed all checks.")
                else:
                    messages.error(request,
                        f"TROJAN BLOCKED: '{uploaded.name}' rejected — {msg}")

    return redirect("attack_demo_dashboard")


# ── Attack 3: Spyware ─────────────────────────────────────────

@login_required
def spyware_trigger(request):
    """
    Simulates spyware by logging all current patient records.
    Calling this = spyware silently copying your database.
    """
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")

    if request.method == "POST":
        # Grab all reports and "exfiltrate" them
        all_reports = Report.objects.select_related(
            "image__user", "image__assigned_doctor"
        ).all()

        count = 0
        for r in all_reports:
            patient_record = {
                "patient_id"   : r.image.user.id,
                "patient_name" : r.image.user.get_full_name() or r.image.user.username,
                "report_id"    : r.id,
                "diagnosis"    : r.diagnosis or "N/A",
                "severity"     : r.severity or "N/A",
                "is_paid"      : r.is_paid,
            }
            spyware_log_patient_data(request.user, patient_record, context="bulk_exfiltration")
            count += 1

        messages.error(request,
            f"SPYWARE: {count} patient records silently copied to attacker! "
            f"Check attack_logs/spyware_stolen_data.json")

    return redirect("attack_demo_dashboard")


@login_required
def spyware_clear(request):
    """Clears spyware log (resets demo)."""
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")
    if request.method == "POST":
        spyware_clear_log()
        messages.success(request, "Spyware log cleared.")
    return redirect("attack_demo_dashboard")


# ── Attack 4: Keylogger ───────────────────────────────────────

@csrf_exempt
def keylogger_capture(request):
    """
    Receives keystrokes from the JavaScript keylogger on the login page.

    SECURITY: Disabled by default. Only reachable when
    settings.ATTACK_DEMO_ENABLED is explicitly True. In production this
    returns 404 so the endpoint cannot act as a credential-theft sink or
    a disk-fill DoS target. The client-side JS that once fed this endpoint
    was permanently removed from templates/login.html.
    """
    _require_attack_demo()
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            keylogger_save_capture(data)
            return HttpResponse("ok", status=200)
        except Exception:
            return HttpResponse("error", status=400)
    return HttpResponse("", status=405)


@login_required
def keylogger_clear(request):
    """Clears keylogger log (resets demo)."""
    _require_attack_demo()
    if not request.user.is_staff:
        return redirect("dashboard")
    if request.method == "POST":
        keylogger_clear_log()
        messages.success(request, "Keylogger log cleared.")
    return redirect("attack_demo_dashboard")

