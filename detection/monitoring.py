"""
Real-time security monitoring engine.

Every security-relevant action in this project already writes a structured
event into ``LoginLog`` (the ``role`` field holds a tag such as
``DECRYPT_FAIL_img7:REPLAY`` or ``UPI_REJECTED``). This module turns that raw
stream into:

  * a live threat snapshot for the SOC dashboard (``build_snapshot``)
  * throttled, threaded email alerts on critical events (``alert_if_critical``)
  * a scheduled anomaly sweep for the cron command (``scan_anomalies``)

Nothing here changes how events are produced — it only classifies and reacts,
so historical events light up the dashboard immediately.
"""

import threading
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta


# ── Severity ordering (higher = worse) ───────────────────────────────────────
SEV_OK, SEV_INFO, SEV_WARNING, SEV_CRITICAL = "ok", "info", "warning", "critical"
_SEV_RANK = {SEV_OK: 0, SEV_INFO: 1, SEV_WARNING: 2, SEV_CRITICAL: 3}


# ── Classification rules ─────────────────────────────────────────────────────
# Each rule: (substring to match in the tag, category, severity, icon, label)
# First match wins; order matters (most specific first).
_RULES = [
    ("REPLAY",             "Replay attack",        SEV_CRITICAL, "bi-arrow-repeat",          "Replay attack blocked"),
    ("IDOR_VERIFY",        "IDOR",                 SEV_CRITICAL, "bi-shield-lock",           "IDOR verify attempt blocked"),
    ("IDOR",               "IDOR",                 SEV_CRITICAL, "bi-shield-lock",           "IDOR access blocked"),
    ("INTEGRITY_FAIL",     "Integrity",            SEV_CRITICAL, "bi-file-earmark-break",    "Integrity check FAILED (tamper)"),
    ("UPI_REJECTED",       "Payment fraud",        SEV_CRITICAL, "bi-cash-coin",             "Fake / unsettled UPI rejected"),
    ("APT_",               "Anomaly",              SEV_WARNING,  "bi-activity",              "APT anomaly flagged"),
    ("LOGIN_LOCK",         "Brute force",          SEV_WARNING,  "bi-lock",                  "Login locked (too many attempts)"),
    ("LOGIN_FAIL",         "Auth",                 SEV_WARNING,  "bi-x-circle",              "Failed login"),
    ("RATE",               "Rate limit",           SEV_WARNING,  "bi-speedometer",           "Rate limit triggered"),
    ("DECRYPT_FAIL",       "Decrypt",              SEV_WARNING,  "bi-unlock",                "Decryption attempt failed"),
    ("UPI_VERIFIED",       "Payment",              SEV_INFO,     "bi-cash",                  "UPI payment verified"),
    ("DECRYPT_OK",         "Decrypt",              SEV_INFO,     "bi-unlock",                "Image decrypted"),
    ("LOGIN_OK",           "Auth",                 SEV_OK,       "bi-box-arrow-in-right",    "Successful login"),
]

# Categories that trigger an email alert.
_CRITICAL_CATEGORIES = {"Replay attack", "IDOR", "Integrity", "Payment fraud"}


def classify(tag: str) -> dict:
    """Map a raw LoginLog role-tag to a category / severity / icon / label."""
    tag = tag or ""
    for needle, category, severity, icon, label in _RULES:
        if needle in tag:
            return {"category": category, "severity": severity, "icon": icon, "label": label}
    # Unrecognised login-page role names ("patient"/"doctor"/"admin") = ok auth.
    return {"category": "Auth", "severity": SEV_OK, "icon": "bi-person", "label": "Session"}


def _detail_from_tag(tag: str) -> str:
    """Return the ':reason' suffix of a tag, if present."""
    return tag.split(":", 1)[1] if ":" in (tag or "") else ""


# ── Live snapshot for the dashboard ──────────────────────────────────────────
def build_snapshot(minutes: int = 60, feed_limit: int = 40) -> dict:
    """
    Aggregate recent LoginLog rows into a threat snapshot the dashboard renders.
    """
    from .models import LoginLog

    now = timezone.now()
    window_start = now - timedelta(minutes=minutes)

    recent = list(
        LoginLog.objects.select_related("user")
        .filter(login_time__gte=window_start)
        .order_by("-login_time")[:400]
    )

    counters = {
        "critical": 0, "warning": 0, "info": 0, "ok": 0,
        "replay": 0, "idor": 0, "integrity": 0, "payment_fraud": 0,
        "failed_login": 0, "anomaly": 0, "decrypt_fail": 0,
    }
    ip_hits = {}
    feed = []
    worst = SEV_OK

    for row in recent:
        info = classify(row.role)
        sev, cat = info["severity"], info["category"]
        counters[sev] = counters.get(sev, 0) + 1
        if _SEV_RANK[sev] > _SEV_RANK[worst]:
            worst = sev

        if cat == "Replay attack":  counters["replay"] += 1
        elif cat == "IDOR":         counters["idor"] += 1
        elif cat == "Integrity":    counters["integrity"] += 1
        elif cat == "Payment fraud":counters["payment_fraud"] += 1
        elif cat == "Anomaly":      counters["anomaly"] += 1
        if "LOGIN_FAIL" in (row.role or "") or "LOGIN_LOCK" in (row.role or ""):
            counters["failed_login"] += 1
        if cat == "Decrypt" and sev == SEV_WARNING:
            counters["decrypt_fail"] += 1

        ip = row.ip_address or "unknown"
        ip_hits[ip] = ip_hits.get(ip, 0) + 1

        if len(feed) < feed_limit:
            feed.append({
                "time":     timezone.localtime(row.login_time).strftime("%H:%M:%S"),
                "date":     timezone.localtime(row.login_time).strftime("%d %b"),
                "user":     (row.user.username if row.user else "—"),
                "ip":       ip,
                "severity": sev,
                "category": cat,
                "icon":     info["icon"],
                "label":    info["label"],
                "detail":   _detail_from_tag(row.role),
            })

    # Threat level derived from what was seen in the window.
    if counters["critical"] > 0:
        threat = "CRITICAL"
    elif counters["warning"] >= 5:
        threat = "HIGH"
    elif counters["warning"] > 0:
        threat = "ELEVATED"
    else:
        threat = "NORMAL"

    top_ips = sorted(ip_hits.items(), key=lambda kv: kv[1], reverse=True)[:6]

    return {
        "generated_at": timezone.localtime(now).strftime("%d %b %Y, %H:%M:%S"),
        "window_min":   minutes,
        "threat_level": threat,
        "worst_severity": worst,
        "counters":     counters,
        "events_total": len(recent),
        "top_ips":      [{"ip": ip, "hits": n} for ip, n in top_ips],
        "feed":         feed,
    }


# ── Email alerting (throttled + threaded so it never blocks a request) ────────
def _send_email_async(subject: str, body: str, recipient: str):
    def _worker():
        try:
            send_mail(subject, body, settings.EMAIL_HOST_USER or None,
                      [recipient], fail_silently=True)
        except Exception:
            pass
    threading.Thread(target=_worker, daemon=True).start()


def alert_if_critical(tag: str, ip: str = "", username: str = ""):
    """
    Fire an email alert for a critical security event, throttled per
    (category, IP) so a burst of attacks does not flood the inbox.

    Safe to call from any request path — all failures are swallowed.
    """
    try:
        if not getattr(settings, "SECURITY_ALERTS_ENABLED", False):
            return
        recipient = getattr(settings, "SECURITY_ALERT_EMAIL", "")
        if not recipient:
            return

        info = classify(tag)
        if info["category"] not in _CRITICAL_CATEGORIES:
            return

        throttle_min = getattr(settings, "SECURITY_ALERT_THROTTLE_MIN", 10)
        cache_key = f"secalert:{info['category']}:{ip or 'noip'}"
        if cache.get(cache_key):
            return
        cache.set(cache_key, 1, throttle_min * 60)

        when = timezone.localtime(timezone.now()).strftime("%d %b %Y, %H:%M:%S")
        subject = f"[Secure Skin AI] SECURITY ALERT — {info['label']}"
        body = (
            "A critical security event was detected and blocked.\n\n"
            f"  Event    : {info['label']}\n"
            f"  Category : {info['category']}\n"
            f"  User     : {username or '—'}\n"
            f"  Source IP: {ip or 'unknown'}\n"
            f"  Raw tag  : {tag}\n"
            f"  Time     : {when}\n\n"
            "Open the Live Security Monitor for full context.\n"
            "This is an automated message from your Secure Skin AI monitoring engine."
        )
        _send_email_async(subject, body, recipient)
    except Exception:
        # Monitoring must never break the protected request.
        pass


# ── Scheduled anomaly sweep (called by the cron management command) ───────────
def scan_anomalies(minutes: int = 15) -> dict:
    """
    Sweep the last ``minutes`` of events for anomalies even when no admin is
    watching the dashboard. Returns a summary; emails a digest if threats found.
    Also checks the media folder for ransomware-style ``.locked`` files.
    """
    from pathlib import Path
    from .models import LoginLog

    now = timezone.now()
    window_start = now - timedelta(minutes=minutes)
    rows = LoginLog.objects.filter(login_time__gte=window_start)

    critical, warning = [], []
    fail_by_ip = {}
    for row in rows:
        info = classify(row.role)
        line = f"{row.role} · {row.ip_address or 'unknown'} · {row.user.username if row.user else '—'}"
        if info["severity"] == SEV_CRITICAL:
            critical.append(line)
        elif info["severity"] == SEV_WARNING:
            warning.append(line)
        if "LOGIN_FAIL" in (row.role or "") or "LOGIN_LOCK" in (row.role or ""):
            ip = row.ip_address or "unknown"
            fail_by_ip[ip] = fail_by_ip.get(ip, 0) + 1

    # Brute-force heuristic: 5+ failed logins from one IP in the window.
    brute = [f"{ip} ({n} failed logins)" for ip, n in fail_by_ip.items() if n >= 5]

    # Ransomware heuristic: encrypted (.locked) files in media.
    locked = []
    try:
        media = Path(settings.BASE_DIR) / "media"
        locked = [str(p) for p in media.rglob("*.locked")]
    except Exception:
        pass

    threats = bool(critical or brute or locked)
    summary = {
        "checked_at": timezone.localtime(now).strftime("%d %b %Y, %H:%M:%S"),
        "window_min": minutes,
        "critical_count": len(critical),
        "warning_count": len(warning),
        "brute_force_ips": brute,
        "ransomware_locked": len(locked),
        "threats": threats,
    }

    if threats and getattr(settings, "SECURITY_ALERTS_ENABLED", False):
        recipient = getattr(settings, "SECURITY_ALERT_EMAIL", "")
        if recipient:
            body = [
                f"Scheduled security sweep — {summary['checked_at']}",
                f"Window: last {minutes} minutes\n",
                f"Critical events : {len(critical)}",
                f"Warnings        : {len(warning)}",
                f"Ransomware files: {len(locked)}",
            ]
            if critical:
                body.append("\nCritical:\n  " + "\n  ".join(critical[:20]))
            if brute:
                body.append("\nPossible brute force:\n  " + "\n  ".join(brute))
            if locked:
                body.append("\nEncrypted (.locked) files:\n  " + "\n  ".join(locked[:20]))
            _send_email_async(
                "[Secure Skin AI] Scheduled sweep — threats detected",
                "\n".join(body), recipient)

    return summary
