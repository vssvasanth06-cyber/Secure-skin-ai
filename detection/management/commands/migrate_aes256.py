"""
One-time migration: re-encrypt all existing data to AES-256-GCM.

Records created before the AES-256 upgrade were encrypted with Fernet
(AES-128-CBC + HMAC). They still decrypt via the transparent fallback, but this
command converts them in place so the ENTIRE database uses AES-256, matching the
framework's AES-256 claim end-to-end.

    python manage.py migrate_aes256 --dry-run     # report what would change
    python manage.py migrate_aes256               # perform the migration

Safe to re-run: records already in AES-256-GCM are skipped. Each record is
converted independently; a failure on one record is reported and skipped without
touching the rest. Plaintext (image_hash / report_hash) and RSA signatures are
unchanged, so integrity and signature checks keep passing.
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from detection.models import UserProfile, MedicalImage, Report
from detection.security import decrypt_private_key, encrypt_private_key
from detection.crypto_utils import (
    generate_aes_key, encrypt_data, decrypt_data,
    encrypt_key, decrypt_key,
)

GCM_MAGIC = b"GCM1"


def _b(x):
    if x is None:
        return None
    if isinstance(x, memoryview):
        return bytes(x)
    return bytes(x)


class Command(BaseCommand):
    help = "Re-encrypt all existing data (private keys, images, reports) to AES-256-GCM."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Report what would change without writing.")

    def handle(self, *args, **opts):
        dry = opts["dry_run"]
        self.stdout.write(self.style.MIGRATE_HEADING(
            "AES-256-GCM migration " + ("(DRY RUN)" if dry else "(LIVE)")))

        pk = self._migrate_private_keys(dry)
        im = self._migrate_images(dry)
        rp = self._migrate_reports(dry)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"Private keys: {pk['done']} converted, {pk['skip']} already AES-256, {pk['fail']} failed"))
        self.stdout.write(self.style.SUCCESS(
            f"Images      : {im['done']} converted, {im['skip']} already AES-256, {im['fail']} failed"))
        self.stdout.write(self.style.SUCCESS(
            f"Reports     : {rp['done']} converted, {rp['skip']} already AES-256, {rp['fail']} failed"))
        if dry:
            self.stdout.write(self.style.WARNING("Dry run — no changes written. Re-run without --dry-run to apply."))

    # ── Private keys at rest ────────────────────────────────────────────────
    def _migrate_private_keys(self, dry):
        done = skip = fail = 0
        for prof in UserProfile.objects.select_related("user").all():
            val = prof.private_key
            if not val:
                continue
            if isinstance(val, str) and val.startswith("GCM1."):
                skip += 1
                continue
            try:
                pem = decrypt_private_key(val)          # legacy Fernet / plaintext
                if not dry:
                    prof.private_key = encrypt_private_key(pem)   # → AES-256-GCM
                    prof.save(update_fields=["private_key"])
                done += 1
            except Exception as e:
                fail += 1
                self.stdout.write(self.style.ERROR(f"  privkey {prof.user.username}: {e}"))
        return {"done": done, "skip": skip, "fail": fail}

    # ── Medical images (bulk AES payload + both RSA-wrapped keys) ────────────
    def _migrate_images(self, dry):
        done = skip = fail = 0
        for img in MedicalImage.objects.select_related("assigned_doctor", "user").all():
            blob = _b(img.encrypted_image)
            if blob and blob[:4] == GCM_MAGIC:
                skip += 1
                continue
            try:
                doc = img.assigned_doctor
                pat = img.user
                # Unwrap the current (legacy) AES key with whichever key we can.
                priv = decrypt_private_key(doc.userprofile.private_key)
                aes_old = decrypt_key(_b(img.encrypted_aes_key), priv)
                raw = decrypt_data(blob, aes_old)

                # Re-encrypt with a fresh AES-256 key, re-wrap for both parties.
                aes_new = generate_aes_key()
                new_blob = encrypt_data(raw, aes_new)
                doc_pub = _b(doc.userprofile.public_key.encode()
                             if isinstance(doc.userprofile.public_key, str)
                             else doc.userprofile.public_key)
                new_doc_wrap = encrypt_key(aes_new, doc_pub)

                new_pat_wrap = None
                if pat.userprofile.public_key:
                    pat_pub = pat.userprofile.public_key
                    pat_pub = pat_pub.encode() if isinstance(pat_pub, str) else _b(pat_pub)
                    new_pat_wrap = encrypt_key(aes_new, pat_pub)

                if not dry:
                    img.encrypted_image = new_blob
                    img.encrypted_aes_key = new_doc_wrap
                    if new_pat_wrap is not None:
                        img.patient_encrypted_aes_key = new_pat_wrap
                    img.save(update_fields=[
                        "encrypted_image", "encrypted_aes_key", "patient_encrypted_aes_key"])
                done += 1
            except Exception as e:
                fail += 1
                self.stdout.write(self.style.ERROR(f"  image #{img.id}: {e}"))
        return {"done": done, "skip": skip, "fail": fail}

    # ── Reports (bulk AES payload + patient-wrapped key) ─────────────────────
    def _migrate_reports(self, dry):
        done = skip = fail = 0
        for rep in Report.objects.select_related("image__user").all():
            blob = _b(rep.encrypted_report)
            if blob and blob[:4] == GCM_MAGIC:
                skip += 1
                continue
            try:
                pat = rep.image.user
                priv = decrypt_private_key(pat.userprofile.private_key)
                aes_old = decrypt_key(_b(rep.encrypted_aes_key), priv)
                raw = decrypt_data(blob, aes_old)

                aes_new = generate_aes_key()
                new_blob = encrypt_data(raw, aes_new)
                pat_pub = pat.userprofile.public_key
                pat_pub = pat_pub.encode() if isinstance(pat_pub, str) else _b(pat_pub)
                new_wrap = encrypt_key(aes_new, pat_pub)

                if not dry:
                    rep.encrypted_report = new_blob
                    rep.encrypted_aes_key = new_wrap
                    rep.save(update_fields=["encrypted_report", "encrypted_aes_key"])
                done += 1
            except Exception as e:
                fail += 1
                self.stdout.write(self.style.ERROR(f"  report #{rep.id}: {e}"))
        return {"done": done, "skip": skip, "fail": fail}
