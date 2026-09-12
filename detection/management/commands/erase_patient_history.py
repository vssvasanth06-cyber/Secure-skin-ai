"""
Erase ALL images and reports for a specific patient (or all patients).

Usage:
  python manage.py erase_patient_history --username alice
  python manage.py erase_patient_history --all
  python manage.py erase_patient_history --username alice --dry-run
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from detection.models import MedicalImage, Report


class Command(BaseCommand):
    help = "Erase images and reports for a patient. Does NOT delete the user account."

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--username", type=str, help="Username of the patient")
        group.add_argument("--all", action="store_true", help="Erase history for ALL patients")
        parser.add_argument("--dry-run", action="store_true",
                            help="Preview what would be deleted without actually deleting")

    def handle(self, *args, **options):
        dry = options["dry_run"]
        mode = "[DRY RUN] " if dry else ""

        if options["all"]:
            patients = User.objects.filter(userprofile__role="patient")
        else:
            try:
                user = User.objects.get(username=options["username"])
                if user.userprofile.role != "patient":
                    raise CommandError(f"'{user.username}' is not a patient (role={user.userprofile.role})")
                patients = [user]
            except User.DoesNotExist:
                raise CommandError(f"User '{options['username']}' not found.")

        total_img = total_rpt = 0

        for patient in patients:
            images  = MedicalImage.objects.filter(user=patient)
            reports = Report.objects.filter(image__user=patient)

            img_count = images.count()
            rpt_count = reports.count()
            total_img += img_count
            total_rpt += rpt_count

            self.stdout.write(
                f"  {mode}Patient: {patient.username}  "
                f"→  {img_count} image(s),  {rpt_count} report(s)"
            )

            if not dry:
                reports.delete()
                images.delete()

        self.stdout.write("")
        if dry:
            self.stdout.write(
                self.style.WARNING(
                    f"[DRY RUN] Would delete {total_img} image(s) and {total_rpt} report(s). "
                    "Remove --dry-run to apply."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Deleted {total_img} image(s) and {total_rpt} report(s) successfully."
                )
            )
