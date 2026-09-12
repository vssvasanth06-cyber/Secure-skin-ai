"""
Scheduled security sweep — run by the host's cron/scheduler for 24/7 coverage.

    python manage.py scan_security --minutes 15

Sweeps recent security events for critical attacks, brute-force patterns and
ransomware-style .locked files even when no admin is watching the dashboard,
and emails an alert digest if anything is found (throttling handled in
monitoring.scan_anomalies / alert_if_critical).

Wire it to your host's scheduler, e.g.:
  * Render   → a Cron Job service running this command every 5-15 min
  * Railway  → a cron trigger
  * Cron/Task Scheduler on a VPS → */10 * * * *
"""

from django.core.management.base import BaseCommand
from detection.monitoring import scan_anomalies


class Command(BaseCommand):
    help = "Sweep recent security events for anomalies and alert on threats."

    def add_arguments(self, parser):
        parser.add_argument(
            "--minutes", type=int, default=15,
            help="Look-back window in minutes (default: 15).",
        )

    def handle(self, *args, **opts):
        minutes = max(1, opts["minutes"])
        summary = scan_anomalies(minutes=minutes)

        line = (
            f"[scan_security] {summary['checked_at']} | window={minutes}m | "
            f"critical={summary['critical_count']} warning={summary['warning_count']} "
            f"brute_ips={len(summary['brute_force_ips'])} locked_files={summary['ransomware_locked']}"
        )
        if summary["threats"]:
            self.stdout.write(self.style.ERROR(line + "  >> THREATS DETECTED — alert email sent"))
        else:
            self.stdout.write(self.style.SUCCESS(line + "  >> all clear"))
