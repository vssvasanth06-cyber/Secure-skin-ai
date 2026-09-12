from django.conf import settings


def feature_flags(request):
    """Expose selected feature flags to every template."""
    return {
        "attack_demo_enabled": getattr(settings, "ATTACK_DEMO_ENABLED", False),
    }
