from django.contrib import admin
from .models import UserProfile, MedicalImage, Report, LoginLog, DoctorAvailability


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "specialization", "is_available", "current_cases")
    list_filter = ("role", "is_available")
    search_fields = ("user__username", "user__email", "specialization")


@admin.register(MedicalImage)
class MedicalImageAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "assigned_doctor", "image_type", "severity", "is_verified", "uploaded_at")
    list_filter = ("severity", "is_verified")
    search_fields = ("user__username", "assigned_doctor__username")
    readonly_fields = ("image_hash", "uploaded_at")


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "get_patient", "severity", "is_paid", "transaction_id", "created_at")
    list_filter = ("severity", "is_paid")
    search_fields = ("image__user__username",)
    readonly_fields = ("report_hash", "access_token", "created_at")

    def get_patient(self, obj):
        return obj.image.user.username
    get_patient.short_description = "Patient"


@admin.register(LoginLog)
class LoginLogAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "ip_address", "login_time")
    list_filter = ("role",)
    search_fields = ("user__username", "ip_address")
    readonly_fields = ("login_time",)


@admin.register(DoctorAvailability)
class DoctorAvailabilityAdmin(admin.ModelAdmin):
    list_display = ("doctor", "date", "slot", "is_booked", "patient")
    list_filter = ("is_booked", "slot")
    search_fields = ("doctor__username", "patient__username")
