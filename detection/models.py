from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
import uuid


# ============================================
# 👤 User Profile Model
# ============================================

class UserProfile(models.Model):

    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='patient')

    assigned_doctor = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_patients"
    )

    is_available = models.BooleanField(default=True)
    current_cases = models.IntegerField(default=0)

    specialization = models.CharField(max_length=100, blank=True)

    public_key = models.TextField(null=True, blank=True)
    private_key = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} ({self.role})"


# ============================================
# 🩺 Doctor Availability
# ============================================

class DoctorAvailability(models.Model):

    doctor = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField()

    SLOT_CHOICES = [
        ('9AM-10AM', '9AM-10AM'),
        ('10AM-11AM', '10AM-11AM'),
        ('11AM-12PM', '11AM-12PM'),
        ('2PM-3PM', '2PM-3PM'),
        ('3PM-4PM', '3PM-4PM'),
    ]

    slot = models.CharField(max_length=20, choices=SLOT_CHOICES)
    is_booked = models.BooleanField(default=False)

    patient = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="booked_slots"
    )

    class Meta:
        unique_together = ['doctor', 'date', 'slot']

    def __str__(self):
        return f"{self.doctor.username} - {self.date} - {self.slot}"


# ============================================
# 🖼️ Medical Image Model
# ============================================

class MedicalImage(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)

    assigned_doctor = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_cases"
    )

    encrypted_image = models.BinaryField()
    encrypted_aes_key = models.BinaryField()           # encrypted with doctor's public key
    patient_encrypted_aes_key = models.BinaryField(null=True, blank=True)  # encrypted with patient's own public key
    image_hash = models.CharField(max_length=64)
    image_type = models.CharField(max_length=50, default="image/jpeg")

    severity = models.CharField(max_length=20, null=True, blank=True)

    prescription = models.TextField(blank=True, null=True)

    encrypted_prediction = models.BinaryField(null=True, blank=True)
    signature = models.BinaryField(null=True, blank=True)
    final_hash = models.CharField(max_length=64, null=True, blank=True)

    is_verified = models.BooleanField(default=False)
    verification_status = models.CharField(max_length=20, default="pending")
    remarks = models.TextField(blank=True)

    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image {self.id} - {self.user.username}"


# ============================================
# 📄 Report Model (UPDATED WITH SECURITY)
# ============================================

class Report(models.Model):

    image = models.ForeignKey(MedicalImage, on_delete=models.CASCADE)

    encrypted_report = models.BinaryField()
    encrypted_aes_key = models.BinaryField()

    # 🔐 SECURITY
    signature = models.BinaryField(null=True, blank=True)
    report_hash = models.CharField(max_length=64, null=True, blank=True)

    severity = models.CharField(max_length=10, default='mild')

    is_paid = models.BooleanField(default=False)
    transaction_id = models.CharField(max_length=100, blank=True, null=True)
    payment_time = models.DateTimeField(blank=True, null=True)

    qr_code = models.ImageField(upload_to='qr_codes/', null=True, blank=True)
    access_token = models.CharField(max_length=200, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def mark_as_paid(self):
        self.is_paid = True
        self.transaction_id = str(uuid.uuid4())
        self.payment_time = timezone.now()
        self.save()

    def __str__(self):
        return f"Report {self.id}"


# ============================================
# 🔐 Decryption Token
# ============================================

class DecryptionToken(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    image = models.ForeignKey(MedicalImage, on_delete=models.CASCADE)

    token_hash = models.CharField(max_length=64)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    is_used = models.BooleanField(default=False)
    attempt_count = models.IntegerField(default=0)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_valid(self):
        return (not self.is_used) and (timezone.now() < self.expires_at)


# ============================================
# 📊 Login Logs
# ============================================

class LoginLog(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20)

    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)


# ============================================
# 🔄 SIGNALS
# ============================================

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'userprofile'):
        instance.userprofile.save()