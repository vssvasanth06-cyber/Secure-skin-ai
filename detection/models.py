from django.db import models
from django.contrib.auth.models import User

class MedicalImage(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_image = models.BinaryField()
    image_hash = models.CharField(max_length=64)
    encrypted_prediction = models.BinaryField(null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.username} - {self.role}"
    
    from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.username} - {self.role}"
