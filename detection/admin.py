from django.contrib import admin
from .models import UserProfile, MedicalImage

admin.site.register(UserProfile)
admin.site.register(MedicalImage)