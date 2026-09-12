from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import UserProfile


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    role = forms.ChoiceField(
        choices=UserProfile.ROLE_CHOICES,
        required=True
    )

    doctor_code = forms.CharField(
        required=False,
        widget=forms.PasswordInput,
        help_text="Required only for doctor registration"
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'role', 'doctor_code']

    def clean(self):
        cleaned_data = super().clean()
        role = cleaned_data.get("role")
        doctor_code = cleaned_data.get("doctor_code")

        # Secure Doctor Registration Code
        if role == "doctor":
            if doctor_code != "HOSPITAL2026":
                raise forms.ValidationError("Invalid Doctor Authorization Code")

        return cleaned_data