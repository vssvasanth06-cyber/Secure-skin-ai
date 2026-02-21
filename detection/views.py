import torch
import torchvision.transforms as transforms
import torchvision.models as models
from PIL import Image
import io
import hashlib

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.conf import settings

from cryptography.fernet import Fernet
from .models import MedicalImage


# 🔐 Encryption
fernet = Fernet(settings.ENCRYPTION_KEY)


# ==============================
# 🔬 LAZY LOAD MODEL (IMPORTANT)
# ==============================

model = None

def get_model():
    global model
    if model is None:
       model = models.resnet18(weights=None)
        model.eval()
    return model


# ==============================
# 🔑 LOGIN WITH ROLE
# ==============================

def login_view(request):
    if request.method == "POST":
        selected_role = request.POST.get('role')
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user:
            actual_role = user.userprofile.role

            if actual_role == selected_role:
                login(request, user)
                return redirect('dashboard')
            else:
                return render(request, 'login.html', {
                    'error': 'Role does not match ❌'
                })

        return render(request, 'login.html', {
            'error': 'Invalid credentials ❌'
        })

    return render(request, 'login.html')


# ==============================
# 🏠 ROLE DASHBOARD
# ==============================

@login_required
def dashboard(request):
    role = request.user.userprofile.role

    if role == 'patient':
        return render(request, 'patient_dashboard.html')

    elif role == 'doctor':
        return render(request, 'doctor_dashboard.html')

    elif role == 'admin':
        return render(request, 'admin_dashboard.html')

    return redirect('login')


# ==============================
# 🧑‍⚕️ PATIENT UPLOAD
# ==============================

@login_required
def patient_upload(request):
    if request.user.userprofile.role != 'patient':
        return HttpResponse("Unauthorized ❌")

    if request.method == "POST":
        image_file = request.FILES.get('image')

        if image_file:
            image_bytes = image_file.read()

            image_hash = hashlib.sha256(image_bytes).hexdigest()
            encrypted_data = fernet.encrypt(image_bytes)

            image_record = MedicalImage.objects.create(
                user=request.user,
                encrypted_image=encrypted_data,
                image_hash=image_hash
            )

            return redirect('verify', image_id=image_record.id)

        return HttpResponse("No Image Selected")

    return redirect('dashboard')


# ==============================
# 🔍 VERIFY + AI
# ==============================

@login_required
def verify_and_decrypt(request, image_id):
    try:
        image_record = MedicalImage.objects.get(id=image_id)

        decrypted_data = fernet.decrypt(image_record.encrypted_image)

        new_hash = hashlib.sha256(decrypted_data).hexdigest()

        if new_hash != image_record.image_hash:
            return render(request, 'result.html', {
                'error': "Integrity Failed ❌ Image Tampered"
            })

        prediction = run_prediction(decrypted_data)

        encrypted_result = fernet.encrypt(prediction.encode())
        image_record.encrypted_prediction = encrypted_result
        image_record.save()

        return render(request, 'result.html', {
            'prediction': prediction
        })

    except MedicalImage.DoesNotExist:
        return HttpResponse("Image Not Found")

    except Exception as e:
        return HttpResponse("Error: " + str(e))


# ==============================
# 🤖 AI PREDICTION
# ==============================

def run_prediction(image_bytes):
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
    ])

    image_tensor = transform(image).unsqueeze(0)

    model = get_model()

    with torch.no_grad():
        outputs = model(image_tensor)

    predicted_index = torch.argmax(outputs).item()

    return f"Class Index: {predicted_index}"


# ==============================
# 🚪 LOGOUT
# ==============================

def logout_view(request):
    logout(request)
    return redirect('login')