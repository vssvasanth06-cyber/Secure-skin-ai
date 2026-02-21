from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('patient/upload/', views.patient_upload, name='patient_upload'),
    path('verify/<int:image_id>/', views.verify_and_decrypt, name='verify'),
    path('logout/', views.logout_view, name='logout'),
]

