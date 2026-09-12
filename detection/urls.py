from django.urls import path
from . import views

urlpatterns = [

    # ── Authentication ───────────────────────────────────────────────
    path('',               views.login_view,                name='login'),
    path('login/',         views.login_view,                name='login_page'),
    path('register/',      views.register_view,             name='register'),

    path('verify-registration-otp/', views.verify_registration_otp, name='verify_registration_otp'),
    path('verify-login-otp/',         views.verify_login_otp,         name='verify_login_otp'),

    path('forgot-password/',  views.forgot_password,   name='forgot_password'),
    path('verify-reset-otp/', views.verify_reset_otp,  name='verify_reset_otp'),
    path('reset-password/',   views.reset_password,    name='reset_password'),
    path('resend-otp/',        views.resend_otp,         name='resend_otp'),

    path('logout/', views.logout_view, name='logout'),

    # ── Dashboard ────────────────────────────────────────────────────
    path('dashboard/',         views.dashboard,          name='dashboard'),
    path('patient/dashboard/', views.patient_dashboard,  name='patient_dashboard'),

    # ── Patient – Image Upload ────────────────────────────────────────
    path('patient/upload/', views.patient_upload, name='patient_upload'),

    # ── Doctor – Image Actions ────────────────────────────────────────
    path('view-decrypted/<int:image_id>/', views.view_decrypted_image, name='view_decrypted_image'),
    path('verify/<int:image_id>/',         views.verify_and_decrypt,   name='verify_image'),

    # ── Report System ────────────────────────────────────────────────
    path('upload-report/<int:image_id>/',  views.upload_report,  name='upload_report'),
    path('view-report/<int:report_id>/',   views.view_report,    name='view_report'),
    path('make-payment/<int:report_id>/',  views.make_payment,   name='make_payment'),
    path('download-report/<int:report_id>/', views.download_report, name='download_report'),
    path('verify-report/<str:token>/',     views.verify_report,  name='verify_report'),

    # ── Appointments – Doctor ─────────────────────────────────────────
    path('doctor/add-availability/',  views.add_availability,    name='add_availability'),
    path('doctor-appointments/',      views.doctor_appointments, name='doctor_appointments'),

    # ── Appointments – Patient ────────────────────────────────────────
    path('patient/slots/',              views.view_available_slots, name='view_slots'),
    path('patient/book/<int:slot_id>/', views.book_slot,            name='book_slot'),
    path('patient/cancel/<int:slot_id>/', views.cancel_booking,     name='cancel_booking'),
    path('book-appointment/',           views.book_appointment,     name='book_appointment'),

    # ── Appointments – Shared ─────────────────────────────────────────
    path('my-appointments/',   views.my_appointments,   name='my_appointments'),
    path('view-appointments/', views.view_appointments, name='view_appointments'),
    path('update-appointment/<int:appointment_id>/<str:status>/',
         views.update_appointment_status, name='update_appointment_status'),
    path('emergency-appointment/', views.emergency_appointment, name='emergency_appointment'),

    # ── Doctor Stats ──────────────────────────────────────────────────
    path('doctor-cases/', views.doctor_cases, name='doctor_cases'),

    # ── Admin ─────────────────────────────────────────────────────────
    path('admin-dashboard/users/',    views.admin_users,    name='admin_users'),
    path('admin-dashboard/doctors/',  views.admin_doctors,  name='admin_doctors'),
    path('admin-dashboard/patients/', views.admin_patients, name='admin_patients'),
    path('admin-dashboard/reports/',  views.admin_reports,  name='admin_reports'),
    path('delete-user/<int:user_id>/', views.delete_user,   name='delete_user'),
    path('portal/approve-upi/<int:report_id>/', views.approve_upi_payment, name='approve_upi_payment'),
    path('portal/reject-upi/<int:report_id>/',  views.reject_upi_payment,  name='reject_upi_payment'),

    # ── Analytics ─────────────────────────────────────────────────────
    path('weekly-uploads/', views.weekly_uploads, name='weekly_uploads'),
    path('weekly-reports/', views.weekly_reports, name='weekly_reports'),

    # ── Security / Crypto Demo ────────────────────────────────────────
    path('crypto-proof/',                views.crypto_proof_view,   name='crypto_proof'),
    path('portal/patient-crypto-proof/', views.admin_patient_crypto, name='admin_patient_crypto'),
    path('portal/doctor-crypto-proof/',  views.admin_doctor_crypto,  name='admin_doctor_crypto'),
    path('security-demo/',               views.security_demo,        name='security_demo'),

    # ── Live Security Monitor (Admin Only) ───────────────────────────
    path('security-monitor/',      views.security_monitor,      name='security_monitor'),
    path('security-monitor/feed/', views.security_monitor_feed, name='security_monitor_feed'),

    # ── Attack Simulations (Admin Only) ──────────────────────────────
    path('attack-demo/',               views.attack_demo_dashboard, name='attack_demo_dashboard'),
    path('attack/ransomware/trigger/', views.ransomware_trigger,    name='ransomware_trigger'),
    path('attack/ransomware/restore/', views.ransomware_restore,    name='ransomware_restore'),
    path('attack/trojan/upload/',      views.trojan_upload_test,    name='trojan_upload_test'),
    path('attack/spyware/trigger/',    views.spyware_trigger,       name='spyware_trigger'),
    path('attack/spyware/clear/',      views.spyware_clear,         name='spyware_clear'),
    path('attack/keylogger/capture/',  views.keylogger_capture,     name='keylogger_capture'),
    path('attack/keylogger/clear/',    views.keylogger_clear,       name='keylogger_clear'),
]
