from django.contrib import admin
from django.urls import path, include

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # ============================================
    # 🔐 ADMIN PANEL
    # ============================================
    path('admin/', admin.site.urls),

    # ============================================
    # 📦 APP ROUTES (DETECTION APP)
    # ============================================
    path('', include('detection.urls')),   # ✅ connects all your app URLs
]

# ============================================
# 🖼️ MEDIA FILES (ONLY FOR DEVELOPMENT)
# ============================================
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)