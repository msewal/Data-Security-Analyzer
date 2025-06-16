from django.contrib import admin
from django.urls import path, include
 
urlpatterns = [
    path('admin/', admin.site.urls),
    path('regex/', include('regex.urls')),
    path('quarantine/', include('quarantine.urls')),
] 