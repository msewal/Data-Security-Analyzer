"""
URL configuration for wfe project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import views
# from main import views # Assuming main app is not used for index anymore based on summary

urlpatterns = [
    path('admin/', admin.site.urls),
    path('host-test/', views.test_host),
    path('', include('list.urls')), # Assuming list app handles the index view now
    path('bash/', include('bash.urls')),
    path('malware/', include('malware.urls')),
    path('regex/', include('regex.urls')),
    path('quarantine/', include('quarantine.urls')),  # quarantine uygulamasının URL'lerini dahil et
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
