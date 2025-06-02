from django.urls import path
from . import views

app_name = 'bash'

urlpatterns = [
    path('', views.index, name='index'),
    path('edit/', views.edit, name='edit'),
    path('api/mkdir/', views.api_mkdir, name='api_mkdir'),
    path('api/touch/', views.api_touch, name='api_touch'),
    path('api/mv/', views.api_mv, name='api_mv'),
    path('api/cp/', views.api_cp, name='api_cp'),
    path('api/chmod/', views.api_chmod, name='api_chmod'),
    path('api/savefile/', views.api_savefile, name='api_savefile'),
] 