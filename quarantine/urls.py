from django.urls import path
from . import views

app_name = 'quarantine'

urlpatterns = [
    path('', views.quarantine_list, name='quarantine_list'),
    path('quarantine/', views.quarantine_file, name='quarantine_file'),
    path('restore/<int:file_id>/', views.restore_file, name='restore_file'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
] 