from django.urls import path

from . import views

app_name = 'list'

urlpatterns = [
    # Ana sayfa ve temel görünümler
    path("dashboard/", views.dashboard, name="dashboard"),
    path("procedure/", views.procedure, name="procedure"),
    
    # Dosya işlemleri
    path("edit/", views.edit_file, name="edit_file"),
    path("preview/", views.file_preview, name="file_preview"),
    path("download/", views.download_file, name="download_file"),
    
    # API endpoints
    path("api/savefile/", views.save_file, name="api_savefile"),
    path("api/delete/", views.delete_item, name="delete_item"),
    path("api/upload/", views.upload_file, name="upload_file"),
    path("api/create_folder/", views.create_folder, name="create_folder"),

    # Catch-all URL pattern for the root directory
    path('', views.index, name='index'),
]