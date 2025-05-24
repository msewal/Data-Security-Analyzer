from django.urls import path

from . import views

app_name = 'list'

urlpatterns = [
    path("", views.index, name="index"),
    path("procedure/", views.procedure, name="procedure"),
    path("api/mkdir/", views.api_mkdir, name="api_mkdir"),
    path("api/touch/", views.api_touch, name="api_touch"),
    path("api/mv/", views.api_mv, name="api_mv"),
    path("api/cp/", views.api_cp, name="api_cp"),
    path("api/chmod/", views.api_chmod, name="api_chmod"),
    path("edit/", views.edit, name="edit"),
    path("api/savefile/", views.api_savefile, name="api_saveile"),
    path("api/regex_search/", views.api_regex_search),
    path("api/malware_scan/", views.api_malware_scan),
    path("api/quarantine/", views.api_quarantine),
    path("api/classify_file/", views.api_classify_file),
    path("regex_search/", views.regex_search_page, name="regex_search"),
    path("quarantine/", views.quarantine_list, name="quarantine_list"),
    path("quarantine/restore/<str:filename>", views.quarantine_restore, name="quarantine_restore"),
    path("quarantine/delete/<str:filename>", views.quarantine_delete, name="quarantine_delete"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("edit/", views.edit_file, name="edit_file"),
    path("api/savefile/", views.save_file, name="api_savefile"),
    path("api/delete/", views.delete_item, name="delete_item"),
    path("api/quarantine/", views.quarantine_file, name="quarantine_file"),
    path("api/run_procedure/", views.run_procedure, name="run_procedure"),
    path("api/upload/", views.upload_file, name="upload_file"),
    path("api/create_folder/", views.create_folder, name="create_folder"),
    path("download/", views.download_file, name="download_file"),
    path("preview/", views.file_preview, name="file_preview"),
]