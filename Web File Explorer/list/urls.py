from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
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
    path("dashboard/", views.dashboard),
]