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
    path("api/savefile/", views.api_savefile, name="api_savefile"),
    path("api/regex/", views.api_regex, name="api_regex"),
    path("api/malware-scan/", views.api_malware_scan, name="api_malware_scan"),
    path("api/quarantine/", views.api_quarantine, name="api_quarantine"),
    path("api/classify/", views.api_classify, name="api_classify"),
    path('api/regex-search/', views.regex_search, name='regex_search'),
    path('api/classify/', views.classify_data, name='classify_data'),
    path('api/regex-search/', views.regex_search_view, name='regex_search_view'),
]