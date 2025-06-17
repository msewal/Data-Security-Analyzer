from django.urls import path
from . import views

app_name = 'regex'

urlpatterns = [
    path('', views.regex_search, name='regex_search'),
    path('results/', views.regex_search_results, name='regex_search_results'),
    path('regex-search/<path:file_path>/', views.regex_search_detail, name='regex_search_detail'),
    path('quarantine/', views.quarantine_list, name='quarantine_list'),
    path('quarantine/<path:file_path>/', views.quarantine_file, name='quarantine_file'),
    path('edit/<path:file_path>/', views.edit_file, name='edit_file'),
    path('api/patterns/', views.api_get_regex_patterns, name='api_get_regex_patterns'),
    path('sensitive-scan/', views.sensitive_scan, name='sensitive_scan'),
    path('sensitive-scan/results/', views.sensitive_scan_results, name='sensitive_scan_results'),
    path('sensitive-scan/<path:file_path>/', views.sensitive_scan_detail, name='sensitive_scan_detail'),
    path('view/<path:file_path>/', views.view_file, name='view_file'),
]
