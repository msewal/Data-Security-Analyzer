from django.urls import path
from . import views

app_name = 'regex'

urlpatterns = [
    path('', views.regex_search, name='regex_search'),
    path('sensitive-scan/', views.sensitive_scan, name='sensitive_scan'),
    path('sensitive-scan/<path:file_path>/', views.sensitive_scan_detail, name='sensitive_scan_detail'),
    path('regex-search/<path:file_path>/', views.regex_search_detail_view, name='regex_search_detail'),
    path('api/regex-patterns/', views.api_get_regex_patterns, name='api_get_regex_patterns'),
    path('regex-search-results/', views.regex_search_results, name='regex_search_results'),
    path('edit-file/<path:file_path>/', views.edit_file, name='edit_file'),
    path('quarantine-file/<path:file_path>/', views.quarantine_file, name='quarantine_file'),
    path('quarantine/', views.quarantine_list, name='quarantine_list'),
    path('quarantine_file/', views.quarantine_file, name='quarantine_file'),
]
