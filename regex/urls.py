from django.urls import path
from . import views

app_name = 'regex'

urlpatterns = [
    path('search/', views.regex_search_results_view, name='regex_search_results_view'),
    path('detail/<path:file_path>/', views.regex_search_detail_view, name='regex_search_detail_view'),
    path('api/patterns/', views.api_get_regex_patterns, name='api_get_regex_patterns'),
]
