from django.shortcuts import render
from django.http import HttpResponse

def test_host(request):
    return HttpResponse(f"Host: {request.get_host()}")

# ... existing code ... 