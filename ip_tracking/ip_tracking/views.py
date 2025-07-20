from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.views.decorators.http import require_POST
import json


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def login_view(request):
    """
    Login view with rate limiting:
    - 10 requests per minute for authenticated users
    - 5 requests per minute for anonymous users (handled by custom decorator)
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'ip_tracking/login.html')


@ratelimit(key='ip', rate='5/m', method=['GET', 'POST'], block=True)
def anonymous_sensitive_view(request):
    """
    Sensitive view for anonymous users with stricter rate limiting.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    return render(request, 'ip_tracking/anonymous_sensitive.html')


@csrf_exempt
@require_POST
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
def api_login(request):
    """
    API login endpoint with rate limiting.
    """
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({
                'success': True,
                'message': 'Login successful',
                'user_id': user.id
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Invalid credentials'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON data'
        }, status=400)


@ratelimit(key='ip', rate='20/m', method='GET', block=True)
def dashboard_view(request):
    """
    Dashboard view with moderate rate limiting for authenticated users.
    """
    if not request.user.is_authenticated:
        return redirect('login')
    
    return render(request, 'ip_tracking/dashboard.html', {
        'user': request.user
    })


def ratelimited_error(request, exception):
    """
    Custom view to handle rate limit exceeded errors.
    """
    return JsonResponse({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.'
    }, status=429)


# Additional utility views for IP tracking analytics

@ratelimit(key='ip', rate='30/m', method='GET', block=True)
def ip_analytics_view(request):
    """
    View to display IP analytics (admin only).
    """
    if not request.user.is_staff:
        return redirect('login')
    
    from .models import RequestLog, BlockedIP, SuspiciousIP
    from django.db.models import Count
    from datetime import timedelta
    from django.utils import timezone
    
    # Get recent request logs
    recent_logs = RequestLog.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).values('country').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Get top IPs
    top_ips = RequestLog.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).values('ip_address').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    context = {
        'recent_logs': recent_logs,
        'top_ips': top_ips,
        'blocked_count': BlockedIP.objects.count(),
        'suspicious_count': SuspiciousIP.objects.filter(resolved=False).count(),
    }
    
    return render(request, 'ip_tracking/analytics.html', context)