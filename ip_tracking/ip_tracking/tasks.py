from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP, BlockedIP
import logging

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalous_ips():
    """
    Celery task to detect anomalous IP behavior.
    Runs hourly to check for:
    1. IPs exceeding 100 requests/hour
    2. IPs accessing sensitive paths frequently
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    
    logger.info("Starting anomaly detection task")
    
    # Check for high request volume (>100 requests/hour)
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=100)
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if already flagged recently
        if not SuspiciousIP.objects.filter(
            ip_address=ip_address,
            flagged_at__gte=one_hour_ago,
            reason__contains='High volume'
        ).exists():
            
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'High volume: {request_count} requests in 1 hour'
            )
            logger.warning(f"Flagged IP {ip_address} for high volume: {request_count} requests")
    
    # Check for suspicious path access
    sensitive_paths = ['/admin', '/login', '/api/login', '/django-admin']
    
    for path in sensitive_paths:
        suspicious_path_ips = RequestLog.objects.filter(
            timestamp__gte=one_hour_ago,
            path__startswith=path
        ).values('ip_address').annotate(
            access_count=Count('id')
        ).filter(access_count__gt=10)  # More than 10 attempts to sensitive paths
        
        for ip_data in suspicious_path_ips:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            # Skip if already flagged recently for this path
            if not SuspiciousIP.objects.filter(
                ip_address=ip_address,
                flagged_at__gte=one_hour_ago,
                reason__contains=f'Sensitive path access: {path}'
            ).exists():
                
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f'Sensitive path access: {path} ({access_count} times)'
                )
                logger.warning(f"Flagged IP {ip_address} for suspicious path access: {path}")
    
    logger.info("Anomaly detection task completed")


@shared_task
def auto_block_suspicious_ips():
    """
    Task to automatically block IPs that have been flagged multiple times.
    """
    # Get IPs flagged more than 3 times in the last 24 hours
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    
    repeat_offenders = SuspiciousIP.objects.filter(
        flagged_at__gte=twenty_four_hours_ago,
        resolved=False
    ).values('ip_address').annotate(
        flag_count=Count('id')
    ).filter(flag_count__gte=3)
    
    for ip_data in repeat_offenders:
        ip_address = ip_data['ip_address']
        flag_count = ip_data['flag_count']
        
        # Check if not already blocked
        if not BlockedIP.objects.filter(ip_address=ip_address).exists():
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=f'Auto-blocked: {flag_count} suspicious activities detected'
            )
            
            # Mark related suspicious entries as resolved
            SuspiciousIP.objects.filter(
                ip_address=ip_address,
                resolved=False
            ).update(resolved=True)
            
            logger.warning(f"Auto-blocked IP {ip_address} after {flag_count} suspicious activities")


@shared_task
def cleanup_old_logs():
    """
    Task to clean up old request logs to prevent database bloat.
    Keeps logs for 30 days.
    """
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    deleted_count = RequestLog.objects.filter(
        timestamp__lt=thirty_days_ago
    ).delete()[0]
    
    logger.info(f"Cleaned up {deleted_count} old request logs")


@shared_task
def generate_security_report():
    """
    Task to generate daily security reports.
    """
    now = timezone.now()
    yesterday = now - timedelta(days=1)
    
    # Get statistics for the last 24 hours
    total_requests = RequestLog.objects.filter(timestamp__gte=yesterday).count()
    unique_ips = RequestLog.objects.filter(
        timestamp__gte=yesterday
    ).values('ip_address').distinct().count()
    
    suspicious_ips = SuspiciousIP.objects.filter(
        flagged_at__gte=yesterday
    ).count()
    
    blocked_ips = BlockedIP.objects.filter(
        created_at__gte=yesterday
    ).count()
    
    # Top countries by request volume
    top_countries = RequestLog.objects.filter(
        timestamp__gte=yesterday,
        country__isnull=False
    ).exclude(country='').values('country').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Most accessed paths
    top_paths = RequestLog.objects.filter(
        timestamp__gte=yesterday
    ).values('path').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    report_data = {
        'date': yesterday.date(),
        'total_requests': total_requests,
        'unique_ips': unique_ips,
        'suspicious_ips': suspicious_ips,
        'blocked_ips': blocked_ips,
        'top_countries': list(top_countries),
        'top_paths': list(top_paths),
    }
    
    logger.info(f"Security report generated: {report_data}")
    
    # In a real implementation, you might want to:
    # - Send email reports to administrators
    # - Store reports in a separate model
    # - Export to external monitoring systems
    
    return report_data


@shared_task
def check_geolocation_consistency():
    """
    Task to check and update missing geolocation data.
    """
    from .middleware import IPTrackingMiddleware
    
    # Get recent logs without geolocation data
    logs_missing_geo = RequestLog.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24),
        country__isnull=True
    ).values('ip_address').distinct()
    
    middleware = IPTrackingMiddleware()
    updated_count = 0
    
    for log_data in logs_missing_geo:
        ip_address = log_data['ip_address']
        country, city = middleware.get_geolocation(ip_address)
        
        if country:  # Only update if we got valid data
            RequestLog.objects.filter(
                ip_address=ip_address,
                country__isnull=True
            ).update(country=country, city=city)
            updated_count += 1
    
    logger.info(f"Updated geolocation data for {updated_count} IP addresses")
    return updated_count