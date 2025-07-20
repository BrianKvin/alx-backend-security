import logging
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from ipware import get_client_ip
from .models import RequestLog, BlockedIP
import requests
import json

logger = logging.getLogger(__name__)


class IPTrackingMiddleware(MiddlewareMixin):
    """Middleware to log IP addresses, block blacklisted IPs, and add geolocation data."""

    def process_request(self, request):
        # Get client IP address
        client_ip, is_routable = get_client_ip(request)
        
        if not client_ip:
            client_ip = '127.0.0.1'  # Fallback for local development
        
        # Check if IP is blacklisted
        if self.is_blocked_ip(client_ip):
            logger.warning(f"Blocked IP attempted access: {client_ip}")
            return HttpResponseForbidden("Access denied: Your IP address is blocked.")
        
        # Store IP in request for later use
        request.client_ip = client_ip
        
        # Log the request with geolocation
        self.log_request(client_ip, request.path)
        
        return None

    def is_blocked_ip(self, ip_address):
        """Check if IP is in the blacklist using cache for performance."""
        cache_key = f"blocked_ip_{ip_address}"
        is_blocked = cache.get(cache_key)
        
        if is_blocked is None:
            # Check database
            is_blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
            # Cache result for 5 minutes
            cache.set(cache_key, is_blocked, 300)
        
        return is_blocked

    def get_geolocation(self, ip_address):
        """Get geolocation data for IP address with caching."""
        if ip_address in ['127.0.0.1', '::1'] or ip_address.startswith('192.168.'):
            return None, None  # Skip local IPs
        
        cache_key = f"geo_{ip_address}"
        geo_data = cache.get(cache_key)
        
        if geo_data is None:
            try:
                # Using ipinfo.io (free tier allows 1000 requests/day)
                response = requests.get(
                    f"https://ipinfo.io/{ip_address}/json",
                    timeout=2
                )
                
                if response.status_code == 200:
                    data = response.json()
                    country = data.get('country', '')
                    city = data.get('city', '')
                    geo_data = {'country': country, 'city': city}
                else:
                    geo_data = {'country': '', 'city': ''}
                
                # Cache for 24 hours
                cache.set(cache_key, geo_data, 86400)
                
            except Exception as e:
                logger.error(f"Geolocation API error for {ip_address}: {e}")
                geo_data = {'country': '', 'city': ''}
                # Cache failed attempts for 1 hour to avoid repeated failures
                cache.set(cache_key, geo_data, 3600)
        
        return geo_data.get('country', ''), geo_data.get('city', '')

    def log_request(self, ip_address, path):
        """Log request with geolocation data."""
        try:
            country, city = self.get_geolocation(ip_address)
            
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=country,
                city=city
            )
        except Exception as e:
            logger.error(f"Failed to log request for {ip_address}: {e}")