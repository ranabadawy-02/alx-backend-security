from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation.geocoder import GeoIP  # from django-ipgeolocation
from .models import RequestLog, BlockedIP

GEO_CACHE_TTL = 60 * 60 * 24  # 24 hours

class IPLoggingMiddleware:
    """
    Middleware to log requests, block blacklisted IPs,
    and populate geolocation data.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = GeoIP()

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Block request if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Get geolocation from cache or API
        geo_data = cache.get(f'geo_{ip}')
        if not geo_data:
            geo_data = self.geo.get(ip)
            cache.set(f'geo_{ip}', geo_data, GEO_CACHE_TTL)

        country = geo_data.get('country_name', '') if geo_data else ''
        city = geo_data.get('city', '') if geo_data else ''

        # Log request with geolocation
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=country,
            city=city
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
