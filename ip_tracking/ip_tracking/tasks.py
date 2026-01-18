from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']
REQUEST_THRESHOLD = 100  # requests per hour

@shared_task
def detect_suspicious_ips():
    """
    Detect IPs that:
    - Make > 100 requests in the last hour
    - Access sensitive paths
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1. Detect high request rate
    high_requests = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=models.Count('id'))
        .filter(request_count__gt=REQUEST_THRESHOLD)
    )

    for entry in high_requests:
        ip = entry['ip_address']
        reason = f"Exceeded {REQUEST_THRESHOLD} requests/hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    # 2. Detect access to sensitive paths
    sensitive_access = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS)
        .values('ip_address', 'path')
        .distinct()
    )

    for entry in sensitive_access:
        ip = entry['ip_address']
        reason = f"Accessed sensitive path: {entry['path']}"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)
