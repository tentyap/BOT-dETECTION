"""
Security and Telemetry Utilities for Bot Detection System.
Provides safe client IP extraction, header sanitization, and path filtering.
"""
import ipaddress
import logging
from django.conf import settings

logger = logging.getLogger('detector')


def get_client_ip(request):
    """
    Safely extracts the client IP address from the request.
    
    Security Requirement:
    - Never trust X-Forwarded-For blindly because clients can easily spoof it!
    - Only trust X-Forwarded-For if USE_X_FORWARDED_FOR is True AND the direct connection
      (REMOTE_ADDR) originates from an IP listed in TRUSTED_PROXIES (e.g., Cloudflare, AWS ALB, Nginx).
    - Otherwise, default strictly to request.META['REMOTE_ADDR'].
    """
    remote_addr = request.META.get('REMOTE_ADDR', '127.0.0.1')
    
    # Standardize local loopback addresses for readability
    if remote_addr in ('::1', 'localhost'):
        remote_addr = '127.0.0.1'

    use_forwarded = getattr(settings, 'USE_X_FORWARDED_FOR', False)
    trusted_proxies = getattr(settings, 'TRUSTED_PROXIES', [])

    if use_forwarded and remote_addr in trusted_proxies:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For format: client, proxy1, proxy2
            # The client IP is the first entry
            client_candidate = x_forwarded_for.split(',')[0].strip()
            try:
                # Validate that client_candidate is a syntactically valid IP address
                ipaddress.ip_address(client_candidate)
                return client_candidate
            except ValueError:
                logger.warning(f"Malformed IP in X-Forwarded-For: '{client_candidate}'. Falling back to REMOTE_ADDR.")

    # Validate REMOTE_ADDR syntax
    try:
        ipaddress.ip_address(remote_addr)
        return remote_addr
    except ValueError:
        return '127.0.0.1'


def extract_request_headers(request):
    """
    Extracts standard HTTP client headers from request.META into a clean dictionary.
    Excludes sensitive environment and internal server variables.
    """
    headers = {}
    
    # Common headers we specifically care about for browser fingerprinting & anomaly checks
    standard_headers = {
        'HTTP_ACCEPT': 'Accept',
        'HTTP_ACCEPT_LANGUAGE': 'Accept-Language',
        'HTTP_ACCEPT_ENCODING': 'Accept-Encoding',
        'HTTP_CONNECTION': 'Connection',
        'HTTP_USER_AGENT': 'User-Agent',
        'HTTP_REFERER': 'Referer',
        'HTTP_SEC_CH_UA': 'Sec-CH-UA',
        'HTTP_SEC_CH_UA_MOBILE': 'Sec-CH-UA-Mobile',
        'HTTP_SEC_CH_UA_PLATFORM': 'Sec-CH-UA-Platform',
        'HTTP_SEC_FETCH_DEST': 'Sec-Fetch-Dest',
        'HTTP_SEC_FETCH_MODE': 'Sec-Fetch-Mode',
        'HTTP_SEC_FETCH_SITE': 'Sec-Fetch-Site',
        'HTTP_UPGRADE_INSECURE_REQUESTS': 'Upgrade-Insecure-Requests',
    }

    for meta_key, header_name in standard_headers.items():
        val = request.META.get(meta_key)
        if val:
            headers[header_name] = str(val)[:500]  # Truncate overly long values for safety

    return headers


def should_ignore_path(path):
    """
    Determines whether a requested path should be ignored by the tracking system.
    Static assets, media files, and favicons should not skew bot statistics or rate limits.
    """
    ignored_prefixes = (
        '/static/',
        '/media/',
        '/favicon.ico',
        '/robots.txt',
    )
    return path.startswith(ignored_prefixes)
