"""
Visitor Tracking and Bot Detection Middleware.
Intercepts incoming HTTP requests, collects client telemetry, evaluates detection rules,
calculates risk scores, classifies traffic, enforces IP blocklists, and logs audit forensics.
"""
import logging
from django.utils import timezone
from django.template.loader import render_to_string
from django.http import HttpResponseForbidden
from .utils import get_client_ip, extract_request_headers, should_ignore_path
from .models import IPAddress
from .tracker import RequestTracker
from .rules import BotRuleEvaluator

logger = logging.getLogger('detector')


class BotDetectionMiddleware:
    """
    Core security middleware that monitors incoming HTTP traffic.
    
    Responsibilities:
    1. Ignores static/media assets to avoid skewing telemetry.
    2. Safely extracts and normalizes the client IP address.
    3. Checks administrative IP Blocklist (403 if blocked, exempts /admin/ and /toggle-ip/ for admin recovery).
    4. Packages visitor telemetry and rolling frequency metrics.
    5. Evaluates detection rules, calculates risk score, and classifies visitor.
    6. Automatically denies access (403) to critical-risk traffic (risk >= 80).
    7. Persists visitor requests and forensic detection logs into SQLite.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # Step 1: Skip static assets and media files
        if should_ignore_path(path):
            return self.get_response(request)

        # Step 2: Extract client IP safely (mitigating header spoofing)
        client_ip = get_client_ip(request)

        # Step 3: Check administrative IP Blocklist in SQLite database
        # Note: Administrative endpoints (/admin/ and /toggle-ip/) are exempted to prevent administrative lockout
        is_admin_route = path.startswith(('/admin/', '/toggle-ip/'))
        
        try:
            ip_record = IPAddress.objects.filter(ip_address=client_ip).first()
            if ip_record and ip_record.status == 'BLOCKED' and not is_admin_route:
                logger.warning(f"Blocked request from administratively restricted IP: {client_ip} to {path}")
                
                blocked_telemetry = {
                    'client_ip': client_ip,
                    'ip_record': ip_record,
                    'path': path,
                    'method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'referer': request.META.get('HTTP_REFERER', ''),
                    'headers': extract_request_headers(request),
                    'session_key': request.session.session_key if hasattr(request, 'session') else None,
                }
                RequestTracker.record_request(
                    telemetry=blocked_telemetry,
                    status_code=403,
                    risk_score=100,
                    classification='MALICIOUS_BOT',
                    is_blocked=True
                )

                context = {
                    'client_ip': client_ip,
                    'incident_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'block_reason': ip_record.notes or "Your IP address is listed on the active blocklist.",
                }
                content = render_to_string('detector/blocked.html', context, request=request)
                return HttpResponseForbidden(content)
        except Exception as e:
            logger.error(f"Error querying IP status for {client_ip}: {e}")
            ip_record = None

        # Step 4: Extract comprehensive visitor telemetry and calculate rolling frequency metrics
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        referer = request.META.get('HTTP_REFERER', '')
        headers = extract_request_headers(request)
        session_key = request.session.session_key if hasattr(request, 'session') else None
        frequency_metrics = RequestTracker.calculate_frequency_metrics(client_ip, path)

        request.visitor_telemetry = {
            'client_ip': client_ip,
            'ip_record': ip_record,
            'path': path,
            'full_path': request.get_full_path(),
            'method': request.method,
            'user_agent': user_agent,
            'referer': referer,
            'headers': headers,
            'timestamp': timezone.now(),
            'session_key': session_key,
            'frequency_metrics': frequency_metrics,
        }

        # Step 5: Evaluate detection rules and compute risk score
        rules_triggered = BotRuleEvaluator.evaluate_all(request.visitor_telemetry)
        risk_score = min(100, sum(r.risk_points for r in rules_triggered))

        # Evidence-based classification
        if risk_score >= 80:
            classification = 'MALICIOUS_BOT'
        elif risk_score >= 50:
            classification = 'BOT'
        elif risk_score >= 30:
            classification = 'SUSPICIOUS'
        else:
            classification = 'HUMAN'

        # Store evaluation results on request object for views
        request.rules_triggered = rules_triggered
        request.risk_score = risk_score
        request.classification = classification

        # Step 6: Critical Risk Automated Blocking (Score >= 80)
        # Only block if not on administrative management routes
        if risk_score >= 80 and not is_admin_route:
            reasons = [r.reason for r in rules_triggered]
            logger.warning(f"Critical risk traffic intercepted from {client_ip} (Score: {risk_score}): {'; '.join(reasons)}")
            
            RequestTracker.record_request(
                telemetry=request.visitor_telemetry,
                status_code=403,
                risk_score=risk_score,
                classification=classification,
                is_blocked=True,
                rules_triggered=rules_triggered,
            )

            context = {
                'client_ip': client_ip,
                'incident_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'block_reason': f"Critical risk score ({risk_score}/100) triggered: {reasons[0] if reasons else 'Automated security policy'}",
            }
            content = render_to_string('detector/blocked.html', context, request=request)
            return HttpResponseForbidden(content)

        # Step 7: Pass the request down the chain to views
        response = self.get_response(request)

        # Step 8: Persist the completed request in SQLite
        try:
            status_code = response.status_code
            request.visitor_telemetry['status_code'] = status_code

            visitor_record = RequestTracker.record_request(
                telemetry=request.visitor_telemetry,
                status_code=status_code,
                risk_score=risk_score,
                classification=classification,
                is_blocked=False,
                rules_triggered=rules_triggered,
            )
            request.visitor_record = visitor_record
        except Exception as e:
            logger.error(f"Error saving request record for {client_ip}: {e}")

        return response
