"""
Request Tracker and Data Storage Service for Bot Shield.
Handles persistence of visitor telemetry, updates IP reputation records,
stores detection logs, and calculates real-time traffic frequency metrics.
"""
from datetime import timedelta
import logging
from django.utils import timezone
from .models import IPAddress, VisitorRequest, DetectionLog

logger = logging.getLogger('detector')


class RequestTracker:
    """
    Service responsible for persisting visitor telemetry into SQLite
    and tracking request rates for automated bot detection.
    """

    @staticmethod
    def get_or_create_ip(ip_address):
        """
        Retrieves or creates an IPAddress record for the given IP.
        Ensures thread-safe creation and maintains total request count.
        """
        try:
            ip_obj, created = IPAddress.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'status': 'MONITORED',
                    'reputation_score': 100,
                    'total_requests': 0,
                    'is_bot': False,
                }
            )
            return ip_obj
        except Exception as e:
            logger.error(f"Error in get_or_create_ip for {ip_address}: {e}")
            return None

    @staticmethod
    def calculate_frequency_metrics(ip_address, path):
        """
        Calculates rolling request frequencies for the given IP address:
        - burst_count_10s: Requests within the last 10 seconds (detects fast floods/scripts).
        - rate_count_60s: Requests within the last 60 seconds (detects sustained scraping).
        - path_count_60s: Repeated requests to this exact path in 60s (detects endpoint fuzzing).
        """
        now = timezone.now()
        ten_seconds_ago = now - timedelta(seconds=10)
        sixty_seconds_ago = now - timedelta(seconds=60)

        burst_count = VisitorRequest.objects.filter(
            ip_address_str=ip_address,
            timestamp__gte=ten_seconds_ago
        ).count()

        rate_count = VisitorRequest.objects.filter(
            ip_address_str=ip_address,
            timestamp__gte=sixty_seconds_ago
        ).count()

        path_count = VisitorRequest.objects.filter(
            ip_address_str=ip_address,
            path=path,
            timestamp__gte=sixty_seconds_ago
        ).count()

        return {
            'burst_count_10s': burst_count,
            'rate_count_60s': rate_count,
            'path_count_60s': path_count,
        }

    @classmethod
    def record_request(
        cls,
        telemetry,
        status_code=200,
        risk_score=0,
        classification='HUMAN',
        is_blocked=False,
        rules_triggered=None,
    ):
        """
        Creates and saves a VisitorRequest record in the database.
        Saves individual DetectionLog records and updates IPAddress metrics.
        """
        try:
            client_ip = telemetry['client_ip']
            ip_obj = telemetry.get('ip_record') or cls.get_or_create_ip(client_ip)

            if not ip_obj:
                logger.warning(f"Unable to resolve IPAddress record for {client_ip}. Skipping persistence.")
                return None

            # Create the VisitorRequest audit entry
            req_record = VisitorRequest.objects.create(
                ip=ip_obj,
                ip_address_str=client_ip,
                path=telemetry.get('path', '')[:1024],
                method=telemetry.get('method', 'GET')[:10],
                user_agent=telemetry.get('user_agent', ''),
                referer=telemetry.get('referer', ''),
                status_code=status_code,
                session_key=telemetry.get('session_key'),
                risk_score=risk_score,
                classification=classification,
                is_blocked=is_blocked,
                headers_json=telemetry.get('headers', {}),
            )

            # Persist individual DetectionLog records for forensics
            if rules_triggered:
                for r in rules_triggered:
                    DetectionLog.objects.create(
                        request=req_record,
                        rule=getattr(r, 'rule_instance', None),
                        rule_name=r.rule_name,
                        severity_points=r.risk_points,
                        reason=r.reason,
                    )

            # Update IPAddress reputation, is_bot, total_requests, and last_seen
            is_bot_traffic = classification in ('BOT', 'MALICIOUS_BOT') or ip_obj.is_bot
            new_reputation = max(0, 100 - risk_score)
            updated_reputation = min(ip_obj.reputation_score, new_reputation)

            IPAddress.objects.filter(pk=ip_obj.pk).update(
                total_requests=ip_obj.total_requests + 1,
                last_seen=timezone.now(),
                is_bot=is_bot_traffic,
                reputation_score=updated_reputation,
            )

            return req_record

        except Exception as e:
            logger.error(f"Error persisting VisitorRequest: {e}", exc_info=True)
            return None
