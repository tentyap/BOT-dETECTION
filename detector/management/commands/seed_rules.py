from django.core.management.base import BaseCommand
from detector.models import DetectionRule

class Command(BaseCommand):
    help = "Populates the database with initial Bot Detection rules."

    def handle(self, *args, **kwargs):
        rules = [
            {
                'name': 'Missing or Empty User-Agent',
                'rule_type': 'USER_AGENT',
                'description': 'Detects incoming HTTP requests with an empty or omitted User-Agent header. Modern browsers always send an identifiable User-Agent.',
                'pattern': r'^$',
                'risk_weight': 35,
                'is_active': True,
            },
            {
                'name': 'Known Bot / Automated Tool User-Agent',
                'rule_type': 'USER_AGENT',
                'description': 'Detects User-Agent headers matching known automation frameworks and scrapers (curl, wget, python-requests, scrapy, postman, nmap, sqlmap, nikto, httpx).',
                'pattern': r'(curl|wget|python-requests|scrapy|aiohttp|urllib|postman|insomnia|nmap|sqlmap|nikto|httpx|gobuster|dirbuster|censys)',
                'risk_weight': 50,
                'is_active': True,
            },
            {
                'name': 'Excessive Request Frequency (Rate Limiting)',
                'rule_type': 'RATE_LIMIT',
                'description': 'Detects visitor IPs that trigger more than 20 requests within a 10-second rolling window.',
                'pattern': '20_per_10s',
                'risk_weight': 30,
                'is_active': True,
            },
            {
                'name': 'Access to Sensitive / Vulnerability Probing Paths',
                'rule_type': 'SUSPICIOUS_PATH',
                'description': 'Detects attempts to scan for common sensitive files, backup archives, or environment files (.env, wp-login, .git, phpmyadmin, etc.).',
                'pattern': r'(\.env|\.git|\.aws|wp-login\.php|phpmyadmin|\.bak|\.config|shell|xmlrpc\.php)',
                'risk_weight': 40,
                'is_active': True,
            },
            {
                'name': 'Missing Essential Browser Headers',
                'rule_type': 'HEADER_ANOMALY',
                'description': 'Detects standard GET requests missing standard browser headers such as Accept or Accept-Language.',
                'pattern': 'missing_accept',
                'risk_weight': 20,
                'is_active': True,
            },
            {
                'name': 'Suspicious or Rare HTTP Method',
                'rule_type': 'HTTP_METHOD',
                'description': 'Detects HTTP methods rarely used by standard web visitors on web pages (e.g., PUT, DELETE, TRACE, CONNECT, OPTIONS).',
                'pattern': r'^(PUT|DELETE|TRACE|CONNECT|OPTIONS)$',
                'risk_weight': 25,
                'is_active': True,
            },
        ]

        created_count = 0
        for rule_data in rules:
            rule, created = DetectionRule.objects.get_or_create(
                name=rule_data['name'],
                defaults=rule_data
            )
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f"Created rule: {rule.name} (+{rule.risk_weight} pts)"))
            else:
                self.stdout.write(f"Rule already exists: {rule.name}")

        self.stdout.write(self.style.SUCCESS(f"\nDone! Seeded {created_count} new detection rules into SQLite."))
