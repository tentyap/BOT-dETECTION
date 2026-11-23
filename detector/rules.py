"""
Rule-Based Bot Detection Engine for Bot Shield.
Contains individual inspection rules for User-Agents, path probing,
rate bursts, header anomalies, HTTP methods, and legitimate search engine crawlers.
"""
import re
import logging
from dataclasses import dataclass
from typing import List, Optional
from .models import DetectionRule

logger = logging.getLogger('detector')


@dataclass
class RuleEvaluationResult:
    """
    Data structure representing the outcome of an individual rule check.
    """
    rule_name: str
    rule_type: str
    triggered: bool
    risk_points: int
    reason: str
    rule_instance: Optional[DetectionRule] = None


# ==============================================================================
# Known Signatures and Regular Expressions
# ==============================================================================

# Common automated tools, CLI scrapers, and penetration testing scanners
BOT_USER_AGENT_PATTERN = re.compile(
    r'(curl|wget|python-requests|aiohttp|urllib|scrapy|postman|insomnia|'
    r'httpie|go-http-client|apache-httpclient|java/|okhttp|censys|shodan|'
    r'nmap|sqlmap|nikto|gobuster|dirbuster|wfuzz|masscan|zgrab|httpx)',
    re.IGNORECASE
)

# Legitimate search engine crawlers that should NOT be penalized as malicious
SEARCH_ENGINE_PATTERN = re.compile(
    r'(googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|sogou|exabot|facebot|facebookexternalhit)',
    re.IGNORECASE
)

# Common sensitive files and administrative backdoors targeted by malicious scanners
SENSITIVE_PATHS_PATTERN = re.compile(
    r'(\.env|\.git|\.aws|\.svn|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|'
    r'admin\.php|config\.(php|inc|json|yaml|ini)|shell\.php|setup\.php|'
    r'info\.php|phpinfo|\.bak|\.sql|\.tar\.gz|\.zip|cgi-bin|etc/passwd)',
    re.IGNORECASE
)

# Uncommon/suspicious HTTP methods on standard web endpoints
SUSPICIOUS_METHODS = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS', 'PATCH'}


class BotRuleEvaluator:
    """
    Evaluates HTTP request telemetry against active security rules.
    """

    @classmethod
    def is_legitimate_search_engine(cls, user_agent: str) -> bool:
        """
        Determines whether the User-Agent claims to be a recognized search engine crawler
        (e.g., Googlebot, Bingbot).
        """
        if not user_agent:
            return False
        return bool(SEARCH_ENGINE_PATTERN.search(user_agent))

    @classmethod
    def check_empty_user_agent(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Checks for completely missing or empty User-Agent header.
        """
        user_agent = telemetry.get('user_agent', '').strip()
        risk_weight = rule.risk_weight if rule else 35
        rule_name = rule.name if rule else "Missing or Empty User-Agent"

        if not user_agent:
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="USER_AGENT",
                triggered=True,
                risk_points=risk_weight,
                reason="The incoming request did not supply a User-Agent header. Modern browsers always send one.",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="USER_AGENT",
            triggered=False,
            risk_points=0,
            reason="User-Agent header is present.",
            rule_instance=rule
        )

    @classmethod
    def check_known_bot_user_agent(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Checks for known automated tools, scripting libraries, and scanner User-Agents.
        Exempts recognized search engine crawlers.
        """
        user_agent = telemetry.get('user_agent', '').strip()
        risk_weight = rule.risk_weight if rule else 50
        rule_name = rule.name if rule else "Known Bot / Automated Tool User-Agent"

        if not user_agent:
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="USER_AGENT",
                triggered=False,
                risk_points=0,
                reason="Handled by Missing User-Agent check.",
                rule_instance=rule
            )

        # Allow legitimate search crawlers through without penalty
        if cls.is_legitimate_search_engine(user_agent):
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="USER_AGENT",
                triggered=False,
                risk_points=0,
                reason=f"Recognized legitimate search engine crawler: {user_agent[:60]}",
                rule_instance=rule
            )

        match = BOT_USER_AGENT_PATTERN.search(user_agent)
        if match:
            matched_tool = match.group(0)
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="USER_AGENT",
                triggered=True,
                risk_points=risk_weight,
                reason=f"Automated tool or scraper signature detected in User-Agent: '{matched_tool}'",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="USER_AGENT",
            triggered=False,
            risk_points=0,
            reason="User-Agent is not in the known bot signature list.",
            rule_instance=rule
        )

    @classmethod
    def check_sensitive_path(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Detects reconnaissance and vulnerability scans targeting sensitive endpoints (.env, wp-login, etc.).
        """
        path = telemetry.get('path', '')
        risk_weight = rule.risk_weight if rule else 40
        rule_name = rule.name if rule else "Access to Sensitive / Vulnerability Probing Paths"

        match = SENSITIVE_PATHS_PATTERN.search(path)
        if match:
            probed_target = match.group(0)
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="SUSPICIOUS_PATH",
                triggered=True,
                risk_points=risk_weight,
                reason=f"Request attempted to access known sensitive or probing path: '{probed_target}' in '{path}'",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="SUSPICIOUS_PATH",
            triggered=False,
            risk_points=0,
            reason="Requested path is standard application content.",
            rule_instance=rule
        )

    @classmethod
    def check_rate_limiting(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Evaluates burst frequency in the last 10 seconds.
        """
        metrics = telemetry.get('frequency_metrics', {})
        burst_count = metrics.get('burst_count_10s', 0)
        risk_weight = rule.risk_weight if rule else 30
        rule_name = rule.name if rule else "Excessive Request Frequency (Rate Limiting)"

        # Threshold: More than 15 requests in 10 seconds indicates automated flooding
        if burst_count > 15:
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="RATE_LIMIT",
                triggered=True,
                risk_points=risk_weight,
                reason=f"Excessive request burst detected: {burst_count} requests in 10 seconds (threshold: 15).",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="RATE_LIMIT",
            triggered=False,
            risk_points=0,
            reason="Request rate is within acceptable human tolerance.",
            rule_instance=rule
        )

    @classmethod
    def check_repeated_endpoint(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Detects endpoint fuzzing: same URL path hit excessively (> 25 times) in 60 seconds.
        """
        metrics = telemetry.get('frequency_metrics', {})
        path_count = metrics.get('path_count_60s', 0)
        path = telemetry.get('path', '')
        risk_weight = 20
        rule_name = "Repeated Endpoint Fuzzing"

        if path_count > 25:
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="RATE_LIMIT",
                triggered=True,
                risk_points=risk_weight,
                reason=f"Repeated targeting of endpoint '{path}': {path_count} hits in 60 seconds (threshold: 25).",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="RATE_LIMIT",
            triggered=False,
            risk_points=0,
            reason="Endpoint frequency is normal.",
            rule_instance=rule
        )

    @classmethod
    def check_header_anomalies(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Checks for missing standard browser headers (Accept, Accept-Language).
        Real browsers consistently send these; basic scripts usually omit them.
        """
        headers = telemetry.get('headers', {})
        user_agent = telemetry.get('user_agent', '')
        risk_weight = rule.risk_weight if rule else 20
        rule_name = rule.name if rule else "Missing Essential Browser Headers"

        # Search crawlers are exempted from browser-specific headers
        if cls.is_legitimate_search_engine(user_agent):
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="HEADER_ANOMALY",
                triggered=False,
                risk_points=0,
                reason="Search crawler exempted from browser header check.",
                rule_instance=rule
            )

        missing = []
        if 'Accept' not in headers:
            missing.append('Accept')
        if 'Accept-Language' not in headers:
            missing.append('Accept-Language')

        if missing:
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="HEADER_ANOMALY",
                triggered=True,
                risk_points=risk_weight,
                reason=f"Request is missing standard browser headers: {', '.join(missing)}.",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="HEADER_ANOMALY",
            triggered=False,
            risk_points=0,
            reason="All expected browser headers are present.",
            rule_instance=rule
        )

    @classmethod
    def check_http_method(cls, telemetry: dict, rule: Optional[DetectionRule] = None) -> RuleEvaluationResult:
        """
        Identifies unusual HTTP methods (PUT, DELETE, TRACE, etc.) on standard web endpoints.
        """
        method = telemetry.get('method', 'GET').upper()
        risk_weight = rule.risk_weight if rule else 25
        rule_name = rule.name if rule else "Suspicious or Rare HTTP Method"

        if method in SUSPICIOUS_METHODS:
            return RuleEvaluationResult(
                rule_name=rule_name,
                rule_type="HTTP_METHOD",
                triggered=True,
                risk_points=risk_weight,
                reason=f"Unusual HTTP method '{method}' observed for web path.",
                rule_instance=rule
            )

        return RuleEvaluationResult(
            rule_name=rule_name,
            rule_type="HTTP_METHOD",
            triggered=False,
            risk_points=0,
            reason="Standard HTTP method (GET/POST).",
            rule_instance=rule
        )

    @classmethod
    def evaluate_all(cls, telemetry: dict) -> List[RuleEvaluationResult]:
        """
        Runs all active detection rules against the request telemetry.
        Returns a list of all triggered RuleEvaluationResult objects.
        """
        try:
            # Index active rules by their exact database name for precise matching
            db_rules = {r.name: r for r in DetectionRule.objects.filter(is_active=True)}
        except Exception as e:
            logger.warning(f"Could not load rules from DB: {e}. Using defaults.")
            db_rules = {}

        results = []

        # 1. Check Missing User-Agent
        r_empty_ua = db_rules.get("Missing or Empty User-Agent")
        res1 = cls.check_empty_user_agent(telemetry, r_empty_ua)
        if res1.triggered:
            results.append(res1)

        # 2. Check Known Bot User-Agent (only if User-Agent exists)
        if not res1.triggered:
            r_bot_ua = db_rules.get("Known Bot / Automated Tool User-Agent")
            res2 = cls.check_known_bot_user_agent(telemetry, r_bot_ua)
            if res2.triggered:
                results.append(res2)

        # 3. Check Sensitive Path Probing
        r_path = db_rules.get("Access to Sensitive / Vulnerability Probing Paths")
        res3 = cls.check_sensitive_path(telemetry, r_path)
        if res3.triggered:
            results.append(res3)

        # 4. Check Rate Limiting / Flooding
        r_rate = db_rules.get("Excessive Request Frequency (Rate Limiting)")
        res4 = cls.check_rate_limiting(telemetry, r_rate)
        if res4.triggered:
            results.append(res4)

        # 5. Check Repeated Endpoint Probing
        res5 = cls.check_repeated_endpoint(telemetry)
        if res5.triggered:
            results.append(res5)

        # 6. Check Browser Header Anomalies
        r_hdr = db_rules.get("Missing Essential Browser Headers")
        res6 = cls.check_header_anomalies(telemetry, r_hdr)
        if res6.triggered:
            results.append(res6)

        # 7. Check Suspicious HTTP Methods
        r_method = db_rules.get("Suspicious or Rare HTTP Method")
        res7 = cls.check_http_method(telemetry, r_method)
        if res7.triggered:
            results.append(res7)

        return results
