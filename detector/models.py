from django.db import models

# ==============================================================================
# Model 1: IPAddress
# Purpose: Maintains global state, reputation, and access control for unique IP addresses.
# ==============================================================================
class IPAddress(models.Model):
    """
    Represents a unique visitor IP address.
    Tracks reputation, status (monitored, allowlisted, blocked), and traffic aggregates.
    """
    STATUS_CHOICES = [
        ('MONITORED', 'Monitored (Default)'),
        ('ALLOWLISTED', 'Allowlisted (Bypass Rules)'),
        ('BLOCKED', 'Blocked (Deny Access)'),
    ]

    # Supports both IPv4 and IPv6; unpack_ipv4 standardizes ::ffff:192.0.2.1 to 192.0.2.1
    ip_address = models.GenericIPAddressField(
        unique=True,
        unpack_ipv4=True,
        db_index=True,
        help_text="Standard IPv4 or IPv6 client address"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='MONITORED',
        db_index=True,
        help_text="Access control status for this IP"
    )
    total_requests = models.PositiveIntegerField(
        default=0,
        help_text="Cumulative number of requests made by this IP"
    )
    reputation_score = models.IntegerField(
        default=100,
        help_text="Current reputation score (0 = malicious, 100 = completely trustworthy)"
    )
    is_bot = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Flag indicating if this IP has been classified as an automated bot"
    )
    first_seen = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp of the very first request from this IP"
    )
    last_seen = models.DateTimeField(
        auto_now=True,
        db_index=True,
        help_text="Timestamp of the most recent request from this IP"
    )
    notes = models.TextField(
        blank=True,
        null=True,
        help_text="Administrator notes, manual block reasons, or ISP info"
    )

    class Meta:
        verbose_name = "IP Address"
        verbose_name_plural = "IP Addresses"
        ordering = ['-last_seen']

    def __str__(self):
        return f"{self.ip_address} [{self.get_status_display()}]"


# ==============================================================================
# Model 2: DetectionRule
# Purpose: Dynamic, configurable rules evaluated by the Bot Detection Engine.
# ==============================================================================
class DetectionRule(models.Model):
    """
    Defines a rule used by the Bot Detection Engine to inspect visitor requests.
    Rules can be enabled/disabled and weighted dynamically by administrators.
    """
    RULE_TYPE_CHOICES = [
        ('USER_AGENT', 'User-Agent Signature Analysis'),
        ('RATE_LIMIT', 'Request Rate Limiting / Flooding'),
        ('HEADER_ANOMALY', 'Browser Header Anomaly Check'),
        ('SUSPICIOUS_PATH', 'Sensitive / Probing URL Path'),
        ('HTTP_METHOD', 'Unusual HTTP Request Method'),
    ]

    name = models.CharField(
        max_length=120,
        unique=True,
        help_text="Unique name identifying the detection rule (e.g., 'Missing User-Agent')"
    )
    rule_type = models.CharField(
        max_length=40,
        choices=RULE_TYPE_CHOICES,
        db_index=True,
        help_text="Category of inspection logic applied"
    )
    description = models.TextField(
        help_text="Detailed explanation of what this rule detects and why it poses risk"
    )
    pattern = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Regex, keyword pattern, or threshold parameter used by the rule engine"
    )
    risk_weight = models.PositiveSmallIntegerField(
        default=20,
        help_text="Points contributed to total risk score (0-100) when triggered"
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Enables or disables rule evaluation in real time"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Detection Rule"
        verbose_name_plural = "Detection Rules"
        ordering = ['-risk_weight', 'name']

    def __str__(self):
        status = "Active" if self.is_active else "Disabled"
        return f"{self.name} (+{self.risk_weight} pts) [{status}]"


# ==============================================================================
# Model 3: VisitorRequest
# Purpose: Comprehensive audit log of every intercepted HTTP request.
# ==============================================================================
class VisitorRequest(models.Model):
    """
    Stores full metadata for an intercepted incoming HTTP request.
    Includes classification outcome, calculated risk score, and raw headers for forensics.
    """
    CLASSIFICATION_CHOICES = [
        ('HUMAN', 'Human / Normal Traffic'),
        ('SUSPICIOUS', 'Suspicious Traffic'),
        ('BOT', 'Automated Bot'),
        ('MALICIOUS_BOT', 'Malicious Bot'),
    ]

    ip = models.ForeignKey(
        IPAddress,
        on_delete=models.CASCADE,
        related_name='requests',
        help_text="Foreign key to the originating IPAddress record"
    )
    ip_address_str = models.GenericIPAddressField(
        db_index=True,
        unpack_ipv4=True,
        help_text="Direct IP string representation for optimized filtering"
    )
    path = models.CharField(
        max_length=1024,
        db_index=True,
        help_text="Target URL path requested by the client (e.g., '/admin/login/')"
    )
    method = models.CharField(
        max_length=10,
        help_text="HTTP method used (GET, POST, HEAD, PUT, DELETE, etc.)"
    )
    user_agent = models.TextField(
        blank=True,
        default='',
        help_text="Raw HTTP User-Agent string provided by the client"
    )
    referer = models.TextField(
        blank=True,
        default='',
        help_text="HTTP Referer header indicating traffic origin"
    )
    status_code = models.PositiveSmallIntegerField(
        default=200,
        help_text="HTTP response status code served to the visitor"
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Exact date and time when the request was intercepted"
    )
    session_key = models.CharField(
        max_length=40,
        blank=True,
        null=True,
        db_index=True,
        help_text="Django session identifier for session-based tracking"
    )
    risk_score = models.PositiveSmallIntegerField(
        default=0,
        db_index=True,
        help_text="Calculated risk score from 0 (Safe) to 100 (Critical Risk)"
    )
    classification = models.CharField(
        max_length=30,
        choices=CLASSIFICATION_CHOICES,
        default='HUMAN',
        db_index=True,
        help_text="Evidence-based classification result"
    )
    is_blocked = models.BooleanField(
        default=False,
        db_index=True,
        help_text="True if the request was denied/blocked with 403 Forbidden"
    )
    headers_json = models.JSONField(
        default=dict,
        blank=True,
        help_text="Captured HTTP request headers stored securely in JSON format for analysis"
    )

    class Meta:
        verbose_name = "Visitor Request"
        verbose_name_plural = "Visitor Requests"
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.method} {self.path} - {self.get_classification_display()} ({self.risk_score})"


# ==============================================================================
# Model 4: DetectionLog
# Purpose: Granular breakdown of individual rules triggered by a specific request.
# ==============================================================================
class DetectionLog(models.Model):
    """
    Granular audit log linking a VisitorRequest to specific DetectionRules that triggered.
    Explains the exact reasons and point contributions toward the final risk score.
    """
    request = models.ForeignKey(
        VisitorRequest,
        on_delete=models.CASCADE,
        related_name='detection_logs',
        help_text="The visitor request on which an anomaly was detected"
    )
    rule = models.ForeignKey(
        DetectionRule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='logs',
        help_text="The detection rule that was triggered (if still exists)"
    )
    rule_name = models.CharField(
        max_length=120,
        help_text="Archived name of the rule in case the rule is later renamed or deleted"
    )
    severity_points = models.PositiveSmallIntegerField(
        help_text="Points contributed to the visitor request's overall risk score"
    )
    reason = models.TextField(
        help_text="Human-readable explanation of why the rule flagged this request"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when the detection log entry was recorded"
    )

    class Meta:
        verbose_name = "Detection Log"
        verbose_name_plural = "Detection Logs"
        ordering = ['-created_at']

    def __str__(self):
        return f"Triggered '{self.rule_name}' (+{self.severity_points} pts) on Req #{self.request_id}"
