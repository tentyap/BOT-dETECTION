from django.contrib import admin
from .models import IPAddress, DetectionRule, VisitorRequest, DetectionLog


@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'status', 'total_requests', 'reputation_score', 'is_bot', 'last_seen')
    list_filter = ('status', 'is_bot', 'last_seen')
    search_fields = ('ip_address', 'notes')
    ordering = ('-last_seen',)
    readonly_fields = ('first_seen', 'last_seen', 'total_requests')
    actions = ['mark_as_blocked', 'mark_as_allowlisted', 'mark_as_monitored']

    @admin.action(description="Block selected IP addresses")
    def mark_as_blocked(self, request, queryset):
        queryset.update(status='BLOCKED')

    @admin.action(description="Allowlist selected IP addresses")
    def mark_as_allowlisted(self, request, queryset):
        queryset.update(status='ALLOWLISTED')

    @admin.action(description="Set selected IP addresses to Monitored")
    def mark_as_monitored(self, request, queryset):
        queryset.update(status='MONITORED')


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'rule_type', 'risk_weight', 'is_active', 'updated_at')
    list_filter = ('rule_type', 'is_active')
    search_fields = ('name', 'description', 'pattern')
    list_editable = ('risk_weight', 'is_active')
    ordering = ('-risk_weight', 'name')


class DetectionLogInLine(admin.TabularInline):
    model = DetectionLog
    extra = 0
    readonly_fields = ('rule_name', 'severity_points', 'reason', 'created_at')
    can_delete = False


@admin.register(VisitorRequest)
class VisitorRequestAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'ip_address_str', 'method', 'path', 'classification', 'risk_score', 'is_blocked', 'status_code')
    list_filter = ('classification', 'is_blocked', 'method', 'timestamp')
    search_fields = ('ip_address_str', 'path', 'user_agent')
    readonly_fields = ('timestamp', 'ip', 'ip_address_str', 'method', 'path', 'user_agent', 'referer', 'status_code', 'risk_score', 'classification', 'is_blocked', 'headers_json', 'session_key')
    ordering = ('-timestamp',)
    inlines = [DetectionLogInLine]
    date_hierarchy = 'timestamp'


@admin.register(DetectionLog)
class DetectionLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'request', 'rule_name', 'severity_points', 'reason')
    list_filter = ('rule_name', 'created_at')
    search_fields = ('rule_name', 'reason', 'request__ip_address_str')
    readonly_fields = ('created_at', 'request', 'rule', 'rule_name', 'severity_points', 'reason')
    ordering = ('-created_at',)
