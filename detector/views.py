import json
import ipaddress
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Max, Count, Q
from django.db.models.functions import TruncDate
from .models import VisitorRequest, IPAddress, DetectionRule, DetectionLog


def index(request):
    """
    Landing View:
    1. Interactive Front-End IP Search / Forensic Lookup.
    2. Real-time telemetry and risk analysis of the current visitor.
    3. Quick system traffic statistics.
    """
    telemetry = getattr(request, 'visitor_telemetry', {})
    rules_triggered = getattr(request, 'rules_triggered', [])
    risk_score = getattr(request, 'risk_score', 0)
    classification = getattr(request, 'classification', 'HUMAN')
    current_ip = telemetry.get('client_ip', '127.0.0.1')

    # Counters
    total_requests = VisitorRequest.objects.count()
    total_ips = IPAddress.objects.count()
    detected_bots = IPAddress.objects.filter(is_bot=True).count()
    blocked_ips = IPAddress.objects.filter(status='BLOCKED').count()

    # IP Search
    search_query = request.GET.get('search_ip', '').strip()
    searched_ip_obj = None
    searched_requests = []
    searched_stats = {}
    search_error = None

    if search_query:
        try:
            cleaned_ip = str(ipaddress.ip_address(search_query))
            searched_ip_obj = IPAddress.objects.filter(ip_address=cleaned_ip).first()

            if searched_ip_obj:
                base_qs = VisitorRequest.objects.filter(ip=searched_ip_obj)
                max_risk = base_qs.aggregate(Max('risk_score'))['risk_score__max'] or 0
                human_count = base_qs.filter(classification='HUMAN').count()
                bot_count = base_qs.filter(classification__in=['BOT', 'MALICIOUS_BOT']).count()
                suspicious_count = base_qs.filter(classification='SUSPICIOUS').count()

                triggered_rule_names = (
                    DetectionLog.objects.filter(request__ip=searched_ip_obj)
                    .values_list('rule_name', flat=True)
                    .distinct()
                )

                searched_requests = (
                    base_qs.prefetch_related('detection_logs')
                    .order_by('-timestamp')[:50]
                )

                searched_stats = {
                    'max_risk': max_risk,
                    'human_count': human_count,
                    'bot_count': bot_count,
                    'suspicious_count': suspicious_count,
                    'triggered_rules': list(triggered_rule_names),
                }
            else:
                search_error = f"No traffic records found for IP address '{cleaned_ip}'. It has not contacted this server yet."
        except ValueError:
            search_error = f"'{search_query}' is not a valid IPv4 or IPv6 address. Please enter a valid IP address (e.g. 127.0.0.1)."

    context = {
        'client_ip': current_ip,
        'user_agent': telemetry.get('user_agent', 'Unknown'),
        'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'risk_score': risk_score,
        'classification': classification,
        'rules_triggered': rules_triggered,

        'total_requests': total_requests,
        'total_ips': total_ips,
        'detected_bots': detected_bots,
        'blocked_ips': blocked_ips,

        'search_query': search_query,
        'searched_ip': searched_ip_obj,
        'searched_requests': searched_requests,
        'searched_stats': searched_stats,
        'search_error': search_error,
    }
    return render(request, 'detector/index.html', context)


def dashboard(request):
    """
    Analytics & Security Operations Dashboard (Phase 9 & 10):
    - System metrics cards (Human %, Bot %, Total Threats).
    - Chart.js interactive Donut Chart: Bot vs Human traffic breakdown.
    - Chart.js Timeline Chart: Daily traffic trends (Human vs Bots).
    - Chart.js Top Rules Bar Chart: Most frequently triggered security rules.
    - High-risk IP addresses table.
    - Recent suspicious requests live feed.
    """
    total_requests = VisitorRequest.objects.count()
    human_count = VisitorRequest.objects.filter(classification='HUMAN').count()
    suspicious_count = VisitorRequest.objects.filter(classification='SUSPICIOUS').count()
    bot_count = VisitorRequest.objects.filter(classification='BOT').count()
    malicious_count = VisitorRequest.objects.filter(classification='MALICIOUS_BOT').count()

    total_bots = bot_count + malicious_count
    human_percent = round((human_count / total_requests * 100), 1) if total_requests > 0 else 0
    bot_percent = round((total_bots / total_requests * 100), 1) if total_requests > 0 else 0

    total_ips = IPAddress.objects.count()
    blocked_ips_count = IPAddress.objects.filter(status='BLOCKED').count()
    allowlisted_ips_count = IPAddress.objects.filter(status='ALLOWLISTED').count()

    # Chart 1: Traffic Breakdown Doughnut
    traffic_breakdown_data = {
        'labels': ['Human / Legitimate', 'Suspicious', 'Automated Bot', 'Malicious Bot'],
        'counts': [human_count, suspicious_count, bot_count, malicious_count],
        'colors': ['#10b981', '#f59e0b', '#ef4444', '#7f1d1d'],
    }

    # Chart 2: 7-Day Timeline Trends
    seven_days_ago = timezone.now().date() - timedelta(days=6)
    daily_records = (
        VisitorRequest.objects.filter(timestamp__date__gte=seven_days_ago)
        .annotate(day=TruncDate('timestamp'))
        .values('day')
        .annotate(
            total=Count('id'),
            humans=Count('id', filter=Q(classification='HUMAN')),
            bots=Count('id', filter=Q(classification__in=['BOT', 'MALICIOUS_BOT'])),
            suspicious=Count('id', filter=Q(classification='SUSPICIOUS')),
        )
        .order_by('day')
    )

    timeline_labels = []
    timeline_humans = []
    timeline_bots = []
    
    # Prepopulate last 7 days so chart is continuous
    day_map = {r['day'].strftime('%b %d'): r for r in daily_records}
    for i in range(7):
        d = seven_days_ago + timedelta(days=i)
        d_str = d.strftime('%b %d')
        timeline_labels.append(d_str)
        if d_str in day_map:
            timeline_humans.append(day_map[d_str]['humans'])
            timeline_bots.append(day_map[d_str]['bots'] + day_map[d_str]['suspicious'])
        else:
            timeline_humans.append(0)
            timeline_bots.append(0)

    timeline_data = {
        'labels': timeline_labels,
        'humans': timeline_humans,
        'bots': timeline_bots,
    }

    # Chart 3: Top Detection Rules Triggered
    top_rules_qs = (
        DetectionLog.objects.values('rule_name')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    top_rules_data = {
        'labels': [r['rule_name'] for r in top_rules_qs],
        'counts': [r['count'] for r in top_rules_qs],
    }

    # High-Risk IP Addresses
    high_risk_ips = (
        IPAddress.objects.filter(Q(is_bot=True) | Q(reputation_score__lt=60) | Q(status='BLOCKED'))
        .order_by('reputation_score', '-total_requests')[:10]
    )

    # Recent Suspicious Requests Feed (Risk >= 30)
    recent_suspicious = (
        VisitorRequest.objects.filter(risk_score__gte=30)
        .prefetch_related('detection_logs')
        .order_by('-timestamp')[:10]
    )

    context = {
        'total_requests': total_requests,
        'human_count': human_count,
        'total_bots': total_bots,
        'human_percent': human_percent,
        'bot_percent': bot_percent,
        'total_ips': total_ips,
        'blocked_ips_count': blocked_ips_count,
        'allowlisted_ips_count': allowlisted_ips_count,

        'traffic_breakdown_json': json.dumps(traffic_breakdown_data),
        'timeline_data_json': json.dumps(timeline_data),
        'top_rules_json': json.dumps(top_rules_data),

        'high_risk_ips': high_risk_ips,
        'recent_suspicious': recent_suspicious,
    }
    return render(request, 'detector/dashboard.html', context)


def investigate(request):
    """
    Request Investigation & Forensics Console:
    Allows filtering by IP, classification, risk score range, User-Agent search, and date.
    Includes pagination.
    """
    queryset = VisitorRequest.objects.all().prefetch_related('detection_logs').order_by('-timestamp')

    # Filter by IP Address
    ip_filter = request.GET.get('ip', '').strip()
    if ip_filter:
        queryset = queryset.filter(ip_address_str__icontains=ip_filter)

    # Filter by Classification
    class_filter = request.GET.get('classification', '').strip()
    if class_filter and class_filter != 'ALL':
        queryset = queryset.filter(classification=class_filter)

    # Filter by Risk Score Range
    risk_filter = request.GET.get('risk_level', '').strip()
    if risk_filter == 'LOW':
        queryset = queryset.filter(risk_score__lte=29)
    elif risk_filter == 'MEDIUM':
        queryset = queryset.filter(risk_score__gte=30, risk_score__lte=49)
    elif risk_filter == 'HIGH':
        queryset = queryset.filter(risk_score__gte=50, risk_score__lte=79)
    elif risk_filter == 'CRITICAL':
        queryset = queryset.filter(risk_score__gte=80)

    # Filter by User-Agent substring
    ua_filter = request.GET.get('user_agent', '').strip()
    if ua_filter:
        queryset = queryset.filter(user_agent__icontains=ua_filter)

    # Pagination: 20 records per page
    paginator = Paginator(queryset, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'total_matched': paginator.count,
        'ip_filter': ip_filter,
        'class_filter': class_filter,
        'risk_filter': risk_filter,
        'ua_filter': ua_filter,
    }
    return render(request, 'detector/investigate.html', context)


def ip_management(request):
    """
    IP Address Management Console (Phase 11):
    Allows searching, filtering (Monitored, Allowlisted, Blocked),
    manually adding new IPs to Allowlist or Blocklist, and toggling statuses.
    """
    # Handle manual addition of an IP to Allowlist or Blocklist
    if request.method == 'POST' and 'add_ip' in request.POST:
        new_ip = request.POST.get('ip_address', '').strip()
        new_status = request.POST.get('status', 'MONITORED')
        new_notes = request.POST.get('notes', '').strip()

        try:
            cleaned_ip = str(ipaddress.ip_address(new_ip))
            ip_obj, created = IPAddress.objects.get_or_create(
                ip_address=cleaned_ip,
                defaults={
                    'status': new_status,
                    'notes': new_notes or "Manually added via IP Management Console",
                    'reputation_score': 0 if new_status == 'BLOCKED' else 100,
                }
            )
            if not created:
                ip_obj.status = new_status
                if new_notes:
                    ip_obj.notes = new_notes
                ip_obj.save()
                messages.info(request, f"Updated existing IP record: {cleaned_ip} ({new_status}).")
            else:
                messages.success(request, f"Successfully registered IP: {cleaned_ip} as {new_status}.")
        except ValueError:
            messages.error(request, f"'{new_ip}' is not a valid IPv4 or IPv6 address.")

        return redirect('detector:ip_management')

    queryset = IPAddress.objects.all().order_by('-last_seen')

    # Tab Filter
    status_tab = request.GET.get('tab', 'ALL').upper()
    if status_tab in ('MONITORED', 'ALLOWLISTED', 'BLOCKED'):
        queryset = queryset.filter(status=status_tab)
    elif status_tab == 'BOTS':
        queryset = queryset.filter(is_bot=True)

    # Search filter
    search_query = request.GET.get('q', '').strip()
    if search_query:
        queryset = queryset.filter(Q(ip_address__icontains=search_query) | Q(notes__icontains=search_query))

    paginator = Paginator(queryset, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Global IP counts for tabs
    tab_counts = {
        'all': IPAddress.objects.count(),
        'monitored': IPAddress.objects.filter(status='MONITORED').count(),
        'allowlisted': IPAddress.objects.filter(status='ALLOWLISTED').count(),
        'blocked': IPAddress.objects.filter(status='BLOCKED').count(),
        'bots': IPAddress.objects.filter(is_bot=True).count(),
    }

    context = {
        'page_obj': page_obj,
        'status_tab': status_tab,
        'search_query': search_query,
        'tab_counts': tab_counts,
    }
    return render(request, 'detector/ip_management.html', context)


def toggle_ip_status(request, ip_address):
    """
    Toggles an IP address status between BLOCKED, MONITORED, or ALLOWLISTED.
    Redirects back to the referring page.
    """
    if request.method == 'POST':
        action = request.POST.get('action', 'toggle')
        ip_obj = IPAddress.objects.filter(ip_address=ip_address).first()
        if ip_obj:
            if action == 'allowlist':
                ip_obj.status = 'ALLOWLISTED'
                ip_obj.notes = "Allowlisted via Console"
                messages.success(request, f"IP Address {ip_address} is now ALLOWLISTED.")
            elif action == 'block' or (action == 'toggle' and ip_obj.status != 'BLOCKED'):
                ip_obj.status = 'BLOCKED'
                ip_obj.notes = "Manually blocked via Console"
                messages.warning(request, f"IP Address {ip_address} is now BLOCKED.")
            else:
                ip_obj.status = 'MONITORED'
                ip_obj.notes = "Set to monitored status"
                messages.success(request, f"IP Address {ip_address} is now set to MONITORED.")
            ip_obj.save()
        else:
            messages.error(request, f"IP Address {ip_address} not found.")

    next_url = request.META.get('HTTP_REFERER') or '/'
    return redirect(next_url)
