"""
URL routing table for the 'detector' application.
Maps all public views: Live Scanner, Analytics Dashboard,
Request Investigation Console, and IP Address Management.
"""
from django.urls import path
from . import views

app_name = 'detector'

urlpatterns = [
    # 1. Landing View (Live Telemetry & IP Forensics Search)
    path('', views.index, name='index'),

    # 2. Security Analytics Dashboard (Charts & Metrics)
    path('dashboard/', views.dashboard, name='dashboard'),

    # 3. Request Investigation & Forensics Console
    path('investigate/', views.investigate, name='investigate'),

    # 4. IP Address Management Console
    path('ips/', views.ip_management, name='ip_management'),

    # 5. Front-End IP Block/Allowlist Toggle Action
    path('toggle-ip/<str:ip_address>/', views.toggle_ip_status, name='toggle_ip_status'),
]
