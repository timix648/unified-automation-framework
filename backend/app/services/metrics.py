"""
UAF Prometheus Metrics Exporter
=================================
Exposes network automation metrics for Prometheus/Grafana monitoring.

Metrics exposed:
- Device reachability
- Interface status
- Security events
- Automation task performance
"""

import logging
from prometheus_client import Counter, Gauge, Histogram, Info, generate_latest, REGISTRY
from prometheus_client.core import CollectorRegistry
from typing import Dict
import time

logger = logging.getLogger(__name__)


class UAFMetricsExporter:
    """
    Prometheus metrics exporter for UAF.
    """
    
    def __init__(self):
        """Initialize metrics."""
        
        # Device Metrics
        self.device_up = Gauge(
            'uaf_device_up',
            'Device reachability (1=up, 0=down)',
            ['device', 'platform']
        )
        
        self.device_response_time = Gauge(
            'uaf_device_response_time_seconds',
            'Device response time',
            ['device']
        )
        
        # Interface Metrics
        self.interface_status = Gauge(
            'uaf_interface_status',
            'Interface status (1=up, 0=down)',
            ['device', 'interface']
        )
        
        self.interface_errors = Counter(
            'uaf_interface_errors_total',
            'Interface errors',
            ['device', 'interface', 'direction']
        )
        
        # Security Metrics
        self.security_events = Counter(
            'uaf_security_events_total',
            'Security events detected',
            ['event_type', 'device']
        )
        
        self.ports_shutdown = Counter(
            'uaf_ports_shutdown_total',
            'Ports automatically shutdown',
            ['device', 'reason']
        )
        
        self.active_threats = Gauge(
            'uaf_active_threats',
            'Current active threats',
            ['threat_type']
        )
        
        # Automation Metrics
        self.automation_tasks = Counter(
            'uaf_automation_tasks_total',
            'Automation tasks executed',
            ['task_type', 'status']
        )
        
        self.task_duration = Histogram(
            'uaf_task_duration_seconds',
            'Task execution duration',
            ['task_type']
        )
        
        self.config_changes = Counter(
            'uaf_config_changes_total',
            'Configuration changes deployed',
            ['device', 'change_type']
        )
        
        # API Metrics
        self.api_requests = Counter(
            'uaf_api_requests_total',
            'API requests',
            ['endpoint', 'method', 'status']
        )
        
        self.api_latency = Histogram(
            'uaf_api_latency_seconds',
            'API request latency',
            ['endpoint']
        )
        
        logger.info("✅ Prometheus metrics initialized")
    
    def update_device_status(self, device: str, platform: str, is_up: bool, response_time: float = None):
        """Update device reachability metrics."""
        self.device_up.labels(device=device, platform=platform).set(1 if is_up else 0)
        if response_time:
            self.device_response_time.labels(device=device).set(response_time)
    
    def update_interface_status(self, device: str, interface: str, is_up: bool):
        """Update interface status."""
        self.interface_status.labels(device=device, interface=interface).set(1 if is_up else 0)
    
    def record_security_event(self, event_type: str, device: str):
        """Record a security event."""
        self.security_events.labels(event_type=event_type, device=device).inc()
    
    def record_port_shutdown(self, device: str, reason: str):
        """Record an automated port shutdown."""
        self.ports_shutdown.labels(device=device, reason=reason).inc()
    
    def record_automation_task(self, task_type: str, duration: float, success: bool):
        """Record automation task execution."""
        status = "success" if success else "failed"
        self.automation_tasks.labels(task_type=task_type, status=status).inc()
        self.task_duration.labels(task_type=task_type).observe(duration)
    
    def record_config_change(self, device: str, change_type: str):
        """Record a configuration change."""
        self.config_changes.labels(device=device, change_type=change_type).inc()
    
    def record_api_request(self, endpoint: str, method: str, status: int, latency: float):
        """Record an API request."""
        self.api_requests.labels(endpoint=endpoint, method=method, status=str(status)).inc()
        self.api_latency.labels(endpoint=endpoint).observe(latency)
    
    def get_metrics(self) -> bytes:
        """Get metrics in Prometheus format."""
        return generate_latest(REGISTRY)


# Global metrics instance
metrics_exporter = UAFMetricsExporter()
