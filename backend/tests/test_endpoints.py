"""
Tests for API endpoints — verifies routing, auth gating, and basic responses.
All tests run against MOCK_MODE so no real devices are needed.
"""
import pytest


class TestHealthEndpoints:
    def test_root(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "online"

    def test_api_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_metrics_endpoint(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        # Prometheus text format starts with # HELP or device_
        assert "device_" in resp.text or "HELP" in resp.text or resp.text == ""


# ── Device endpoints ───────────────────────────────────────────────────────

class TestDeviceEndpoints:
    def test_get_devices_requires_auth(self, client):
        resp = client.get("/api/devices")
        assert resp.status_code == 401

    def test_get_devices(self, client, auth_headers):
        resp = client.get("/api/devices", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert body["count"] >= 1

    def test_get_device_detail(self, client, auth_headers):
        resp = client.get("/api/devices/cisco-switch-01", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["device"]["platform"] == "cisco_ios"

    def test_get_device_not_found(self, client, auth_headers):
        resp = client.get("/api/devices/nonexistent", headers=auth_headers)
        assert resp.status_code == 404


# ── Port control ───────────────────────────────────────────────────────────

class TestPortControl:
    def test_port_control_requires_operator(self, client, viewer_headers):
        payload = {"device_name": "cisco-switch-01", "port_id": "Gi0/1", "action": "shutdown"}
        resp = client.post("/api/devices/port-control", json=payload, headers=viewer_headers)
        assert resp.status_code == 403

    def test_port_control_shutdown(self, client, operator_headers):
        payload = {"device_name": "cisco-switch-01", "port_id": "Gi0/1", "action": "shutdown"}
        resp = client.post("/api/devices/port-control", json=payload, headers=operator_headers)
        assert resp.status_code == 200
        assert resp.json()["action"] == "shutdown"

    def test_port_control_invalid_action(self, client, operator_headers):
        payload = {"device_name": "cisco-switch-01", "port_id": "Gi0/1", "action": "reboot"}
        resp = client.post("/api/devices/port-control", json=payload, headers=operator_headers)
        assert resp.status_code == 400


# ── Security endpoints ─────────────────────────────────────────────────────

class TestSecurityEndpoints:
    def test_get_threats(self, client, auth_headers):
        resp = client.get("/api/security/threats", headers=auth_headers)
        assert resp.status_code == 200
        assert "threats" in resp.json()

    def test_get_security_stats(self, client, auth_headers):
        resp = client.get("/api/security/stats", headers=auth_headers)
        assert resp.status_code == 200
        assert "statistics" in resp.json()

    def test_security_scan_requires_operator(self, client, viewer_headers):
        resp = client.post("/api/security/scan", headers=viewer_headers)
        assert resp.status_code == 403

    def test_security_scan_accepted(self, client, operator_headers):
        resp = client.post("/api/security/scan", headers=operator_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"


# ── Scheduler endpoints ───────────────────────────────────────────────────

class TestSchedulerEndpoints:
    def test_scheduler_status(self, client, auth_headers):
        resp = client.get("/api/scheduler/status", headers=auth_headers)
        assert resp.status_code == 200
        assert "jobs" in resp.json()

    def test_scheduler_control_requires_admin(self, client, operator_headers):
        payload = {"action": "trigger_security"}
        resp = client.post("/api/scheduler/control", json=payload, headers=operator_headers)
        assert resp.status_code == 403

    def test_scheduler_trigger(self, client, auth_headers):
        payload = {"action": "trigger_security"}
        resp = client.post("/api/scheduler/control", json=payload, headers=auth_headers)
        assert resp.status_code == 200


# ── Wake-on-LAN ───────────────────────────────────────────────────────────

class TestWoLEndpoints:
    def test_wol_requires_operator(self, client, viewer_headers):
        payload = {"mac_address": "AA:BB:CC:DD:EE:FF"}
        resp = client.post("/api/power/wake", json=payload, headers=viewer_headers)
        assert resp.status_code == 403

    def test_wol_success(self, client, operator_headers):
        payload = {"mac_address": "AA:BB:CC:DD:EE:FF"}
        resp = client.post("/api/power/wake", json=payload, headers=operator_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"


# ── Audit & config endpoints ──────────────────────────────────────────────

class TestAdminEndpoints:
    def test_audit_logs_requires_admin(self, client, operator_headers):
        resp = client.get("/api/audit/logs", headers=operator_headers)
        assert resp.status_code == 403

    def test_audit_logs_as_admin(self, client, auth_headers):
        resp = client.get("/api/audit/logs", headers=auth_headers)
        assert resp.status_code == 200
        assert "logs" in resp.json()

    def test_system_config(self, client, auth_headers):
        resp = client.get("/api/config/system", headers=auth_headers)
        assert resp.status_code == 200
        assert "config" in resp.json()
