"""
Integration Tests (Report 4.8)
==============================
These exercise interactions ACROSS subsystems rather than one unit at a time:

  * provisioning a network segment across all three vendors in a single call,
  * triggering the Kill-Switch while the scheduler is active,
  * a bulk Wake-on-LAN across the inventory,
  * the real-time WebSocket event channel (4.7) carrying a security alert.

They run in mock mode (forced by conftest), so they validate the orchestration
and wiring end-to-end without physical hardware.
"""
import pytest

from .conftest import MOCK_CISCO, MOCK_MIKROTIK, MOCK_UNIFI


# ── 4.8: one intent → every vendor configured in a single call ──────────────

class TestCrossVendorProvisioning:
    def test_provision_touches_all_three_vendors(self, client, auth_headers):
        payload = {
            "network_name": "Integration-Lab",
            "vlan_id": 42,
            "subnet": "192.168.42.0/24",
            "gateway": "192.168.42.1",
            "enable_dhcp": True,
            "enable_port_security": True,
            "switch_ports": ["GigabitEthernet0/1", "GigabitEthernet0/2"],
            "wifi_ssid": "Integration-WiFi",
            "wifi_password": "test12345",
        }
        resp = client.post("/api/provision/network", json=payload, headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        # A single high-level intent produced multiple concrete steps.
        assert body["total_steps"] > 0
        assert body["successful_steps"] > 0

        steps = body["details"]["steps_completed"]
        step_names = {s["step"] for s in steps}
        # Vendor-agnostic abstraction: Cisco VLAN, MikroTik DHCP, UniFi SSID.
        assert "create_vlan" in step_names
        assert "create_dhcp_pool" in step_names
        assert "create_wifi_ssid" in step_names

    def test_provision_requires_admin(self, client, operator_headers):
        payload = {
            "network_name": "Nope", "vlan_id": 50, "subnet": "10.0.50.0/24",
            "gateway": "10.0.50.1",
        }
        resp = client.post("/api/provision/network", json=payload,
                           headers=operator_headers)
        assert resp.status_code == 403


# ── 4.8: kill-switch firing while the scheduler is running ──────────────────

class TestKillSwitchWithSchedulerActive:
    def test_scheduler_is_running(self, client, auth_headers):
        resp = client.get("/api/scheduler/status", headers=auth_headers)
        assert resp.status_code == 200
        # The TestClient context manager triggers app startup -> scheduler on.
        assert resp.json()["running"] is True

    def test_alert_while_scheduler_active(self, client, operator_headers, auth_headers):
        # Scheduler is up...
        assert client.get("/api/scheduler/status",
                          headers=auth_headers).json()["running"] is True
        # ...and a security alert is accepted concurrently.
        alert = {"device_name": "cisco-switch-01", "port_id": "Gi0/3",
                 "threat_type": "rogue_device"}
        resp = client.post("/api/security/alert", json=alert, headers=operator_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"
        # Threat list still queryable after the alert.
        threats = client.get("/api/security/threats", headers=auth_headers)
        assert threats.status_code == 200
        assert "threats" in threats.json()


# ── 4.8: bulk operation across the inventory ────────────────────────────────

class TestBulkOperations:
    def test_wake_batch_across_inventory(self, client, operator_headers):
        macs = [MOCK_CISCO["mac"], MOCK_MIKROTIK["mac"], MOCK_UNIFI["mac"]]
        resp = client.post("/api/power/wake-batch",
                           json={"macs": macs, "broadcast_ip": "255.255.255.255"},
                           headers=operator_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 3
        assert body["sent"] == 3


# ── 4.7: real-time WebSocket event channel ──────────────────────────────────

class TestRealTimeEventChannel:
    def _token(self, headers):
        return headers["Authorization"].split(" ", 1)[1]

    def test_ws_rejects_without_token(self, client):
        with pytest.raises(Exception):
            with client.websocket_connect("/api/ws/events"):
                pass

    def test_ws_streams_published_event(self, client, auth_headers):
        from app.services.event_bus import event_bus

        token = self._token(auth_headers)
        with client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "connected"

            # Publish a threat and confirm it arrives over the socket.
            event_bus.publish("threat", device="cisco-switch-01",
                              port="Gi0/9", threat_type="rogue_device")
            seen = None
            for _ in range(8):  # skip any device_status snapshots
                ev = ws.receive_json()
                if ev["type"] == "threat":
                    seen = ev
                    break
            assert seen is not None
            assert seen["device"] == "cisco-switch-01"
            assert seen["threat_type"] == "rogue_device"

# ── Account security: change own password, role preserved ───────────────────

class TestChangePassword:
    """A user can change their own password; role + permissions are preserved,
    and the new password takes effect (old one stops working)."""

    def _make_user(self, client, auth_headers, username, password, role):
        # Admin creates a throwaway user so we never mutate the seeded admin.
        client.post("/api/auth/users",
                    json={"username": username, "password": password, "role": role},
                    headers=auth_headers)

    def _login(self, client, username, password):
        return client.post("/api/auth/login",
                           json={"username": username, "password": password})

    def test_change_password_preserves_role(self, client, auth_headers):
        self._make_user(client, auth_headers, "pwuser", "initpass123", "operator")
        login = self._login(client, "pwuser", "initpass123")
        assert login.status_code == 200
        token = login.json()["access_token"]

        resp = client.post("/api/auth/change-password",
                           json={"old_password": "initpass123",
                                 "new_password": "newpass456"},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        # Role is echoed back unchanged — admin stays admin, operator stays operator.
        assert resp.json()["role"] == "operator"

        # New password works, old one no longer does.
        assert self._login(client, "pwuser", "newpass456").status_code == 200
        assert self._login(client, "pwuser", "initpass123").status_code == 401

    def test_change_password_rejects_wrong_current(self, client, auth_headers):
        self._make_user(client, auth_headers, "pwuser2", "rightpass123", "viewer")
        token = self._login(client, "pwuser2", "rightpass123").json()["access_token"]
        resp = client.post("/api/auth/change-password",
                           json={"old_password": "WRONG", "new_password": "whatever123"},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400
