"""
Tests for the Kill-Switch service.
"""
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from app.services.kill_switch import KillSwitchService
from tests.conftest import MOCK_CISCO, ALL_MOCK_DEVICES


class TestKillSwitchService:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Use a temporary directory for threat logs during tests."""
        self.log_file = tmp_path / "security_threats.json"
        self.log_file.write_text("[]")
        self.ks = KillSwitchService()
        self.ks.threat_log_file = self.log_file

    def test_initial_threats_empty(self):
        assert self.ks.get_active_threats() == []

    def test_threat_statistics_empty(self):
        stats = self.ks.get_threat_statistics()
        assert stats["total_incidents"] == 0
        assert stats["successful_responses"] == 0

    @patch("app.services.kill_switch.NetboxInventory")
    @patch("app.services.kill_switch.DeviceFactory")
    def test_handle_security_alert_success(self, mock_factory, mock_nb_cls):
        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = ALL_MOCK_DEVICES
        mock_nb_cls.return_value = mock_nb

        mock_driver = MagicMock()
        mock_driver.shutdown_port.return_value = {"status": "ok"}
        mock_factory.get_driver.return_value = mock_driver

        result = self.ks.handle_security_alert(
            device_name="cisco-switch-01",
            port_id="Gi0/1",
            threat_type="rogue_device",
        )

        assert result["success"] is True
        assert result["device"] == "cisco-switch-01"
        mock_driver.connect.assert_called_once()
        mock_driver.shutdown_port.assert_called_once_with("Gi0/1")
        mock_driver.disconnect.assert_called_once()

    @patch("app.services.kill_switch.NetboxInventory")
    def test_handle_alert_device_not_found(self, mock_nb_cls):
        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = ALL_MOCK_DEVICES
        mock_nb_cls.return_value = mock_nb

        result = self.ks.handle_security_alert(
            device_name="nonexistent-switch",
            port_id="Gi0/1",
            threat_type="rogue_device",
        )
        assert result["success"] is False

    def test_log_and_retrieve_incidents(self):
        self.ks._log_incident(
            device_name="sw1",
            device_ip="10.0.0.1",
            port_id="Gi0/1",
            threat_type="rogue_device",
            threat_details={"mac": "AA:BB:CC:DD:EE:FF"},
            action_result={"status": "ok"},
            success=True,
        )
        threats = self.ks.get_active_threats()
        assert len(threats) == 1
        assert threats[0]["threat_type"] == "rogue_device"

    def test_threat_statistics_counts(self):
        for i in range(3):
            self.ks._log_incident(
                device_name=f"sw{i}",
                device_ip="10.0.0.1",
                port_id="Gi0/1",
                threat_type="rogue_device" if i < 2 else "mac_spoofing",
                threat_details=None,
                action_result={},
                success=(i != 2),
            )
        stats = self.ks.get_threat_statistics()
        assert stats["total_incidents"] == 3
        assert stats["successful_responses"] == 2
        assert stats["failed_responses"] == 1
        assert stats["threats_by_type"]["rogue_device"] == 2

    @patch("app.services.kill_switch.NetboxInventory")
    @patch("app.services.kill_switch.DeviceFactory")
    def test_restore_port(self, mock_factory, mock_nb_cls):
        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = ALL_MOCK_DEVICES
        mock_nb_cls.return_value = mock_nb

        mock_driver = MagicMock()
        mock_driver.enable_port.return_value = {"status": "ok"}
        mock_factory.get_driver.return_value = mock_driver

        result = self.ks.restore_port("cisco-switch-01", "Gi0/1", reason="cleared")
        assert result["success"] is True
        mock_driver.enable_port.assert_called_once_with("Gi0/1")

    def test_clear_threat_log(self):
        self.ks._log_incident("sw1", "10.0.0.1", "Gi0/1", "test", None, {}, True)
        assert len(self.ks.get_active_threats()) == 1
        self.ks.clear_threat_log()
        assert len(self.ks.get_active_threats()) == 0
