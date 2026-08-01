"""
Tests for the scheduler module — time-based ACL enforcement and rogue scanning.
"""
import pytest
from unittest.mock import patch, MagicMock
import datetime

# Pre-import the module so @patch can resolve it
import app.services.scheduler as scheduler_mod


class TestSchedulerTimePolicyOffHours:
    """Simulate an off-hours run (e.g. 22:00)."""

    @patch.object(scheduler_mod, "send_magic_packet")
    @patch.object(scheduler_mod, "DeviceFactory")
    @patch.object(scheduler_mod, "NetboxInventory")
    @patch.object(scheduler_mod, "datetime")
    def test_cisco_acl_applied_off_hours(self, mock_dt, mock_nb_cls, mock_factory, mock_wol):
        mock_dt.datetime.now.return_value = datetime.datetime(2025, 1, 15, 22, 0)

        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = [
            {"name": "cisco-sw", "platform": "cisco_ios", "device_role": "switch"},
        ]
        mock_nb_cls.return_value = mock_nb

        mock_driver = MagicMock()
        mock_factory.get_driver.return_value = mock_driver

        scheduler_mod.auto_enforce_time_policy()

        mock_driver.connect.assert_called_once()
        mock_driver._execute_config_commands.assert_called_once()
        cmds = mock_driver._execute_config_commands.call_args[0][0]
        assert any("UAF-OFF-HOURS" in c for c in cmds)
        mock_driver.disconnect.assert_called_once()

    @patch.object(scheduler_mod, "send_magic_packet")
    @patch.object(scheduler_mod, "DeviceFactory")
    @patch.object(scheduler_mod, "NetboxInventory")
    @patch.object(scheduler_mod, "datetime")
    def test_mikrotik_firewall_rule_added_off_hours(self, mock_dt, mock_nb_cls, mock_factory, mock_wol):
        mock_dt.datetime.now.return_value = datetime.datetime(2025, 1, 15, 22, 0)

        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = [
            {"name": "mt-router", "platform": "mikrotik_routeros", "device_role": "edge-router"},
        ]
        mock_nb_cls.return_value = mock_nb

        mock_driver = MagicMock()
        mock_factory.get_driver.return_value = mock_driver

        scheduler_mod.auto_enforce_time_policy()

        mock_driver.add_firewall_rule.assert_called_once()
        kwargs = mock_driver.add_firewall_rule.call_args[1]
        assert kwargs["action"] == "drop"
        # Edge router should also have WAN disabled
        mock_driver.shutdown_port.assert_called_once_with("ether1")


class TestSchedulerTimePolicyWorkHours:
    """Simulate a work-hours run (e.g. 10:00)."""

    @patch.object(scheduler_mod, "send_magic_packet")
    @patch.object(scheduler_mod, "DeviceFactory")
    @patch.object(scheduler_mod, "NetboxInventory")
    @patch.object(scheduler_mod, "datetime")
    def test_cisco_acl_removed_work_hours(self, mock_dt, mock_nb_cls, mock_factory, mock_wol):
        mock_dt.datetime.now.return_value = datetime.datetime(2025, 1, 15, 10, 0)

        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = [
            {"name": "cisco-sw", "platform": "cisco_ios", "device_role": "switch"},
        ]
        mock_nb_cls.return_value = mock_nb

        mock_driver = MagicMock()
        mock_factory.get_driver.return_value = mock_driver

        scheduler_mod.auto_enforce_time_policy()

        cmds = mock_driver._execute_config_commands.call_args[0][0]
        assert any("no ip access-list" in c for c in cmds)


class TestSchedulerWoL:
    """WoL should fire at 8 AM for desktop/workstation roles."""

    @patch.object(scheduler_mod, "send_magic_packet")
    @patch.object(scheduler_mod, "DeviceFactory")
    @patch.object(scheduler_mod, "NetboxInventory")
    @patch.object(scheduler_mod, "datetime")
    def test_wol_sent_at_8am(self, mock_dt, mock_nb_cls, mock_factory, mock_wol):
        mock_dt.datetime.now.return_value = datetime.datetime(2025, 1, 15, 8, 30)

        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = [
            {"name": "desktop-01", "platform": "generic", "device_role": "desktop", "mac": "AA:BB:CC:DD:EE:FF"},
        ]
        mock_nb_cls.return_value = mock_nb

        scheduler_mod.auto_enforce_time_policy()

        mock_wol.assert_called_once_with("AA:BB:CC:DD:EE:FF")

    @patch.object(scheduler_mod, "send_magic_packet")
    @patch.object(scheduler_mod, "DeviceFactory")
    @patch.object(scheduler_mod, "NetboxInventory")
    @patch.object(scheduler_mod, "datetime")
    def test_wol_not_sent_at_noon(self, mock_dt, mock_nb_cls, mock_factory, mock_wol):
        mock_dt.datetime.now.return_value = datetime.datetime(2025, 1, 15, 12, 0)

        mock_nb = MagicMock()
        mock_nb.get_all_devices.return_value = [
            {"name": "desktop-01", "platform": "generic", "device_role": "desktop", "mac": "AA:BB:CC:DD:EE:FF"},
        ]
        mock_nb_cls.return_value = mock_nb

        scheduler_mod.auto_enforce_time_policy()

        mock_wol.assert_not_called()


class TestAutoScanForRogues:
    @patch.object(scheduler_mod, "KillSwitchService")
    @patch.object(scheduler_mod, "NornirManager")
    @patch.object(scheduler_mod, "NetboxInventory")
    def test_no_rogues_found(self, mock_nb_cls, mock_nornir_cls, mock_ks_cls):
        mock_nb = MagicMock()
        mock_nb.get_trusted_macs.return_value = ["AA:BB:CC:DD:EE:FF"]
        mock_nb_cls.return_value = mock_nb

        mock_mgr = MagicMock()
        mock_mgr.scan_all_for_rogues.return_value = {
            "total_rogues_found": 0,
            "details": {"results": {}},
        }
        mock_nornir_cls.return_value = mock_mgr

        scheduler_mod.auto_scan_for_rogues()

        # Kill switch should NOT be invoked when network is clean
        mock_ks_cls.assert_not_called()

    # A rogue detection does NOT unconditionally shut a port. Enforcement
    # requires BOTH that enforcement is armed AND that the unrecognized device
    # is infrastructure (a rogue switch/AP). End-user devices and devices whose
    # vendor cannot be identified are recorded for review but never isolated,
    # so a real user is not knocked offline on a guess. The three tests below
    # pin each arm of that decision.

    def _scan_returning(self, mac, interface="Gi0/5"):
        return {
            "total_rogues_found": 1,
            "details": {
                "results": {
                    "cisco-switch-01": {
                        "success": True,
                        "result": {"rogue_devices": [{"mac": mac, "interface": interface}]},
                    }
                }
            },
        }

    @patch.object(scheduler_mod, "enforcement_state")
    @patch.object(scheduler_mod, "KillSwitchService")
    @patch.object(scheduler_mod, "NornirManager")
    @patch.object(scheduler_mod, "NetboxInventory")
    def test_learning_mode_records_but_never_shuts_port(
        self, mock_nb_cls, mock_nornir_cls, mock_ks_cls, mock_enforcement
    ):
        """Learning mode must report the device and shut nothing."""
        mock_enforcement.is_armed.return_value = False
        mock_nb_cls.return_value.get_trusted_macs.return_value = []
        # Ubiquiti OUI -> classified as infrastructure, so the ONLY thing
        # preventing isolation here is that enforcement is not armed.
        mock_nornir_cls.return_value.scan_all_for_rogues.return_value = \
            self._scan_returning("F0:9F:C2:11:22:33")
        mock_ks = mock_ks_cls.return_value

        scheduler_mod.auto_scan_for_rogues()

        mock_ks.execute_response.assert_not_called()
        mock_ks.record_detection.assert_called_once()

    @patch.object(scheduler_mod, "enforcement_state")
    @patch.object(scheduler_mod, "KillSwitchService")
    @patch.object(scheduler_mod, "NornirManager")
    @patch.object(scheduler_mod, "NetboxInventory")
    def test_armed_isolates_rogue_infrastructure(
        self, mock_nb_cls, mock_nornir_cls, mock_ks_cls, mock_enforcement
    ):
        """Armed + infrastructure is the one combination that shuts a port."""
        mock_enforcement.is_armed.return_value = True
        mock_nb_cls.return_value.get_trusted_macs.return_value = []
        mock_nornir_cls.return_value.scan_all_for_rogues.return_value = \
            self._scan_returning("F0:9F:C2:11:22:33")
        mock_ks = mock_ks_cls.return_value

        scheduler_mod.auto_scan_for_rogues()

        mock_ks.execute_response.assert_called_once()
        kwargs = mock_ks.execute_response.call_args.kwargs
        assert kwargs["device_name"] == "cisco-switch-01"
        assert kwargs["port_id"] == "Gi0/5"
        assert kwargs["threat_type"] == "rogue_infrastructure_scheduled_scan"
        assert kwargs["threat_details"]["mac_address"] == "F0:9F:C2:11:22:33"
        assert kwargs["threat_details"]["device_type"] == "infrastructure"

    @patch.object(scheduler_mod, "enforcement_state")
    @patch.object(scheduler_mod, "KillSwitchService")
    @patch.object(scheduler_mod, "NornirManager")
    @patch.object(scheduler_mod, "NetboxInventory")
    def test_armed_does_not_isolate_unclassified_endpoint(
        self, mock_nb_cls, mock_nornir_cls, mock_ks_cls, mock_enforcement
    ):
        """Armed, but an unidentifiable device is recorded, not isolated."""
        mock_enforcement.is_armed.return_value = True
        mock_nb_cls.return_value.get_trusted_macs.return_value = []
        # Unassigned OUI -> classified "unknown", so it must NOT be isolated.
        mock_nornir_cls.return_value.scan_all_for_rogues.return_value = \
            self._scan_returning("DE:AD:BE:EF:00:01")
        mock_ks = mock_ks_cls.return_value

        scheduler_mod.auto_scan_for_rogues()

        mock_ks.execute_response.assert_not_called()
        mock_ks.record_detection.assert_called_once()
