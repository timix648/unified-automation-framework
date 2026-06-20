"""
Tests for the DeviceFactory and vendor drivers (mock mode).
"""
import pytest
from app.services.device_manager import DeviceFactory
from app.drivers.cisco_driver import CiscoIOSDriver
from app.drivers.mikrotik_driver import MikroTikDriver
from app.drivers.unifi_driver import UniFiDriver
from tests.conftest import MOCK_CISCO, MOCK_MIKROTIK, MOCK_UNIFI


class TestDeviceFactory:
    def test_cisco_driver_selected(self):
        driver = DeviceFactory.get_driver(MOCK_CISCO)
        assert isinstance(driver, CiscoIOSDriver)

    def test_mikrotik_driver_selected(self):
        driver = DeviceFactory.get_driver(MOCK_MIKROTIK)
        assert isinstance(driver, MikroTikDriver)

    def test_unifi_driver_selected(self):
        driver = DeviceFactory.get_driver(MOCK_UNIFI)
        assert isinstance(driver, UniFiDriver)

    def test_unsupported_platform_raises(self):
        with pytest.raises(ValueError, match="Unsupported Platform"):
            DeviceFactory.get_driver({"ip": "1.2.3.4", "platform": "juniper"})

    def test_credential_override(self):
        device = {**MOCK_CISCO, "credentials": {"username": "custom_user", "password": "custom_pass"}}
        driver = DeviceFactory.get_driver(device)
        assert driver.device_config["username"] == "custom_user"
        assert driver.device_config["password"] == "custom_pass"


# ── Driver mock-mode smoke tests ──────────────────────────────────────────
# NOTE: In mock mode, connect() returns True but does NOT set self.connected.
# The drivers return {"success": True, ...} — not {"status": "success"}.

class TestCiscoDriverMock:
    @pytest.fixture
    def driver(self):
        d = DeviceFactory.get_driver(MOCK_CISCO)
        assert d.connect() is True
        yield d
        d.disconnect()

    def test_connect_returns_true(self, driver):
        # mock connect() returns True (doesn't flip self.connected)
        assert driver.mock_mode is True

    def test_get_interfaces(self, driver):
        ifaces = driver.get_interfaces()
        assert isinstance(ifaces, list)
        assert len(ifaces) > 0

    def test_disable_port(self, driver):
        result = driver.disable_port("GigabitEthernet0/1")
        assert result["success"] is True
        assert result["action"] == "disabled"

    def test_enable_port(self, driver):
        result = driver.enable_port("GigabitEthernet0/1")
        assert result["success"] is True
        assert result["action"] == "enabled"

    def test_create_vlan(self, driver):
        result = driver.create_vlan(100, "test-vlan")
        assert result["success"] is True
        assert result["vlan_id"] == 100

    def test_get_mac_address_table(self, driver):
        table = driver.get_mac_address_table()
        assert isinstance(table, list)


class TestMikroTikDriverMock:
    @pytest.fixture
    def driver(self):
        d = DeviceFactory.get_driver(MOCK_MIKROTIK)
        assert d.connect() is True
        yield d
        d.disconnect()

    def test_is_mock(self, driver):
        assert driver.mock_mode is True

    def test_get_interfaces(self, driver):
        ifaces = driver.get_interfaces()
        assert isinstance(ifaces, list)

    def test_disable_enable_port(self, driver):
        res = driver.disable_port("ether1")
        assert res["success"] is True
        res = driver.enable_port("ether1")
        assert res["success"] is True

    def test_add_firewall_rule(self, driver):
        result = driver.add_firewall_rule(chain="forward", action="drop")
        assert result["success"] is True
        assert result["rule_created"] is True


class TestUniFiDriverMock:
    @pytest.fixture
    def driver(self):
        d = DeviceFactory.get_driver(MOCK_UNIFI)
        assert d.connect() is True
        yield d
        d.disconnect()

    def test_is_mock(self, driver):
        assert driver.mock_mode is True

    def test_get_interfaces(self, driver):
        ifaces = driver.get_interfaces()
        assert isinstance(ifaces, list)

    def test_disable_enable_port(self, driver):
        # UniFi expects numeric port IDs
        res = driver.disable_port("1")
        assert res["success"] is True
        res = driver.enable_port("1")
        assert res["success"] is True
