"""
Tests for the NetBox inventory client (mock mode).
"""
import pytest
import json
from app.inventory.netbox_client import NetboxInventory, DEFAULT_MOCK_DEVICES, DEFAULT_TRUSTED_MACS


class TestNetboxInventoryMock:
    def test_get_all_devices_returns_defaults(self, tmp_path, monkeypatch):
        # Ensure we're in mock mode (settings.MOCK_MODE is True by default)
        nb = NetboxInventory()
        devices = nb.get_all_devices()
        assert len(devices) >= 3
        names = [d["name"] for d in devices]
        assert "cisco-switch-01" in names
        assert "mikrotik-router-01" in names
        assert "unifi-ap-01" in names

    def test_get_trusted_macs_mock(self):
        nb = NetboxInventory()
        macs = nb.get_trusted_macs()
        assert isinstance(macs, list)
        assert len(macs) > 0
        # Should be a copy, not the same object
        assert macs is not DEFAULT_TRUSTED_MACS

    def test_device_fields(self):
        nb = NetboxInventory()
        devices = nb.get_all_devices()
        for dev in devices:
            assert "name" in dev
            assert "platform" in dev
            assert "device_role" in dev
            assert "ip" in dev or "primary_ip" in dev
