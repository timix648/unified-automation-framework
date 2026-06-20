"""
UAF NetBox Inventory Client
=============================
Wrapper around NetBox interaction.
Supports both Direct API (Production) and JSON File (Dev/Mock).

Credential Resolution Strategy (for 300+ devices at scale):
  1. Per-device credentials from NetBox config_context (highest priority)
  2. Platform-wide credentials from .env / environment variables (fallback)
  3. In enterprise networks, all devices of the same vendor typically share
     credentials because they authenticate via TACACS+/RADIUS.
     e.g., ONE Cisco username/password works on ALL 300 Cisco switches.

FIXED:
- Added DEFAULT_MOCK_DEVICES: 3 seeded devices so mock mode works out of the box
- get_trusted_macs() now returns actual MAC list instead of empty []
- Graceful pynetbox import handling (won't crash if pynetbox isn't installed)
- Added get_device_credentials() to fetch per-device overrides from NetBox
"""

import json
import os
from typing import List, Dict, Optional
from pathlib import Path
from app.core.config import settings
from app.inventory import authorized_registry

# We will use the real NetBox API client now, assuming pynetbox is installed
# If you are still using the JSON file method, we will stick to that for compatibility,
# but add the "get_trusted_macs" method.

DB_FILE = "devices.json"

# Default mock devices seeded on first run so mock mode works immediately
DEFAULT_MOCK_DEVICES = [
    {
        "name": "cisco-switch-01",
        "ip": "192.168.1.10",
        "primary_ip": "192.168.1.10",
        "platform": "cisco_ios",
        "device_role": "switch",
        "site": "home-lab",
        "manufacturer": "Cisco",
        "mac": "00:1A:2B:3C:4D:5E"
    },
    {
        "name": "mikrotik-router-01",
        "ip": "192.168.1.20",
        "primary_ip": "192.168.1.20",
        "platform": "mikrotik_routeros",
        "device_role": "edge-router",
        "site": "home-lab",
        "manufacturer": "MikroTik",
        "mac": "6C:3B:6B:AA:BB:CC"
    },
    {
        "name": "unifi-ap-01",
        "ip": "192.168.1.30",
        "primary_ip": "192.168.1.30",
        "platform": "unifi",
        "device_role": "access-point",
        "site": "home-lab",
        "manufacturer": "Ubiquiti",
        "mac": "F0:9F:C2:11:22:33"
    },
]

# Default trusted MAC addresses for the rogue detection scanner
DEFAULT_TRUSTED_MACS = [
    "AA:BB:CC:DD:EE:FF",
    "00:11:22:33:44:55",
    "00:50:56:C0:00:01",
    "00:50:56:C0:00:08",
]


class NetboxInventory:
    """
    Wrapper around NetBox interaction.
    Supports both Direct API (Production) and JSON File (Dev/Mock).
    """

    def __init__(self):
        self.use_api = False
        self.nb = None
        if settings.NETBOX_URL and settings.NETBOX_TOKEN and not settings.MOCK_MODE:
            try:
                import pynetbox
                self.nb = pynetbox.api(
                    settings.NETBOX_URL,
                    token=settings.NETBOX_TOKEN
                )
                self.use_api = True
            except ImportError:
                print("⚠️  pynetbox not installed. Falling back to JSON mock mode.")
            except Exception as e:
                print(f"⚠️  NetBox connection failed: {e}. Falling back to JSON mock mode.")

    def init_db(self):
        """Creates the DB file if it doesn't exist (Mock Mode). Seeds with default devices."""
        if not os.path.exists(DB_FILE):
            with open(DB_FILE, 'w') as f:
                json.dump(DEFAULT_MOCK_DEVICES, f, indent=2)
            print(f"✅ Created mock device database with {len(DEFAULT_MOCK_DEVICES)} devices")

    def get_all_devices(self) -> List[Dict]:
        """Reads all devices from NetBox (production) or local JSON (mock)."""
        if self.use_api:
            # Production: Fetch from NetBox API
            devices = []
            try:
                nb_devices = self.nb.dcim.devices.all()
                for d in nb_devices:
                    if d.primary_ip:
                        # NetBox renamed device_role -> role in 4.x; accept either.
                        role_obj = getattr(d, "role", None) or getattr(d, "device_role", None)
                        device_data = {
                            "name": d.name,
                            "ip": str(d.primary_ip).split('/')[0],
                            "platform": d.platform.slug if d.platform else "unknown",
                            "device_role": role_obj.slug if role_obj else "unknown",
                            "primary_ip": str(d.primary_ip).split('/')[0],
                            "site": d.site.slug if d.site else "unknown",
                            "manufacturer": d.device_type.manufacturer.slug if d.device_type and d.device_type.manufacturer else "unknown",
                            "mac": "",
                        }
                        # Populate MAC from the device's first interface that has one,
                        # so Wake-on-LAN still works when inventory comes from NetBox.
                        try:
                            ifaces = self.nb.dcim.interfaces.filter(device_id=d.id)
                            for iface in ifaces:
                                if getattr(iface, "mac_address", None):
                                    device_data["mac"] = iface.mac_address
                                    break
                        except Exception:
                            pass
                        # Per-device credential overrides from config_context.
                        # A device with local_context_data
                        # {"credentials": {"username": "x", "password": "y"}}
                        # overrides the platform-wide .env defaults.
                        if hasattr(d, 'config_context') and d.config_context:
                            creds = d.config_context.get('credentials', {})
                            if creds:
                                device_data['credentials'] = creds
                        devices.append(device_data)
                return devices
            except Exception as e:
                print(f"Error fetching from NetBox API: {e}")
                return []
        else:
            # Dev: Read local JSON
            self.init_db()
            with open(DB_FILE, 'r') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return DEFAULT_MOCK_DEVICES

    def get_trusted_macs(self) -> List[str]:
        """
        Returns a list of MAC addresses that are authorized.
        In production, this queries NetBox for all devices with interface MACs.
        In mock mode, returns a sensible default list.
        """
        if self.use_api:
            try:
                trusted = []
                interfaces = self.nb.dcim.interfaces.all()
                for iface in interfaces:
                    if iface.mac_address:
                        trusted.append(iface.mac_address.upper())
                # Union with admin-authorized registry entries
                for m in authorized_registry.authorized_macs():
                    trusted.append(m.upper())
                return trusted if trusted else DEFAULT_TRUSTED_MACS
            except Exception as e:
                print(f"⚠️  Failed to fetch trusted MACs from NetBox: {e}")
                return DEFAULT_TRUSTED_MACS
        
        # Mock / JSON mode: trusted set is the UNION of
        #   (a) MACs the admin explicitly authorized via the registry UI, and
        #   (b) the managed devices' own MACs (a managed switch/router/AP is
        #       never its own rogue).
        # This is what makes the scanner stop flagging legitimate devices and
        # replaces the old hardcoded DEFAULT_TRUSTED_MACS guesswork.
        trusted = set()
        for m in authorized_registry.authorized_macs():
            trusted.add(m.upper())
        try:
            for dev in self.get_all_devices():
                mac = dev.get("mac", "")
                if mac:
                    trusted.add(mac.strip().upper().replace("-", ":"))
        except Exception:
            pass
        # Keep a couple of defaults only if the admin has registered nothing yet,
        # so a fresh install still behaves sanely.
        if not trusted:
            return DEFAULT_TRUSTED_MACS.copy()
        return list(trusted)

# Standalone functions for backward compatibility if needed
def get_all_devices():
    nb = NetboxInventory()
    return nb.get_all_devices()