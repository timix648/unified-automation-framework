"""
UAF Device Manager (Factory Pattern)
======================================
Dynamically selects the correct driver based on the device platform from NetBox.

Credential Resolution (How 300+ devices work without manual per-device config):
  1. NetBox stores the INVENTORY (IPs, hostnames, platforms) for all 600 devices.
  2. The .env file stores ONE set of credentials PER VENDOR PLATFORM:
     - In enterprise networks, all Cisco switches share the same SSH credentials
       because they authenticate via TACACS+/RADIUS (centralized auth server).
     - Same for MikroTik (all share one API user) and UniFi (one controller manages all APs).
  3. If a specific device has DIFFERENT credentials, store them in NetBox's
     "config_context" field as JSON: {"credentials": {"username": "x", "password": "y"}}
     The factory will use those instead of the .env defaults.

So the flow for 300 switches is:
  NetBox API -> 300 device IPs automatically -> Factory creates 300 drivers
  -> All use same TACACS+ credentials from .env -> Nornir runs tasks in parallel
"""

from app.inventory.netbox_client import NetboxInventory
from app.drivers.cisco_driver import CiscoIOSDriver
from app.drivers.mikrotik_driver import MikroTikDriver
from app.drivers.unifi_driver import UniFiDriver
from app.core.config import settings
from typing import Dict, Any, List


class DeviceFactory:
    """
    The Factory Pattern:
    1. Asks NetBox for device details (could be 3 or 3000 devices).
    2. Looks at the 'platform' field to select the correct vendor driver.
    3. Uses per-device credentials if available, else platform-wide .env defaults.
    4. Returns the correct Python driver class automatically.
    """

    @staticmethod
    def get_driver(device_info: Dict[str, Any]):
        """
        Get the appropriate driver for a device.

        Credential resolution order:
          1. Per-device overrides from NetBox config_context (device_info['credentials'])
          2. Platform-wide defaults from .env environment variables

        This means for 300 Cisco switches you only need ONE username/password in .env
        (because they all authenticate via TACACS+/RADIUS), but if switch #47 has a
        unique local account, you set it in NetBox's config_context for that device only.

        Args:
            device_info: Dict with 'ip'/'primary_ip', 'platform', and optionally
                         'credentials' keys (comes from NetBox or local JSON).

        Returns:
            An instance of CiscoIOSDriver, MikroTikDriver, or UniFiDriver.
        """
        # Get IP - support both 'ip' and 'primary_ip' keys from NetBox
        ip = device_info.get('ip') or device_info.get('primary_ip', '')
        platform = device_info.get('platform', '').lower()

        # Per-device credential overrides (from NetBox config_context)
        # If the device has its own credentials, use them; otherwise fall back to .env
        overrides = device_info.get('credentials', {})

        if "cisco" in platform:
            device_config = {
                'host': ip,
                'username': overrides.get('username', settings.CISCO_USER),
                'password': overrides.get('password', settings.CISCO_PASS),
                'secret': overrides.get('secret', settings.CISCO_SECRET),
                'port': overrides.get('port', settings.CISCO_PORT),
            }
            return CiscoIOSDriver(device_config, mock_mode=settings.MOCK_MODE)

        elif "mikrotik" in platform or "routeros" in platform:
            device_config = {
                'host': ip,
                'username': overrides.get('username', settings.MIKROTIK_USER),
                'password': overrides.get('password', settings.MIKROTIK_PASS),
                'port': overrides.get('port', settings.MIKROTIK_PORT),
                'api_port': overrides.get('api_port', 8728),
            }
            return MikroTikDriver(device_config, mock_mode=settings.MOCK_MODE)

        elif "unifi" in platform or "ubiquiti" in platform:
            device_config = {
                'host': ip,
                'username': overrides.get('username', settings.UNIFI_USER),
                'password': overrides.get('password', settings.UNIFI_PASS),
                'port': overrides.get('port', settings.UNIFI_PORT),
                'site': overrides.get('site', settings.UNIFI_SITE),
                'device_mac': device_info.get('mac', ''),
            }
            return UniFiDriver(device_config, mock_mode=settings.MOCK_MODE)

        else:
            raise ValueError(f"Unsupported Platform: {platform}")

    @staticmethod
    def initialize_all_active_devices() -> List:
        """
        Boots up connections to every device listed in NetBox.
        """
        nb = NetboxInventory()
        raw_devices = nb.get_all_devices()

        active_drivers = []
        for dev in raw_devices:
            try:
                print(f"Initializing connection to {dev['name']} ({dev['platform']})...")
                driver = DeviceFactory.get_driver(dev)
                # We don't connect immediately here to save time,
                # we connect only when an action is required.
                active_drivers.append(driver)
            except Exception as e:
                print(f"Skipping {dev['name']}: {e}")

        return active_drivers
