"""
UAF Configuration
==================
Centralized configuration loaded from environment variables.

FIXED:
- Added VERSION (referenced in main.py, endpoints.py)
- Added CISCO_PORT (referenced in device_manager)
- Added MIKROTIK_PORT (referenced in device_manager)
- Added UNIFI_PORT (referenced in device_manager)
- Added UNIFI_SITE (referenced in device_manager, unifi_driver)
- Added MQTT_BROKER, MQTT_PORT, MQTT_TOPIC (referenced in wol_bridge_agent)
- Added JWT_SECRET_KEY, JWT_EXPIRE_MINUTES (referenced in security.py)
"""

import os
import sys
from dotenv import load_dotenv


def _make_console_encoding_safe() -> None:
    """Stop unencodable characters in log/print output from raising.

    Several modules print status lines containing emoji. When stdout cannot
    represent them -- a Windows console under cp1252, or any redirected/piped
    stream on a non-UTF-8 locale -- ``print`` raises UnicodeEncodeError. That
    exception surfaces INSIDE the code path doing the work, not merely in the
    logging: in kill_switch.execute_kill_switch the status line is printed
    before driver.shutdown_port(), so the port was never actually shut.

    Switching the streams to errors="replace" makes unrepresentable characters
    degrade to "?" instead of raising. The console's own encoding is left
    untouched, so UTF-8 terminals (Linux, Docker) keep rendering emoji exactly
    as before. This is deliberately non-fatal: if the streams cannot be
    reconfigured we carry on rather than block startup.
    """
    # Error handlers that already degrade instead of raising. Anything else --
    # including "strict" AND the "surrogateescape" that Python uses by default
    # for a redirected stream -- raises on an unencodable character such as an
    # emoji, so it must be switched.
    non_raising = {"replace", "ignore", "backslashreplace", "xmlcharrefreplace"}
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure") and getattr(stream, "errors", None) not in non_raising:
                stream.reconfigure(errors="replace")
        except (ValueError, OSError, AttributeError):
            # Detached, already closed, or a stream that does not support it.
            pass


# Applied on import. config.py is imported by every module that emits these
# status lines, so this single call covers the whole backend regardless of
# which entry point started it.
_make_console_encoding_safe()

# Load the .env file
load_dotenv()


class Settings:
    # --- System ---
    PROJECT_NAME = os.getenv("PROJECT_NAME", "UAF - Unified Automation Framework")
    VERSION = os.getenv("VERSION", "1.0.0")
    MOCK_MODE = os.getenv("MOCK_MODE", "True").lower() == "true"

    # --- Cisco Credentials (SSH) ---
    CISCO_HOST = os.getenv("CISCO_IP", "192.168.1.10")
    CISCO_USER = os.getenv("CISCO_USER", "admin")
    CISCO_PASS = os.getenv("CISCO_PASS", "cisco123")
    CISCO_SECRET = os.getenv("CISCO_SECRET", "cisco123")
    CISCO_PORT = int(os.getenv("CISCO_PORT", "22"))

    # --- MikroTik Credentials (SSH/API) ---
    MIKROTIK_HOST = os.getenv("MIKROTIK_IP", "192.168.1.20")
    MIKROTIK_USER = os.getenv("MIKROTIK_USER", "admin")
    MIKROTIK_PASS = os.getenv("MIKROTIK_PASS", "mikrotik123")
    MIKROTIK_PORT = int(os.getenv("MIKROTIK_PORT", "22"))

    # --- UniFi Controller (API) ---
    UNIFI_HOST = os.getenv("UNIFI_IP", "192.168.1.30")
    UNIFI_USER = os.getenv("UNIFI_USER", "ubnt")
    UNIFI_PASS = os.getenv("UNIFI_PASS", "ubnt123")
    UNIFI_PORT = int(os.getenv("UNIFI_PORT", "8443"))
    UNIFI_SITE = os.getenv("UNIFI_SITE", "default")

    # --- NetBox ---
    NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8000")
    NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")

    # --- MQTT (WoL Bridge Agent) ---
    MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
    MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
    MQTT_TOPIC = os.getenv("MQTT_TOPIC", "uaf/wol/commands")

    # --- WoL Bridge (remote/cloud deployment) ---
    # A magic packet is a link-local broadcast: it cannot be routed to the lab
    # from a cloud host, so a backend running off-site can never wake anything
    # by sending the packet itself. Point this at the bridge agent running on
    # a machine INSIDE the target network (e.g. "http://100.x.y.z:5001") and
    # wake requests are relayed there instead.
    # Empty (the default) keeps the original behaviour: send locally.
    WOL_BRIDGE_URL = os.getenv("WOL_BRIDGE_URL", "").rstrip("/")
    WOL_BRIDGE_TIMEOUT = float(os.getenv("WOL_BRIDGE_TIMEOUT", "5"))

    # --- JWT Authentication ---
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


settings = Settings()
