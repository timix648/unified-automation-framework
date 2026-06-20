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
from dotenv import load_dotenv

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

    # --- JWT Authentication ---
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


settings = Settings()
