"""
Shared test fixtures for UAF backend tests.
"""
import os
# Force mock mode for the entire suite BEFORE any app module imports config.
# The app reads MOCK_MODE from the environment / .env at import time; during
# live-hardware work the real .env is set to MOCK_MODE=False, which would make
# the driver and endpoint tests attempt real SSH/REST connections and error
# out. Setting it here (load_dotenv does not override an already-set env var)
# keeps the test suite deterministic and self-contained regardless of .env.
os.environ["MOCK_MODE"] = "True"

import sys
from unittest.mock import MagicMock

# Stub out pysnmp asyncore-based modules that don't exist in pysnmp-lextudio 6.x
# These are only needed by snmp_trap_listener which is skipped in MOCK_MODE anyway.
for _mod in [
    "pysnmp.carrier.asyncore",
    "pysnmp.carrier.asyncore.dgram",
    "pysnmp.carrier.asyncore.dgram.udp",
    "pysnmp.entity.rfc3413",
    "pysnmp.entity.rfc3413.ntfrcv",
]:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

import pytest
from unittest.mock import patch
from datetime import timedelta


# ---------------------------------------------------------------------------
# Mock device data (mirrors NetboxInventory.DEFAULT_MOCK_DEVICES)
# ---------------------------------------------------------------------------

MOCK_CISCO = {
    "name": "cisco-switch-01",
    "ip": "192.168.1.10",
    "primary_ip": "192.168.1.10",
    "platform": "cisco_ios",
    "device_role": "switch",
    "site": "home-lab",
    "manufacturer": "Cisco",
    "mac": "00:1A:2B:3C:4D:5E",
}

MOCK_MIKROTIK = {
    "name": "mikrotik-router-01",
    "ip": "192.168.1.20",
    "primary_ip": "192.168.1.20",
    "platform": "mikrotik_routeros",
    "device_role": "edge-router",
    "site": "home-lab",
    "manufacturer": "MikroTik",
    "mac": "6C:3B:6B:AA:BB:CC",
}

MOCK_UNIFI = {
    "name": "unifi-ap-01",
    "ip": "192.168.1.30",
    "primary_ip": "192.168.1.30",
    "platform": "unifi",
    "device_role": "access-point",
    "site": "home-lab",
    "manufacturer": "Ubiquiti",
    "mac": "F0:9F:C2:11:22:33",
}

ALL_MOCK_DEVICES = [MOCK_CISCO, MOCK_MIKROTIK, MOCK_UNIFI]


# ---------------------------------------------------------------------------
# Auth helper — returns a valid JWT bearer header for use in test requests
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_headers():
    """Return Authorization headers with a valid admin JWT token."""
    from app.core.security import create_access_token

    token = create_access_token(
        data={"sub": "admin", "role": "admin", "permissions": ["read", "write", "execute", "delete"]},
        expires_delta=timedelta(minutes=30),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def operator_headers():
    """Return Authorization headers with a valid operator JWT token."""
    from app.core.security import create_access_token

    token = create_access_token(
        data={"sub": "operator", "role": "operator", "permissions": ["read", "execute"]},
        expires_delta=timedelta(minutes=30),
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    """Return Authorization headers with a valid viewer JWT token."""
    from app.core.security import create_access_token

    token = create_access_token(
        data={"sub": "viewer", "role": "viewer", "permissions": ["read"]},
        expires_delta=timedelta(minutes=30),
    )
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# FastAPI TestClient
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Provide an httpx TestClient bound to the FastAPI app."""
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c