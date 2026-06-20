"""
UAF Authorized Devices Registry
================================
A simple, file-backed registry of MAC addresses the network administrator has
explicitly marked as trusted. This is the editable "source of truth" for the
rogue-device scanner: any MAC seen on the network that is NOT in this registry
(and not one of the managed devices' own MACs) is treated as a potential rogue.

Storage: authorized_devices.json (next to devices.json), so it persists across
restarts. Each entry: {"mac": "AA:BB:CC:DD:EE:FF", "label": "Reception PC",
"added": "2026-06-09T20:00:00"}.

This replaces the old hardcoded DEFAULT_TRUSTED_MACS approach with something an
admin can actually manage from the UI.
"""

import json
import os
from datetime import datetime
from typing import List, Dict

REGISTRY_FILE = "authorized_devices.json"


def _normalize(mac: str) -> str:
    return mac.strip().upper().replace("-", ":")


def _load() -> List[Dict]:
    if not os.path.exists(REGISTRY_FILE):
        return []
    try:
        with open(REGISTRY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save(entries: List[Dict]) -> None:
    with open(REGISTRY_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def list_authorized() -> List[Dict]:
    """Return all authorized device entries."""
    return _load()


def add_authorized(mac: str, label: str = "") -> Dict:
    """Add a MAC to the registry. Idempotent — updates label if MAC exists."""
    mac = _normalize(mac)
    if not mac:
        raise ValueError("MAC address is required")
    entries = _load()
    for e in entries:
        if e["mac"] == mac:
            if label:
                e["label"] = label
            _save(entries)
            return e
    entry = {"mac": mac, "label": label or "Unnamed device",
             "added": datetime.now().isoformat(timespec="seconds")}
    entries.append(entry)
    _save(entries)
    return entry


def remove_authorized(mac: str) -> bool:
    """Remove a MAC from the registry. Returns True if something was removed."""
    mac = _normalize(mac)
    entries = _load()
    new_entries = [e for e in entries if e["mac"] != mac]
    if len(new_entries) != len(entries):
        _save(new_entries)
        return True
    return False


def authorized_macs() -> List[str]:
    """Just the MAC strings, normalized — for the scanner to compare against."""
    return [_normalize(e["mac"]) for e in _load()]
