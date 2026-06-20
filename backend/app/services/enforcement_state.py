"""
UAF Enforcement State
======================
Controls whether the automated kill-switch is allowed to actually shut ports.

Two phases, matching how production NAC systems onboard a network:

  - "learning"  (default for a fresh install): the scheduled scan still DETECTS
    and REPORTS rogue devices (they show up as threats in the UI), but the
    kill-switch does NOT shut any ports. This lets a new administrator see
    everything on the network and decide what to trust, instead of logging in
    to find legitimate devices already isolated.

  - "armed": enforcement is active. Any device seen on the network that is not
    in the authorized registry (and is not a managed device) is isolated
    automatically — the self-defending-network behaviour described in the report.

The administrator moves from learning to armed with one explicit action once the
trusted baseline is built. State is file-backed so it survives restarts.

Storage: enforcement_state.json (next to devices.json).
"""

import json
import os
from datetime import datetime
from typing import Dict

STATE_FILE = "enforcement_state.json"

LEARNING = "learning"
ARMED = "armed"


def _default() -> Dict:
    return {
        "mode": LEARNING,
        "updated": datetime.now().isoformat(timespec="seconds"),
        "updated_by": "system",
    }


def _load() -> Dict:
    if not os.path.exists(STATE_FILE):
        return _default()
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        if data.get("mode") not in (LEARNING, ARMED):
            return _default()
        return data
    except (json.JSONDecodeError, OSError):
        return _default()


def _save(data: Dict) -> None:
    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=2)


def get_state() -> Dict:
    """Return the full enforcement state dict."""
    return _load()


def get_mode() -> str:
    """Return just the current mode string ('learning' or 'armed')."""
    return _load().get("mode", LEARNING)


def is_armed() -> bool:
    """True only when the admin has explicitly activated enforcement."""
    return get_mode() == ARMED


def set_mode(mode: str, updated_by: str = "admin") -> Dict:
    """Set enforcement mode. Raises ValueError on an invalid mode."""
    if mode not in (LEARNING, ARMED):
        raise ValueError(f"Invalid enforcement mode: {mode!r}")
    data = {
        "mode": mode,
        "updated": datetime.now().isoformat(timespec="seconds"),
        "updated_by": updated_by or "admin",
    }
    _save(data)
    return data