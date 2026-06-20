"""
UAF Schedule Policy Settings
=============================
File-backed store for the admin-configurable time-based access policy.

Instead of hardcoding "business hours = 8..18" in the scheduler, the admin sets
the window here (via the UI). The scheduler reads these values each cycle, so
changes take effect on the next run without a code edit or restart.

Storage: schedule_policy.json (next to devices.json).
Schema: {"block_start_hour": 18, "block_end_hour": 8, "enabled": true}

Semantics:
  - "Block" hours are when internet access is RESTRICTED (off-hours).
  - The window wraps midnight when block_start_hour > block_end_hour
    (e.g. block 18:00 -> 08:00 means restricted overnight, allowed during the day).
"""

import json
import os
from typing import Dict

POLICY_FILE = "schedule_policy.json"

DEFAULT_POLICY = {
    "block_start_hour": 18,   # 6 PM — start restricting
    "block_end_hour": 8,      # 8 AM — stop restricting
    "enabled": True,
}


def _load() -> Dict:
    if not os.path.exists(POLICY_FILE):
        return DEFAULT_POLICY.copy()
    try:
        with open(POLICY_FILE, "r") as f:
            data = json.load(f)
        # fill any missing keys with defaults
        merged = DEFAULT_POLICY.copy()
        merged.update({k: data[k] for k in DEFAULT_POLICY if k in data})
        return merged
    except (json.JSONDecodeError, OSError):
        return DEFAULT_POLICY.copy()


def get_policy() -> Dict:
    """Return the current schedule policy."""
    return _load()


def set_policy(block_start_hour: int, block_end_hour: int, enabled: bool = True) -> Dict:
    """Update the schedule policy. Hours are 0-23."""
    for h in (block_start_hour, block_end_hour):
        if not isinstance(h, int) or not (0 <= h <= 23):
            raise ValueError("Hours must be integers between 0 and 23")
    policy = {
        "block_start_hour": block_start_hour,
        "block_end_hour": block_end_hour,
        "enabled": bool(enabled),
    }
    with open(POLICY_FILE, "w") as f:
        json.dump(policy, f, indent=2)
    return policy


def is_restricted_now(hour: int) -> bool:
    """Given the current hour (0-23), return True if access should be RESTRICTED.

    Handles windows that wrap past midnight (start > end).
    """
    p = _load()
    if not p.get("enabled", True):
        return False
    start = p["block_start_hour"]
    end = p["block_end_hour"]
    if start == end:
        return False  # zero-length window = never restricted
    if start < end:
        # same-day window, e.g. block 9..17
        return start <= hour < end
    # wraps midnight, e.g. block 18..8 (restricted overnight)
    return hour >= start or hour < end