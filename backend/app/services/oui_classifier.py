"""
UAF — OUI Device Classification (rogue-detection enhancement)
=============================================================

A MAC address is 6 bytes. The first 3 bytes (the OUI — Organizationally Unique
Identifier) are assigned by the IEEE to the device manufacturer. By looking up
that prefix we infer the VENDOR, and from the vendor a likely DEVICE TYPE
(network infrastructure vs. an end-user endpoint).

This is a CLASSIFICATION aid, not authentication:
  - Tells the admin *what kind* of device an unknown MAC probably is, so a rogue
    Ubiquiti AP reads differently from someone's Apple phone.
  - NOT security-grade alone — a MAC can be spoofed. Deliberately spoofing an
    infrastructure OUI on a controlled network is itself a suspicious signal,
    which is exactly why surfacing the vendor is useful.
  - Enterprise-scale path (future work): 802.1X/RADIUS for dynamic device
    authentication + CDP/LLDP topology discovery so isolation targets the
    rogue's edge port, never an uplink/trunk on the core switch.

DATA SOURCES (two-tier, best of both):
  1. CURATED DICT (always present, offline): infrastructure + endpoint vendor
     OUI prefixes covering UAF's gear and common enterprise vendors. Guarantees
     the classifier works with zero external files or network access.
  2. OPTIONAL FULL IEEE REGISTRY: if the official IEEE OUI CSV is present on
     disk (env UAF_OUI_CSV or backend/data/oui.csv), it is loaded for complete
     ~32,000-vendor coverage. Download once from:
        https://standards-oui.ieee.org/oui/oui.csv
     The curated dict still decides infrastructure-vs-endpoint; the full CSV
     just lets us name vendors we don't have curated.

Never raises — a missing/malformed MAC returns an "unknown" record so callers
can attach the result to a threat entry unconditionally.
"""

import os
import csv
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. Curated OUI prefixes (first 3 octets, uppercase, no separators).
#    Infrastructure = switches / routers / APs / firewalls.
# ---------------------------------------------------------------------------
_INFRASTRUCTURE_OUIS: Dict[str, str] = {
    # Cisco
    "00000C": "Cisco", "001A2F": "Cisco", "002155": "Cisco", "00D0BC": "Cisco",
    "0CD996": "Cisco", "E8EDF3": "Cisco", "F4CFE2": "Cisco", "508789": "Cisco",
    "00000C": "Cisco", "000142": "Cisco", "0007EB": "Cisco", "001121": "Cisco",
    "08ECF5": "Cisco", "000F66": "Cisco",  # Linksys/Cisco
    # MikroTik (RouterBoard)
    "6C3B6B": "MikroTik", "4C5E0C": "MikroTik", "E48D8C": "MikroTik",
    "B869F4": "MikroTik", "742F68": "MikroTik", "CC2DE0": "MikroTik",
    "DC2C6E": "MikroTik", "18FD74": "MikroTik", "08555D": "MikroTik",
    "64D154": "MikroTik", "D4CA6D": "MikroTik",
    # Ubiquiti (UniFi)
    "0418D6": "Ubiquiti", "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti",
    "788A20": "Ubiquiti", "802AA8": "Ubiquiti", "B4FBE4": "Ubiquiti",
    "DC9FDB": "Ubiquiti", "FCECDA": "Ubiquiti", "687251": "Ubiquiti",
    "F09FC2": "Ubiquiti", "74ACB9": "Ubiquiti", "E063DA": "Ubiquiti",
    # Juniper
    "002688": "Juniper", "3C61C4": "Juniper", "F0A3B6": "Juniper",
    "5C5EAB": "Juniper", "2C6BF5": "Juniper",
    # Aruba / HPE networking
    "000B86": "Aruba", "186472": "Aruba", "94B40F": "Aruba", "ACA31E": "Aruba",
    "000FB5": "HPE", "002386": "HPE", "70106F": "HPE", "001083": "HPE",
    "643150": "HPE",
    # Netgear
    "00146C": "Netgear", "20E52A": "Netgear", "A040A0": "Netgear",
    "2C3033": "Netgear", "9CD36D": "Netgear",
    # TP-Link
    "001478": "TP-Link", "50C7BF": "TP-Link", "EC086B": "TP-Link",
    "A42BB0": "TP-Link", "B0487A": "TP-Link",
    # Fortinet / Palo Alto / security appliances
    "00090F": "Fortinet", "085B0E": "Fortinet", "904401": "Fortinet",
    "001B17": "PaloAlto", "B40C25": "PaloAlto",
    # D-Link
    "001346": "D-Link", "1CBDB9": "D-Link", "340804": "D-Link",
    # Ruckus / CommScope, Extreme, Zyxel
    "000C42": "Routerboard", "0C8112": "Ruckus", "001392": "Extreme",
    "5C6A80": "Zyxel",
}

# ---------------------------------------------------------------------------
# 2. Curated ENDPOINT (end-user device) vendor prefixes.
# ---------------------------------------------------------------------------
_ENDPOINT_OUIS: Dict[str, str] = {
    # Apple
    "001451": "Apple", "3C0754": "Apple", "A4B197": "Apple", "F0DBF8": "Apple",
    "DC2B2A": "Apple", "8866A5": "Apple", "F018A8": "Apple", "ACBC32": "Apple",
    # Samsung
    "002566": "Samsung", "5CF7E6": "Samsung", "E8508B": "Samsung",
    "8425DB": "Samsung", "C8A823": "Samsung",
    # Dell
    "00188B": "Dell", "B083FE": "Dell", "F8BC12": "Dell", "001422": "Dell",
    "180373": "Dell",
    # Intel (laptop/desktop NICs)
    "001B21": "Intel", "3C970E": "Intel", "A0A8CD": "Intel", "7C7A91": "Intel",
    "8C1645": "Intel", "F8E43B": "Intel",
    # Lenovo
    "00059A": "Lenovo", "54EE75": "Lenovo", "8C1645": "Lenovo",
    # Google / Microsoft / HP (PCs)
    "3C5AB4": "Google", "00155D": "Microsoft", "001B78": "HP",
    "B499BA": "HP", "3863BB": "HP",
}

# ---------------------------------------------------------------------------
# Optional: full IEEE registry, loaded once on first use if the CSV exists.
# ---------------------------------------------------------------------------
_FULL_REGISTRY: Optional[Dict[str, str]] = None  # lazy-loaded


def _candidate_csv_paths():
    """Where we look for the optional full IEEE oui.csv."""
    paths = []
    env = os.getenv("UAF_OUI_CSV")
    if env:
        paths.append(Path(env))
    # common project locations relative to this file: backend/data/oui.csv
    here = Path(__file__).resolve()
    paths.append(here.parent.parent.parent / "data" / "oui.csv")   # backend/data/oui.csv
    paths.append(here.parent / "oui.csv")
    paths.append(Path("data/oui.csv"))
    return paths


def _load_full_registry() -> Dict[str, str]:
    """
    Lazy-load the IEEE oui.csv if present. Returns {OUI6: vendor}. Empty dict if
    no CSV is found (we then rely solely on the curated dicts). Safe on any
    error — classification must never break because of an optional data file.
    """
    global _FULL_REGISTRY
    if _FULL_REGISTRY is not None:
        return _FULL_REGISTRY

    _FULL_REGISTRY = {}
    for p in _candidate_csv_paths():
        try:
            if not p or not p.exists():
                continue
            with open(p, "r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)  # skip header row
                # IEEE oui.csv columns: Registry,Assignment,Organization Name,Org Address
                for row in reader:
                    if len(row) < 3:
                        continue
                    assignment = row[1].replace("-", "").replace(":", "").strip().upper()
                    org = row[2].strip().strip('"')
                    if len(assignment) >= 6 and org:
                        _FULL_REGISTRY[assignment[:6]] = org
            logger.info(f"OUI classifier: loaded {len(_FULL_REGISTRY)} entries from {p}")
            break
        except Exception as e:
            logger.warning(f"OUI classifier: could not load {p}: {e}")
            continue
    return _FULL_REGISTRY


def _normalize(mac: str) -> str:
    """Strip separators and uppercase; return the first 6 hex chars (the OUI)."""
    if not mac:
        return ""
    cleaned = (
        mac.replace(":", "").replace("-", "").replace(".", "").replace(" ", "").upper()
    )
    return cleaned[:6]


def classify_mac(mac: str) -> Dict[str, str]:
    """
    Classify a MAC by its OUI.

    Returns:
      {
        "vendor": "<vendor name or 'Unknown'>",
        "device_type": "infrastructure" | "endpoint" | "unknown",
        "oui": "<first 6 hex chars>",
        "note": "<short human-readable hint>"
      }

    Resolution order:
      1. Curated infrastructure list  -> device_type "infrastructure"
      2. Curated endpoint list        -> device_type "endpoint"
      3. Full IEEE CSV (if loaded)    -> vendor named, device_type "unknown"
                                         (we can't infer role from CSV alone)
      4. Nothing                      -> Unknown / unknown
    """
    oui = _normalize(mac)
    if len(oui) < 6:
        return {
            "vendor": "Unknown",
            "device_type": "unknown",
            "oui": oui,
            "note": "MAC missing or malformed; vendor could not be determined.",
        }

    if oui in _INFRASTRUCTURE_OUIS:
        vendor = _INFRASTRUCTURE_OUIS[oui]
        return {
            "vendor": vendor,
            "device_type": "infrastructure",
            "oui": oui,
            "note": (f"OUI belongs to {vendor} — likely network infrastructure "
                     f"(switch/router/AP). An unrecognised infrastructure device "
                     f"may be a rogue switch or access point."),
        }

    if oui in _ENDPOINT_OUIS:
        vendor = _ENDPOINT_OUIS[oui]
        return {
            "vendor": vendor,
            "device_type": "endpoint",
            "oui": oui,
            "note": (f"OUI belongs to {vendor} — likely an end-user device "
                     f"(laptop/phone/desktop)."),
        }

    # Fall back to the full IEEE registry if available — names the vendor even
    # though we can't infer infrastructure-vs-endpoint from the CSV alone.
    full = _load_full_registry()
    if oui in full:
        vendor = full[oui]
        return {
            "vendor": vendor,
            "device_type": "unknown",
            "oui": oui,
            "note": (f"OUI belongs to {vendor} (IEEE registry). Device role "
                     f"not classified — review manually."),
        }

    return {
        "vendor": "Unknown",
        "device_type": "unknown",
        "oui": oui,
        "note": "OUI not in UAF's known-vendor table; device type undetermined.",
    }


if __name__ == "__main__":
    samples = [
        "6C:3B:6B:96:FF:D6",   # MikroTik   -> infrastructure
        "04:18:D6:5E:AF:65",   # Ubiquiti   -> infrastructure
        "E8:ED:F3:11:22:33",   # Cisco      -> infrastructure
        "3C:07:54:AA:BB:CC",   # Apple      -> endpoint
        "AB:CD:EF:00:11:22",   # unknown
        "",                    # malformed
    ]
    for s in samples:
        print(f"{s or '(empty)':<20} -> {classify_mac(s)}")