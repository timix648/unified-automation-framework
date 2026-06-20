#!/usr/bin/env python3
"""
Seed NetBox with the UAF lab devices (Source-of-Truth population).
=================================================================
Creates everything the UAF NetBox client needs so that, once you flip to NetBox
mode, `get_all_devices()` returns your three devices with the right platform
slugs (driver selection), primary IPs (the client skips devices without one),
MACs (Wake-on-LAN), and per-device credentials (via local_context_data).

Builds the full NetBox object chain, idempotently (safe to re-run):
  site -> manufacturer -> device type -> role -> platform
       -> device -> interface -> IP address -> primary IP -> credentials

Targets NetBox 3.7.x (matches the client's field names; pynetbox 7.3.x).

USAGE
-----
  # NetBox must be running (docker compose stack) and reachable.
  export NETBOX_URL=http://localhost:8080
  export NETBOX_TOKEN=0123456789abcdef0123456789abcdef01234567   # your token
  # (optional) device creds — defaults match config.py
  export CISCO_USER=admin CISCO_PASS=cisco123 CISCO_SECRET=cisco123
  export MIKROTIK_USER=admin MIKROTIK_PASS=mikrotik123
  export UNIFI_USER=admin UNIFI_PASS=ubnt123

  cd backend && python scripts/seed_netbox.py
"""
import os
import sys

try:
    import pynetbox
except ImportError:
    sys.exit("pynetbox not installed. Run: pip install pynetbox")

NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8080")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")

if not NETBOX_TOKEN:
    sys.exit("Set NETBOX_TOKEN (NetBox -> Admin -> API Tokens, or the compose "
             "SUPERUSER_API_TOKEN, e.g. 0123456789abcdef0123456789abcdef01234567)")

# --- The lab devices. platform slug MUST contain cisco / mikrotik / unifi so
#     DeviceFactory picks the right driver. ---
DEVICES = [
    {
        "name": "cisco-switch-01", "ip": "192.168.1.10", "mac": "00:1A:2B:3C:4D:5E",
        "manufacturer": ("Cisco", "cisco"),
        "device_type": ("Catalyst 2960", "catalyst-2960"),
        "role": ("Switch", "switch", "2196f3"),
        "platform": ("Cisco IOS", "cisco_ios"),
        "creds": {"username": os.getenv("CISCO_USER", "admin"),
                  "password": os.getenv("CISCO_PASS", "cisco123"),
                  "secret":   os.getenv("CISCO_SECRET", "cisco123")},
    },
    {
        "name": "mikrotik-router-01", "ip": "192.168.1.20", "mac": "6C:3B:6B:AA:BB:CC",
        "manufacturer": ("MikroTik", "mikrotik"),
        "device_type": ("hAP ac2", "hap-ac2"),
        "role": ("Edge Router", "edge-router", "4caf50"),
        "platform": ("MikroTik RouterOS", "mikrotik_routeros"),
        "creds": {"username": os.getenv("MIKROTIK_USER", "admin"),
                  "password": os.getenv("MIKROTIK_PASS", "mikrotik123")},
    },
    {
        "name": "unifi-ap-01", "ip": "192.168.1.30", "mac": "F0:9F:C2:11:22:33",
        "manufacturer": ("Ubiquiti", "ubiquiti"),
        "device_type": ("UAP-AC-Lite", "uap-ac-lite"),
        "role": ("Access Point", "access-point", "ff9800"),
        "platform": ("UniFi", "unifi"),
        "creds": {"username": os.getenv("UNIFI_USER", "admin"),
                  "password": os.getenv("UNIFI_PASS", "ubnt123")},
    },
]

SITE = ("Home Lab", "home-lab")
PREFIX_LEN = "24"


def get_or_create(endpoint, search: dict, create: dict):
    """Return an existing object matching `search`, else create it with `create`."""
    existing = endpoint.get(**search)
    if existing:
        return existing
    obj = endpoint.create(**create)
    print(f"  + created {endpoint.name}: {create.get('name') or create.get('model') or create.get('address')}")
    return obj


def main():
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    try:
        nb.status()
    except Exception as e:
        sys.exit(f"Cannot reach NetBox at {NETBOX_URL}: {e}")

    print(f"Seeding NetBox at {NETBOX_URL} ...")

    site = get_or_create(nb.dcim.sites,
                         {"slug": SITE[1]},
                         {"name": SITE[0], "slug": SITE[1], "status": "active"})

    for spec in DEVICES:
        print(f"\nDevice: {spec['name']}")
        mfr = get_or_create(nb.dcim.manufacturers,
                            {"slug": spec["manufacturer"][1]},
                            {"name": spec["manufacturer"][0], "slug": spec["manufacturer"][1]})
        dtype = get_or_create(nb.dcim.device_types,
                             {"slug": spec["device_type"][1]},
                             {"model": spec["device_type"][0], "slug": spec["device_type"][1],
                              "manufacturer": mfr.id})
        role = get_or_create(nb.dcim.device_roles,
                            {"slug": spec["role"][1]},
                            {"name": spec["role"][0], "slug": spec["role"][1],
                             "color": spec["role"][2]})
        plat = get_or_create(nb.dcim.platforms,
                            {"slug": spec["platform"][1]},
                            {"name": spec["platform"][0], "slug": spec["platform"][1]})

        # Device (with credentials in local_context_data -> surfaces as config_context)
        dev = nb.dcim.devices.get(name=spec["name"])
        if not dev:
            dev = nb.dcim.devices.create(
                name=spec["name"],
                device_type=dtype.id,
                role=role.id,               # NetBox 3.7 API expects 'role'
                site=site.id,
                platform=plat.id,
                status="active",
                local_context_data={"credentials": spec["creds"]},
            )
            print(f"  + created device: {spec['name']}")
        else:
            dev.local_context_data = {"credentials": spec["creds"]}
            dev.save()

        # Management interface (carries the MAC for Wake-on-LAN)
        iface = nb.dcim.interfaces.get(device_id=dev.id, name="mgmt0")
        if not iface:
            iface = nb.dcim.interfaces.create(
                device=dev.id, name="mgmt0", type="virtual",
                mac_address=spec["mac"],
            )
            print("  + created interface mgmt0")
        else:
            iface.mac_address = spec["mac"]
            iface.save()

        # IP address assigned to the interface
        addr = f"{spec['ip']}/{PREFIX_LEN}"
        ip = nb.ipam.ip_addresses.get(address=addr)
        if not ip:
            ip = nb.ipam.ip_addresses.create(
                address=addr, status="active",
                assigned_object_type="dcim.interface",
                assigned_object_id=iface.id,
            )
            print(f"  + created IP {addr}")

        # Make it the device's primary IP (the client SKIPS devices without one)
        if not dev.primary_ip4 or dev.primary_ip4.id != ip.id:
            dev.primary_ip4 = ip.id
            dev.save()
            print(f"  + set primary IPv4 -> {addr}")

    print("\n✅ Done. Verify in NetBox UI (Devices) or via the UAF backend once "
          "NETBOX_URL/NETBOX_TOKEN are set and MOCK_MODE=False.")


if __name__ == "__main__":
    main()
