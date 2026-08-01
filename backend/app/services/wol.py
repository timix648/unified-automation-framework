"""
UAF Wake-on-LAN Service
=========================
Sends WoL Magic Packets to power on devices remotely.

FIX (delivery): the magic packet was always sent to the limited broadcast
address 255.255.255.255. That address is NOT interface-specific -- the OS
picks a single outgoing interface from the routing table, and on a
multi-homed host (Wi-Fi + Ethernet + a VPN like Tailscale + a WSL/Hyper-V
virtual switch) the winner is frequently a virtual adapter with no physical
network behind it. The packet is then sent successfully into nothing, and
because UDP is connectionless sendto() still reports success, so the caller
is told the host was woken when no frame ever reached the wire.

The fix enumerates the host's live interfaces AT RUN TIME and sends the
packet out of each one explicitly, binding the socket to that interface's
own address. Broadcast addresses are derived from each interface's IP and
netmask, so nothing about any particular network is baked into the code and
it keeps working when the machine moves between networks.
"""

import ipaddress
import socket
from typing import List, Optional, Tuple

try:  # Optional: enumeration needs psutil. Absence must not break WoL.
    import psutil
except ImportError:  # pragma: no cover - depends on the install environment
    psutil = None

# The ambiguous "any interface" destination. Treated as a request to
# auto-select rather than as a literal address to send to.
GLOBAL_BROADCAST = "255.255.255.255"

# Port 9 (discard) is the WoL convention; some NICs and BIOS implementations
# listen on port 7 (echo) instead, so both are used.
WOL_PORTS = (9, 7)


def build_magic_packet(mac_address: str) -> bytes:
    """Build a WoL magic packet: 6 bytes of 0xFF + the target MAC 16 times.

    Raises:
        ValueError: if the MAC address is not 12 hex digits.
    """
    mac_clean = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        raise ValueError(f"Invalid MAC address format: {mac_address}")
    return b"\xFF" * 6 + bytes.fromhex(mac_clean) * 16


def get_broadcast_targets() -> List[Tuple[str, str]]:
    """Return (source_ip, broadcast_ip) for every usable IPv4 interface.

    Derived live from the host's own interfaces, so no address is hardcoded
    and the result follows the machine onto whatever network it joins.

    Excluded, because a magic packet sent there cannot reach a LAN host:
      - interfaces that are administratively down
      - loopback (127.0.0.0/8)
      - link-local / APIPA (169.254.0.0/16), i.e. unplugged adapters
      - /31 and /32 assignments, which have no broadcast domain (a Tailscale
        interface is a /32 and cannot carry a broadcast)
    """
    if psutil is None:
        return []

    targets: List[Tuple[str, str]] = []
    try:
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            iface = stats.get(name)
            if iface is None or not iface.isup:
                continue
            for addr in addrs:
                if addr.family != socket.AF_INET or not addr.netmask:
                    continue
                try:
                    ip = ipaddress.IPv4Address(addr.address)
                    if ip.is_loopback or ip.is_link_local:
                        continue
                    network = ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    if network.prefixlen >= 31:
                        continue
                    targets.append((addr.address, str(network.broadcast_address)))
                except (ipaddress.AddressValueError, ValueError):
                    continue
    except Exception:
        # Interface enumeration is best-effort; the caller falls back.
        return []
    return targets


def _send(packet: bytes, dest_ip: str, port: int, source_ip: Optional[str] = None) -> bool:
    """Send one packet, optionally pinned to a specific source interface."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if source_ip:
                # Binding the source address forces the packet out of that
                # interface instead of letting the routing table choose.
                sock.bind((source_ip, 0))
            sock.sendto(packet, (dest_ip, port))
        return True
    except OSError:
        return False


def _relay_via_bridge(mac_address: str, broadcast_ip: str, port: int) -> bool:
    """Relay the wake request to a bridge agent inside the target network.

    Returns True only if the bridge accepted it. Any failure returns False so
    the caller falls back to sending locally.
    """
    try:
        from app.core.config import settings
        bridge_url = getattr(settings, "WOL_BRIDGE_URL", "")
        if not bridge_url:
            return False
        import requests
        response = requests.post(
            f"{bridge_url}/wake",
            json={"mac_address": mac_address, "broadcast_ip": broadcast_ip, "port": port},
            timeout=getattr(settings, "WOL_BRIDGE_TIMEOUT", 5),
        )
        return response.status_code == 200 and response.json().get("success") is True
    except Exception:
        # Unreachable bridge, bad response, or requests unavailable.
        return False


def send_magic_packet(mac_address: str, broadcast_ip: str = GLOBAL_BROADCAST, port: int = 9,
                      use_bridge: bool = True):
    """Send a Wake-on-LAN magic packet to power on a device.

    Args:
        mac_address: Target MAC ("AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF").
        broadcast_ip: Destination. A specific subnet broadcast (e.g. "192.168.1.255")
            is sent to exactly as given. The default 255.255.255.255 means
            "work it out", and the packet goes out of every live interface.
        port: UDP port used for an explicitly addressed send (default 9).

    Returns:
        True if at least one packet was sent.

    Raises:
        ValueError: If the MAC address format is invalid.
        OSError: If no packet could be sent at all.
    """
    packet = build_magic_packet(mac_address)

    # Remote deployment: a magic packet is a link-local broadcast and cannot be
    # routed from a cloud host into the lab. When a bridge agent inside the
    # target network is configured, relay the request to it. Falls through to a
    # local send if the bridge is unreachable, so this can never make WoL worse.
    # use_bridge=False is passed by the bridge agent itself, so that an agent
    # whose environment also defines WOL_BRIDGE_URL cannot relay to itself.
    if use_bridge and _relay_via_bridge(mac_address, broadcast_ip, port):
        return True

    # An explicit destination is honoured exactly, so a caller that knows the
    # right subnet broadcast keeps full control.
    if broadcast_ip and broadcast_ip != GLOBAL_BROADCAST:
        if not _send(packet, broadcast_ip, port):
            raise OSError(f"Could not send magic packet to {broadcast_ip}:{port}")
        return True

    # Auto mode: out of every live interface, to that interface's own subnet
    # broadcast and to the global broadcast, on both WoL ports.
    sent = 0
    for source_ip, iface_broadcast in get_broadcast_targets():
        for dest in (iface_broadcast, GLOBAL_BROADCAST):
            for wol_port in WOL_PORTS:
                if _send(packet, dest, wol_port, source_ip=source_ip):
                    sent += 1

    if sent == 0:
        # No usable interface found (or psutil unavailable): fall back to the
        # original unbound global broadcast rather than failing outright.
        for wol_port in WOL_PORTS:
            if _send(packet, GLOBAL_BROADCAST, wol_port):
                sent += 1

    if sent == 0:
        raise OSError("Could not send magic packet on any interface")
    return True
