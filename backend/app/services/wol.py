"""
UAF Wake-on-LAN Service
=========================
Sends WoL Magic Packets to power on devices remotely.

FIX: Rewrote magic packet construction for clarity.
Old code: bytes.fromhex("F" * 12 + mac_clean * 16)
This *worked* but was confusing — it relied on the coincidence that
"F" * 12 == "FFFFFFFFFFFF" which decodes to 6 bytes of 0xFF.
New code makes the structure explicit: 6 bytes of 0xFF + MAC repeated 16 times.
"""

import socket


def send_magic_packet(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9):
    """
    Sends a Wake-on-LAN (WoL) Magic Packet to turn on a device.
    
    Magic Packet format: 6 bytes of 0xFF followed by 16 repetitions of the target MAC address.
    
    Args:
        mac_address: Target MAC address (formats: "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF")
        broadcast_ip: Broadcast address to send the packet to (default: 255.255.255.255)
        port: UDP port to send on (default: 9, the standard WoL port)
    
    Returns:
        True if the packet was sent successfully
    
    Raises:
        ValueError: If the MAC address format is invalid
    """
    # 1. Clean the MAC address (remove : or -)
    mac_clean = mac_address.replace(":", "").replace("-", "").upper()

    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        raise ValueError(f"Invalid MAC address format: {mac_address}")

    # 2. Build the Magic Packet:
    #    - 6 bytes of 0xFF (the "sync stream")
    #    - 16 repetitions of the 6-byte target MAC address
    sync_stream = b'\xFF' * 6
    mac_bytes = bytes.fromhex(mac_clean)
    magic_packet = sync_stream + (mac_bytes * 16)

    # 3. Broadcast it to the local network via UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, (broadcast_ip, port))

    return True
