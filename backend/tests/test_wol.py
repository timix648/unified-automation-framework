"""
Tests for the Wake-on-LAN service.
"""
import pytest
from unittest.mock import patch, MagicMock
from app.services.wol import send_magic_packet


class TestWoL:
    @patch("app.services.wol.socket.socket")
    def test_valid_mac_colon(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)

        assert send_magic_packet("AA:BB:CC:DD:EE:FF") is True

        # With no explicit destination the packet is sent out of EVERY live
        # interface, not once to 255.255.255.255. Sending it once lets the
        # routing table pick a single interface, which on a multi-homed host
        # is regularly a virtual adapter with no physical network behind it.
        assert mock_sock.sendto.call_count >= 1

        # Every packet sent must be a well-formed magic packet:
        # 6 x 0xFF followed by 16 repetitions of the target MAC.
        for call in mock_sock.sendto.call_args_list:
            packet = call[0][0]
            assert packet[:6] == b"\xff" * 6
            assert len(packet) == 6 + 6 * 16
            assert packet[6:12] == b"\xaa\xbb\xcc\xdd\xee\xff"
            assert packet[6:] == packet[6:12] * 16

    @patch("app.services.wol.socket.socket")
    def test_valid_mac_dash(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)

        assert send_magic_packet("AA-BB-CC-DD-EE-FF") is True

    def test_invalid_mac_too_short(self):
        with pytest.raises(ValueError):
            send_magic_packet("AA:BB:CC")

    def test_invalid_mac_bad_chars(self):
        with pytest.raises(ValueError):
            send_magic_packet("GG:HH:II:JJ:KK:LL")

    @patch("app.services.wol.socket.socket")
    def test_custom_broadcast_ip(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)

        send_magic_packet("AA:BB:CC:DD:EE:FF", broadcast_ip="10.0.0.255")
        dest = mock_sock.sendto.call_args[0][1]
        assert dest[0] == "10.0.0.255"
        # An explicitly addressed send goes exactly where it was told, once.
        mock_sock.sendto.assert_called_once()


class TestWoLDelivery:
    """The packet must reach the wire on every live interface.

    These patch the interface list so the assertions hold on any machine,
    regardless of the network it happens to be attached to.
    """

    @patch("app.services.wol.get_broadcast_targets")
    @patch("app.services.wol.socket.socket")
    def test_sends_on_every_interface_bound_to_source(self, mock_sock_cls, mock_targets):
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_targets.return_value = [
            ("192.168.1.50", "192.168.1.255"),
            ("172.16.4.9", "172.16.255.255"),
        ]

        send_magic_packet("AA:BB:CC:DD:EE:FF")

        # Bound to each interface's own address, so the routing table cannot
        # divert the packet onto a virtual adapter.
        bound = {c[0][0][0] for c in mock_sock.bind.call_args_list}
        assert bound == {"192.168.1.50", "172.16.4.9"}

        # Each interface's derived subnet broadcast is used.
        destinations = {c[0][1][0] for c in mock_sock.sendto.call_args_list}
        assert "192.168.1.255" in destinations
        assert "172.16.255.255" in destinations

        # Both WoL ports are covered (some NICs listen on 7, not 9).
        ports = {c[0][1][1] for c in mock_sock.sendto.call_args_list}
        assert ports == {9, 7}

    @patch("app.services.wol.get_broadcast_targets")
    @patch("app.services.wol.socket.socket")
    def test_falls_back_when_no_interfaces_found(self, mock_sock_cls, mock_targets):
        """No usable interface (or psutil missing) must not break WoL."""
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_targets.return_value = []

        assert send_magic_packet("AA:BB:CC:DD:EE:FF") is True
        destinations = {c[0][1][0] for c in mock_sock.sendto.call_args_list}
        assert destinations == {"255.255.255.255"}

    def test_broadcast_targets_never_hardcoded(self):
        """Derived from the host's live interfaces, excluding unusable ones."""
        from app.services.wol import get_broadcast_targets
        import ipaddress

        for source_ip, broadcast_ip in get_broadcast_targets():
            ip = ipaddress.IPv4Address(source_ip)
            assert not ip.is_loopback          # 127.x cannot reach a LAN host
            assert not ip.is_link_local        # 169.254.x means unplugged
            # A /32 (e.g. Tailscale) has no broadcast domain and is excluded,
            # so a derived broadcast address is never equal to its own source.
            assert broadcast_ip != source_ip
