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
        mock_sock.sendto.assert_called_once()
        packet = mock_sock.sendto.call_args[0][0]
        # Magic packet: 6 x 0xFF + 16 x MAC
        assert packet[:6] == b"\xff" * 6
        assert len(packet) == 6 + 6 * 16

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
