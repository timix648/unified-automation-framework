"""
UAF Base Network Driver (Abstraction Layer)
=============================================
Every vendor driver (Cisco, MikroTik, UniFi) MUST implement these methods.
This is the "Vendor-Agnostic Abstraction Layer" from the project proposal.

FIXED:
- Renamed class from NetworkDriver → BaseNetworkDriver (all 3 drivers import this name)
- Changed constructor to accept device_config: Dict (matches all 3 driver constructors)
- Added concrete bridge methods: shutdown_port() → disable_port(), get_interfaces() → get_port_status()
  This solves the mismatch where the API/kill-switch call shutdown_port/get_interfaces 
  but the drivers implement disable_port/get_port_status
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime


class BaseNetworkDriver(ABC):
    """
    The Universal Abstraction Layer.
    Every vendor driver (Cisco, MikroTik, UniFi) MUST implement these methods.
    """

    def __init__(self, device_config: Dict[str, Any], mock_mode: bool = False):
        """
        Initialize the base driver.

        Args:
            device_config: Dict containing host, username, password, and vendor-specific keys.
            mock_mode: If True, return mock data instead of real device interaction.
        """
        self.device_config = device_config
        self.mock_mode = mock_mode
        self.connected = False
        self.logger = logging.getLogger(self.__class__.__name__)

    # =========================================================================
    # CONNECTION MANAGEMENT (Abstract - every driver MUST implement)
    # =========================================================================

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the device."""
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """Close the connection."""
        pass

    # =========================================================================
    # PORT / INTERFACE CONTROL (Abstract - every driver MUST implement)
    # =========================================================================

    @abstractmethod
    def enable_port(self, port_id: str) -> Dict[str, Any]:
        """Re-enable a port (e.g., after threat is cleared)."""
        pass

    @abstractmethod
    def disable_port(self, port_id: str, reason: str = "Manual shutdown") -> Dict[str, Any]:
        """Disable a specific port. This is the actual vendor implementation."""
        pass

    @abstractmethod
    def get_port_status(self, port_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get status of one or all interfaces.
        Must return a dict containing an 'interfaces' key with a list of interface dicts.
        """
        pass

    # =========================================================================
    # BRIDGE METHODS - These translate the API-layer calls to driver methods
    # The API, Kill-Switch, Scheduler, and Monitor call these names, but the
    # actual vendor drivers implement disable_port() and get_port_status().
    # =========================================================================

    def shutdown_port(self, port_id: str) -> Dict[str, Any]:
        """
        The 'Kill-Switch' action.
        Called by: endpoints.py, kill_switch.py, scheduler.py
        Delegates to: disable_port() which each vendor driver implements.
        """
        return self.disable_port(port_id, reason="Kill-Switch: Security violation")

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """
        Return a VENDOR-NORMALIZED list of interfaces.
        Called by: endpoints.py, monitor.py, and the dashboard frontend.
        Delegates to: get_port_status() which each vendor driver implements.

        Every driver reports interfaces with different keys (MikroTik:
        name/disabled, Cisco: interface/status, UniFi: name/enabled). The
        frontend and monitor expect ONE shape, so we normalize every entry to
        guarantee these canonical keys are always present:
            - name (str)
            - disabled (bool)   # administrative state
            - mac_address (str)
        Original vendor keys are preserved alongside, so existing callers are
        unaffected.
        """
        try:
            result = self.get_port_status()
            raw = result.get("interfaces", []) if isinstance(result, dict) else []
            return [self._normalize_interface(itf) for itf in raw]
        except Exception as e:
            self.logger.error(f"get_interfaces failed: {str(e)}")
            return []

    # Status strings that mean the port is administratively/effectively down.
    # NOTE: a link-down-but-admin-up port (Cisco 'notconnect') is NOT disabled.
    _ADMIN_DOWN_STATUSES = {
        "disabled", "err-disabled", "errdisable",
        "admin down", "administratively down", "shutdown",
    }

    @staticmethod
    def _coerce_bool(value) -> bool:
        """Accept real bools or vendor string flags ('yes'/'true'/'up'/...)."""
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("yes", "true", "1", "up", "enabled")

    @classmethod
    def _normalize_interface(cls, itf: Dict[str, Any]) -> Dict[str, Any]:
        """Map any vendor's interface dict onto the canonical schema."""
        out = dict(itf)  # preserve all original keys for backward compatibility

        # --- name: MikroTik/UniFi use 'name', Cisco uses 'interface' ---
        name = itf.get("name") or itf.get("interface") or itf.get("port")
        if not name and "port_idx" in itf:
            name = f"Port {itf.get('port_idx')}"
        out["name"] = name or ""

        # --- disabled (administrative state), in order of reliability ---
        if isinstance(itf.get("disabled"), bool):          # MikroTik
            disabled = itf["disabled"]
        elif "disabled" in itf:                             # string form
            disabled = cls._coerce_bool(itf["disabled"])
        elif "enabled" in itf:                              # UniFi admin flag
            disabled = not cls._coerce_bool(itf["enabled"])
        elif "status" in itf:                               # Cisco status word
            disabled = str(itf["status"]).strip().lower() in cls._ADMIN_DOWN_STATUSES
        else:
            disabled = False
        out["disabled"] = disabled

        # --- mac_address: MikroTik 'mac_address', UniFi 'mac', Cisco none ---
        out["mac_address"] = itf.get("mac_address") or itf.get("mac") or ""
        return out

    # =========================================================================
    # OPTIONAL METHODS (Concrete drivers can override as needed)
    # =========================================================================

    def get_device_info(self) -> Dict[str, Any]:
        """Get basic device information. Override in subclass for real data."""
        return {
            "host": self.device_config.get("host", "unknown"),
            "mock_mode": self.mock_mode,
            "driver": self.__class__.__name__,
            "timestamp": datetime.now().isoformat()
        }

    def get_mac_address_table(self, vlan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get MAC address table. Override in subclass."""
        return []

    def create_vlan(self, vlan_id: int, vlan_name: str) -> Dict[str, Any]:
        """Create a VLAN. Override in subclass."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support VLAN creation")

    def configure_port_security(self, port_id: str, max_mac: int = 1,
                                violation_action: str = "shutdown") -> Dict[str, Any]:
        """Configure port security. Override in subclass."""
        raise NotImplementedError(f"{self.__class__.__name__} does not support port security config")


# Legacy alias for backward compatibility (in case anyone imports NetworkDriver)
NetworkDriver = BaseNetworkDriver