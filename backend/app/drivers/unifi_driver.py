"""
Complete UniFi Controller Driver Implementation
================================================
Implements UniFi Controller API integration for Ubiquiti devices.
Supports: AP management, client control, PoE management, guest networks.
"""

import requests
import urllib3
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

from .base_driver import BaseNetworkDriver

# Disable SSL warnings for self-signed certificates (UniFi uses self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UniFiDriver(BaseNetworkDriver):
    """
    Production-ready UniFi Controller driver.
    Communicates with UniFi Controller REST API.
    """

    def __init__(self, device_config: Dict[str, Any], mock_mode: bool = False):
        """
        Initialize UniFi driver.
        
        Args:
            device_config: Dict containing:
                - host: Controller IP/hostname
                - port: Controller port (default 8443)
                - username: Controller username
                - password: Controller password
                - site: Site ID (default 'default')
                - device_mac: MAC address of the specific device this driver manages
            mock_mode: If True, return mock data
        """
        super().__init__(device_config, mock_mode)
        self.base_url = f"https://{device_config['host']}:{device_config.get('port', 8443)}"
        self.site = device_config.get('site', 'default')
        self.device_mac = device_config.get('device_mac', '')
        self.session = None
        self.cookies = None
        self.is_unifios = False   # True if controller is UniFi OS / 10.x style
        self.csrf_token = None
        
    def connect(self) -> bool:
        """Authenticate with the UniFi Controller.

        Handles BOTH controller generations:
          - New (UniFi OS / Network 7+/10.x): POST /api/auth/login, and all
            subsequent calls are prefixed with /proxy/network. Requires the
            X-CSRF-Token returned on login for write calls.
          - Legacy: POST /api/login, no proxy prefix.
        Tries the new endpoint first, falls back to legacy on failure.
        """
        if self.mock_mode:
            self.logger.info(f"[MOCK] Connected to UniFi Controller {self.device_config.get('host')}")
            return True

        creds = {
            "username": self.device_config["username"],
            "password": self.device_config["password"],
            "remember": True,
        }
        self.session = requests.Session()

        # --- Attempt 1: legacy style (classic Network Application) ---
        try:
            r = self.session.post(f"{self.base_url}/api/login", json=creds,
                                  verify=False, timeout=10)
            if r.status_code == 200:
                self.is_unifios = False
                self.cookies = r.cookies
                self.logger.info(f"✅ Connected to UniFi Controller {self.device_config['host']} "
                                 f"(legacy API, site={self.site})")
                return True
        except Exception as e:
            self.logger.info(f"Legacy login attempt failed ({e}); trying UniFi OS endpoint")

        # --- Attempt 2: new UniFi OS style ---
        try:
            r = self.session.post(f"{self.base_url}/api/auth/login", json=creds,
                                  verify=False, timeout=10)
            if r.status_code == 200:
                self.is_unifios = True
                self.csrf_token = (r.headers.get("X-CSRF-Token")
                                   or r.headers.get("x-csrf-token"))
                self.cookies = r.cookies
                self.logger.info(f"✅ Connected to UniFi Controller {self.device_config['host']} "
                                 f"(UniFi OS API, site={self.site})")
                return True
            detail = ""
            try:
                detail = r.json().get("meta", {}).get("msg", "")
            except Exception:
                detail = r.text[:120]
            raise ConnectionError(f"Login failed: HTTP {r.status_code} {detail}".strip())
        except ConnectionError:
            raise
        except Exception as e:
            raise ConnectionError(f"UniFi connection failed: {str(e)}")


    def disconnect(self) -> bool:
        """Logout from UniFi Controller."""
        if self.mock_mode:
            self.logger.info("[MOCK] Disconnected from UniFi Controller")
            return True
            
        try:
            if self.session:
                logout_url = f"{self.base_url}/api/logout"
                self.session.post(logout_url, verify=False)
                self.session.close()
                self.logger.info("Disconnected from UniFi Controller")
            return True
        except Exception as e:
            self.logger.error(f"Disconnect error: {str(e)}")
            return False
    
    def _api_request(self, endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Any:
        """
        Make an API request to UniFi Controller.
        
        Args:
            endpoint: API endpoint (e.g., "/api/s/default/stat/device")
            method: HTTP method (GET, POST, PUT, DELETE)
            data: Request body for POST/PUT
            
        Returns:
            Response data
        """
        if self.mock_mode:
            return self._get_mock_response(endpoint)
            
        if not self.session:
            raise ConnectionError("Not connected to UniFi Controller")
        
        # UniFi OS controllers expose the Network app under /proxy/network.
        prefix = "/proxy/network" if self.is_unifios else ""
        url = f"{self.base_url}{prefix}{endpoint}"
        write_headers = {}
        if self.is_unifios and self.csrf_token:
            write_headers["X-CSRF-Token"] = self.csrf_token
        
        try:
            if method == "GET":
                response = self.session.get(url, verify=False, timeout=10)
            elif method == "POST":
                response = self.session.post(url, json=data, headers=write_headers, verify=False, timeout=10)
            elif method == "PUT":
                response = self.session.put(url, json=data, headers=write_headers, verify=False, timeout=10)
            elif method == "DELETE":
                response = self.session.delete(url, headers=write_headers, verify=False, timeout=10)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            
            result = response.json()
            
            # UniFi API wraps data in {"meta": ..., "data": [...]}
            if isinstance(result, dict) and "data" in result:
                return result["data"]
            return result
            
        except requests.exceptions.HTTPError as e:
            # Surface the controller's own error message (e.g. api.err.XXX)
            detail = ""
            try:
                j = e.response.json()
                detail = j.get("meta", {}).get("msg", "") or str(j)[:160]
            except Exception:
                detail = e.response.text[:160]
            self.logger.error(f"HTTP {e.response.status_code} on {url}: {detail}")
            raise ConnectionError(f"UniFi API {e.response.status_code}: {detail}")
        except Exception as e:
            self.logger.error(f"API request failed: {str(e)}")
            raise
    
    # =========================================================================
    # DEVICE MANAGEMENT
    # =========================================================================
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get all devices (APs, Switches, Gateways) in the site."""
        endpoint = f"/api/s/{self.site}/stat/device"
        devices = self._api_request(endpoint)
        
        device_list = []
        for device in devices:
            device_list.append({
                "id": device.get("_id", ""),
                "mac": device.get("mac", ""),
                "name": device.get("name", "Unknown"),
                "model": device.get("model", "Unknown"),
                "type": device.get("type", "Unknown"),
                "ip": device.get("ip", ""),
                "version": device.get("version", ""),
                "state": device.get("state", 0),  # 0=disconnected, 1=connected
                "uptime": device.get("uptime", 0),
                "adopted": device.get("adopted", False)
            })
        
        return device_list
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get a specific device by MAC address."""
        devices = self.get_devices()
        
        for device in devices:
            if device["mac"].lower() == mac_address.lower():
                return device
        
        return None
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get information about all managed devices."""
        devices = self.get_devices()
        
        return {
            "success": True,
            "device_count": len(devices),
            "devices": devices,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # ACCESS POINT CONTROL
    # =========================================================================
    
    def restart_ap(self, device_mac: str) -> Dict[str, Any]:
        """Restart an Access Point."""
        self.logger.warning(f"Restarting AP {device_mac}")
        
        endpoint = f"/api/s/{self.site}/cmd/devmgr"
        data = {
            "cmd": "restart",
            "mac": device_mac
        }
        
        result = self._api_request(endpoint, method="POST", data=data)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "action": "restarted",
            "timestamp": datetime.now().isoformat()
        }
    
    def locate_ap(self, device_mac: str, enable: bool = True) -> Dict[str, Any]:
        """
        Enable/disable locate mode (flashing LED) on an AP.
        
        Args:
            device_mac: Device MAC address
            enable: True to start locate, False to stop
        """
        self.logger.info(f"{'Enabling' if enable else 'Disabling'} locate mode for {device_mac}")
        
        endpoint = f"/api/s/{self.site}/cmd/devmgr"
        data = {
            "cmd": "set-locate",
            "mac": device_mac
        }
        
        # UniFi API doesn't have a direct "disable locate" - it times out automatically
        result = self._api_request(endpoint, method="POST", data=data)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "locate_enabled": enable,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # POE MANAGEMENT
    # =========================================================================
    
    def enable_poe(self, device_mac: str, port_idx: int) -> Dict[str, Any]:
        """
        Enable PoE on a specific port.
        
        Args:
            device_mac: Switch MAC address
            port_idx: Port index (0-based)
        """
        self.logger.info(f"Enabling PoE on device {device_mac}, port {port_idx}")
        
        endpoint = f"/api/s/{self.site}/rest/device/{device_mac}"
        
        # Get current device config
        device = self.get_device_by_mac(device_mac)
        if not device:
            raise ValueError(f"Device {device_mac} not found")
        
        # Update port override
        data = {
            "port_overrides": [
                {
                    "port_idx": port_idx,
                    "poe_mode": "auto"  # auto, pasv24, passthrough, off
                }
            ]
        }
        
        result = self._api_request(endpoint, method="PUT", data=data)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "port": port_idx,
            "action": "poe_enabled",
            "timestamp": datetime.now().isoformat()
        }
    
    def disable_poe(self, device_mac: str, port_idx: int) -> Dict[str, Any]:
        """Disable PoE on a specific port."""
        self.logger.info(f"Disabling PoE on device {device_mac}, port {port_idx}")
        
        endpoint = f"/api/s/{self.site}/rest/device/{device_mac}"
        
        data = {
            "port_overrides": [
                {
                    "port_idx": port_idx,
                    "poe_mode": "off"
                }
            ]
        }
        
        result = self._api_request(endpoint, method="PUT", data=data)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "port": port_idx,
            "action": "poe_disabled",
            "timestamp": datetime.now().isoformat()
        }
    
    def get_poe_status(self, device_mac: str) -> Dict[str, Any]:
        """Get PoE status for all ports on a device."""
        device = self.get_device_by_mac(device_mac)
        
        if not device:
            raise ValueError(f"Device {device_mac} not found")
        
        # Fetch detailed device info
        endpoint = f"/api/s/{self.site}/stat/device/{device_mac}"
        device_detail = self._api_request(endpoint)
        
        port_table = device_detail[0].get("port_table", []) if device_detail else []
        
        poe_ports = []
        for port in port_table:
            if port.get("port_poe", False):
                poe_ports.append({
                    "port_idx": port.get("port_idx", -1),
                    "name": port.get("name", f"Port {port.get('port_idx')}"),
                    "poe_enable": port.get("poe_enable", False),
                    "poe_mode": port.get("poe_mode", "off"),
                    "poe_power": port.get("poe_power", 0),
                    "poe_voltage": port.get("poe_voltage", 0)
                })
        
        return {
            "success": True,
            "device_mac": device_mac,
            "poe_ports": poe_ports,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # CLIENT MANAGEMENT
    # =========================================================================
    
    def get_clients(self) -> List[Dict[str, Any]]:
        """Get all connected clients."""
        endpoint = f"/api/s/{self.site}/stat/sta"
        clients = self._api_request(endpoint)
        
        client_list = []
        for client in clients:
            client_list.append({
                "mac": client.get("mac", ""),
                "hostname": client.get("hostname", client.get("name", "Unknown")),
                "ip": client.get("ip", ""),
                "network": client.get("network", ""),
                "ap_mac": client.get("ap_mac", ""),
                "essid": client.get("essid", ""),
                "channel": client.get("channel", 0),
                "signal": client.get("signal", 0),
                "noise": client.get("noise", 0),
                "tx_rate": client.get("tx_rate", 0),
                "rx_rate": client.get("rx_rate", 0),
                "uptime": client.get("uptime", 0),
                "is_wired": client.get("is_wired", False)
            })
        
        return client_list
    
    def block_client(self, client_mac: str) -> Dict[str, Any]:
        """
        Block a client from the network.
        
        Args:
            client_mac: Client MAC address to block
        """
        self.logger.warning(f"Blocking client {client_mac}")
        
        endpoint = f"/api/s/{self.site}/cmd/stamgr"
        data = {
            "cmd": "block-sta",
            "mac": client_mac
        }
        
        result = self._api_request(endpoint, method="POST", data=data)
        
        return {
            "success": True,
            "client_mac": client_mac,
            "action": "blocked",
            "timestamp": datetime.now().isoformat()
        }
    
    def unblock_client(self, client_mac: str) -> Dict[str, Any]:
        """Unblock a previously blocked client."""
        self.logger.info(f"Unblocking client {client_mac}")
        
        endpoint = f"/api/s/{self.site}/cmd/stamgr"
        data = {
            "cmd": "unblock-sta",
            "mac": client_mac
        }
        
        result = self._api_request(endpoint, method="POST", data=data)
        
        return {
            "success": True,
            "client_mac": client_mac,
            "action": "unblocked",
            "timestamp": datetime.now().isoformat()
        }
    
    def reconnect_client(self, client_mac: str) -> Dict[str, Any]:
        """Force a client to reconnect (disconnect and let it reconnect)."""
        self.logger.info(f"Forcing reconnect for client {client_mac}")
        
        endpoint = f"/api/s/{self.site}/cmd/stamgr"
        data = {
            "cmd": "kick-sta",
            "mac": client_mac
        }
        
        result = self._api_request(endpoint, method="POST", data=data)
        
        return {
            "success": True,
            "client_mac": client_mac,
            "action": "reconnected",
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # WIRELESS NETWORK MANAGEMENT
    # =========================================================================
    
    def get_wlan_groups(self) -> List[Dict[str, Any]]:
        """Get all WLAN (wireless network) configurations."""
        endpoint = f"/api/s/{self.site}/rest/wlanconf"
        wlans = self._api_request(endpoint)
        
        wlan_list = []
        for wlan in wlans:
            wlan_list.append({
                "id": wlan.get("_id", ""),
                "name": wlan.get("name", ""),
                "ssid": wlan.get("x_passphrase", ""),  # This might be hidden
                "enabled": wlan.get("enabled", False),
                "security": wlan.get("security", "open"),
                "wpa_mode": wlan.get("wpa_mode", ""),
                "wpa_enc": wlan.get("wpa_enc", ""),
                "vlan_enabled": wlan.get("vlan_enabled", False),
                "vlan": wlan.get("vlan", "")
            })
        
        return wlan_list
    
    def set_wlan_enabled(self, wlan_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a wireless network (SSID) by its wlanconf id.

        Used by the time-based access policy so Wi-Fi follows the same
        admin-configured schedule as wired access (Proposal Objective 3:
        'SSID schedules on UniFi controllers').
        """
        endpoint = f"/api/s/{self.site}/rest/wlanconf/{wlan_id}"
        result = self._api_request(endpoint, method="PUT",
                                   data={"enabled": bool(enabled)})
        self.logger.info(f"WLAN {wlan_id} -> "
                         f"{'enabled' if enabled else 'disabled'}")
        return {
            "status": "success",
            "wlan_id": wlan_id,
            "enabled": bool(enabled),
            "result": result,
        }

    def set_all_wlans_enabled(self, enabled: bool,
                              skip_keywords: Optional[List[str]] = None) -> Dict[str, Any]:
        """Enable/disable every SSID on the controller, with a safety skip-list.

        skip_keywords: SSID names containing any of these (case-insensitive)
        are left untouched — by default management/admin SSIDs, so a schedule
        can never lock the administrator out of the network.
        """
        skip = [k.lower() for k in (skip_keywords if skip_keywords is not None
                                    else ["mgmt", "management", "admin"])]
        changed, skipped = [], []
        for wlan in self.get_wlan_groups():
            name = (wlan.get("name") or "").strip()
            if any(k in name.lower() for k in skip):
                skipped.append(name)
                continue
            if bool(wlan.get("enabled", False)) == bool(enabled):
                continue  # already in the desired state
            self.set_wlan_enabled(wlan["id"], enabled)
            changed.append(name)
        return {
            "status": "success",
            "action": "enable" if enabled else "disable",
            "changed": changed,
            "skipped": skipped,
        }

    def update_wlan(self, wlan_id: str, *,
                    name: Optional[str] = None,
                    passphrase: Optional[str] = None,
                    vlan: Optional[int] = None,
                    enabled: Optional[bool] = None,
                    security: Optional[str] = None) -> Dict[str, Any]:
        """Modify an existing SSID in place (rename / password / VLAN / security / on-off).

        Legacy UniFi controllers can reject a *partial* wlanconf PUT for some
        fields, so we fetch the current object, merge only what the caller
        supplied, and PUT the whole object back. Same proven endpoint as
        set_wlan_enabled — just more fields. This is what lets UAF own the full
        SSID lifecycle (create / read / toggle / EDIT / DELETE) without ever
        opening the UniFi controller GUI.
        """
        endpoint = f"/api/s/{self.site}/rest/wlanconf/{wlan_id}"

        current = self._api_request(endpoint)          # REST returns a single-item list
        if isinstance(current, list):
            current = current[0] if current else {}
        if not current:
            raise ValueError(f"WLAN {wlan_id} not found on controller")

        patched = dict(current)
        if name is not None:
            patched["name"] = name
        if passphrase is not None:
            patched["x_passphrase"] = passphrase
            patched.setdefault("security", "wpapsk")   # ensure it's a PSK network
        if security is not None:
            patched["security"] = security
        if enabled is not None:
            patched["enabled"] = bool(enabled)
        if vlan is not None:
            if vlan:                                     # tag on a real VLAN id
                patched["vlan_enabled"] = True
                patched["vlan"] = int(vlan)
            else:                                        # 0 / None => clear tagging
                patched["vlan_enabled"] = False
                patched.pop("vlan", None)

        result = self._api_request(endpoint, method="PUT", data=patched)
        self.logger.info(f"WLAN {wlan_id} updated "
                         f"(name={name}, vlan={vlan}, enabled={enabled})")
        return {"status": "success", "wlan_id": wlan_id,
                "name": patched.get("name"), "result": result}

    def delete_wlan(self, wlan_id: str) -> Dict[str, Any]:
        """Permanently remove an SSID from the controller."""
        endpoint = f"/api/s/{self.site}/rest/wlanconf/{wlan_id}"
        result = self._api_request(endpoint, method="DELETE")
        self.logger.info(f"WLAN {wlan_id} deleted")
        return {"status": "success", "wlan_id": wlan_id, "result": result}

    def _default_apgroup_id(self) -> Optional[str]:
        """Resolve the default AP group id from the v2 API.

        This controller exposes AP groups only at /v2/api/site/<site>/apgroups
        (the legacy /rest/apgroup returns InvalidObject). The v2 endpoint returns
        a bare JSON list, not the usual {meta,data} envelope, so we call it
        directly rather than through _api_request.
        """
        if self.mock_mode:
            return "mock-apgroup"
        if not self.session:
            return None
        prefix = "/proxy/network" if self.is_unifios else ""
        url = f"{self.base_url}{prefix}/v2/api/site/{self.site}/apgroups"
        try:
            resp = self.session.get(url, verify=False, timeout=10)
            resp.raise_for_status()
            groups = resp.json()
            if isinstance(groups, list) and groups:
                default = next((g for g in groups
                                if g.get("attr_hidden_id") == "default"
                                or g.get("name") == "All APs"),
                               groups[0])
                return default.get("_id")
        except Exception as e:
            self.logger.info(f"apgroup (v2) lookup failed: {e}")
        return None

    def _default_wlangroup_id(self) -> Optional[str]:
        """Resolve the controller's default WLAN group id.

        Legacy controllers require wlangroup_id on each SSID. The valid groups
        live at /rest/wlangroup (NOT /rest/apgroup, which returns InvalidObject
        on these versions). We prefer the built-in "Default" group.
        """
        try:
            groups = self._api_request(f"/api/s/{self.site}/rest/wlangroup")
            if groups:
                default = next((g for g in groups
                                if g.get("attr_hidden_id") == "Default"
                                or g.get("name") == "Default"),
                               groups[0])
                return default.get("_id")
        except Exception as e:
            self.logger.info(f"wlangroup lookup failed: {e}")
        return None

    def create_guest_network(self, ssid: str, password: str, 
                            guest_portal: bool = False) -> Dict[str, Any]:
        """
        Create a guest wireless network.
        
        Args:
            ssid: Network name
            password: WPA2 password
            guest_portal: Enable guest portal/hotspot
        """
        self.logger.info(f"Creating guest network '{ssid}'")
        
        endpoint = f"/api/s/{self.site}/rest/wlanconf"
        # Minimal, broadly-compatible WLAN payload. We intentionally OMIT
        # wlangroup_id (an empty string is rejected with HTTP 400 on modern
        # controllers; omitting it applies the SSID to the default group) and
        # do NOT set is_guest unless a guest portal was explicitly requested.
        data = {
            "name": ssid,
            "enabled": True,
            "security": "wpapsk",
            "wpa_mode": "wpa2",
            "wpa_enc": "ccmp",
            "x_passphrase": password,
            "is_guest": bool(guest_portal),
        }
        # Legacy controllers require a (populated) wlangroup_id on every SSID.
        # An empty string is rejected; omit it entirely if we cannot resolve one.
        wlangroup = self._default_wlangroup_id()
        if wlangroup:
            data["wlangroup_id"] = wlangroup
        # This controller also requires an AP group on the SSID.
        apgroup = self._default_apgroup_id()
        if apgroup:
            data["ap_group_ids"] = [apgroup]
            data["ap_group_mode"] = "all"
        
        result = self._api_request(endpoint, method="POST", data=data)
        
        return {
            "success": True,
            "ssid": ssid,
            "security": "WPA2",
            "guest_portal": guest_portal,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # STATISTICS & MONITORING
    # =========================================================================
    
    def get_site_stats(self) -> Dict[str, Any]:
        """Get overall site statistics."""
        endpoint = f"/api/s/{self.site}/stat/health"
        stats = self._api_request(endpoint)
        
        return {
            "success": True,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_device_stats(self, device_mac: str) -> Dict[str, Any]:
        """Get statistics for a specific device."""
        endpoint = f"/api/s/{self.site}/stat/device/{device_mac}"
        stats = self._api_request(endpoint)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # PORT CONTROL (for UniFi Switches)
    # =========================================================================
    
    def enable_port(self, port_id: str) -> Dict[str, Any]:
        """
        Enable a switch port.
        
        Args:
            port_id: Port index as string (e.g., "1", "3"). Uses device_mac from config.
        """
        port_idx = int(port_id)
        device_mac = self.device_mac
        self.logger.info(f"Enabling port {port_idx} on device {device_mac}")
        
        endpoint = f"/api/s/{self.site}/rest/device/{device_mac}"
        data = {
            "port_overrides": [
                {
                    "port_idx": port_idx,
                    "portconf_id": "",  # Use default port profile
                    "poe_mode": "auto"
                }
            ]
        }
        
        result = self._api_request(endpoint, method="PUT", data=data)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "port": port_idx,
            "action": "enabled",
            "timestamp": datetime.now().isoformat()
        }
    
    def disable_port(self, port_id: str, reason: str = "Manual shutdown") -> Dict[str, Any]:
        """
        Disable a switch port.
        
        Args:
            port_id: Port index as string (e.g., "1", "3"). Uses device_mac from config.
            reason: Reason for disabling the port.
        """
        port_idx = int(port_id)
        device_mac = self.device_mac
        self.logger.warning(f"Disabling port {port_idx} on {device_mac} - Reason: {reason}")
        
        endpoint = f"/api/s/{self.site}/rest/device/{device_mac}"
        data = {
            "port_overrides": [
                {
                    "port_idx": port_idx,
                    "portconf_id": "",
                    "poe_mode": "off",
                    "name": f"DISABLED: {reason}"
                }
            ]
        }
        
        result = self._api_request(endpoint, method="PUT", data=data)
        
        return {
            "success": True,
            "device_mac": device_mac,
            "port": port_idx,
            "action": "disabled",
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_port_status(self, port_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get status of all ports on a switch (or a specific port).
        
        Args:
            port_id: Optional port index as string. If None, returns all ports.
        """
        device_mac = self.device_mac
        device = self.get_device_by_mac(device_mac)
        
        if not device:
            raise ValueError(f"Device {device_mac} not found")
        
        # Fetch detailed device info
        endpoint = f"/api/s/{self.site}/stat/device/{device_mac}"
        device_detail = self._api_request(endpoint)
        
        port_table = device_detail[0].get("port_table", []) if device_detail else []
        
        interfaces = []
        for port in port_table:
            port_info = {
                "port_idx": port.get("port_idx", -1),
                "name": port.get("name", f"Port {port.get('port_idx')}"),
                "status": "up" if port.get("up", False) else "down",
                "up": port.get("up", False),
                "enabled": port.get("enable", True),
                "speed": port.get("speed", 0),
                "full_duplex": port.get("full_duplex", False),
                "poe_enable": port.get("poe_enable", False),
                "poe_power": port.get("poe_power", 0)
            }
            interfaces.append(port_info)
        
        # Filter to specific port if requested
        if port_id is not None:
            target_idx = int(port_id)
            interfaces = [p for p in interfaces if p["port_idx"] == target_idx]
        
        return {
            "success": True,
            "device_mac": device_mac,
            "interfaces": interfaces,
            "count": len(interfaces),
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # MOCK DATA GENERATORS
    # =========================================================================
    
    def _get_mock_response(self, endpoint: str) -> Any:
        """Generate mock responses for testing."""
        if "stat/device" in endpoint:
            return [
                {
                    "_id": "abc123",
                    "mac": "00:11:22:33:44:55",
                    "name": "AP-Office",
                    "model": "UAP-AC-LITE",
                    "type": "uap",
                    "ip": "192.168.1.50",
                    "version": "6.0.14",
                    "state": 1,
                    "uptime": 86400,
                    "adopted": True,
                    "port_table": []
                },
                {
                    "_id": "def456",
                    "mac": "00:11:22:33:44:56",
                    "name": "Switch-01",
                    "model": "US-8-60W",
                    "type": "usw",
                    "ip": "192.168.1.51",
                    "version": "6.1.12",
                    "state": 1,
                    "uptime": 172800,
                    "adopted": True,
                    "port_table": [
                        {"port_idx": 1, "name": "Port 1", "up": True, "enable": True, "speed": 1000, "full_duplex": True, "port_poe": True, "poe_enable": True, "poe_mode": "auto", "poe_power": 4.2, "poe_voltage": 48.0},
                        {"port_idx": 2, "name": "Port 2", "up": True, "enable": True, "speed": 1000, "full_duplex": True, "port_poe": True, "poe_enable": True, "poe_mode": "auto", "poe_power": 3.8, "poe_voltage": 48.0},
                        {"port_idx": 3, "name": "Port 3", "up": False, "enable": True, "speed": 0, "full_duplex": False, "port_poe": True, "poe_enable": False, "poe_mode": "off", "poe_power": 0, "poe_voltage": 0},
                        {"port_idx": 4, "name": "Port 4", "up": False, "enable": True, "speed": 0, "full_duplex": False, "port_poe": True, "poe_enable": False, "poe_mode": "off", "poe_power": 0, "poe_voltage": 0},
                        {"port_idx": 5, "name": "Port 5", "up": True, "enable": True, "speed": 1000, "full_duplex": True, "port_poe": False, "poe_enable": False, "poe_mode": "off", "poe_power": 0, "poe_voltage": 0},
                        {"port_idx": 6, "name": "Port 6", "up": True, "enable": True, "speed": 1000, "full_duplex": True, "port_poe": False, "poe_enable": False, "poe_mode": "off", "poe_power": 0, "poe_voltage": 0},
                        {"port_idx": 7, "name": "Port 7", "up": False, "enable": False, "speed": 0, "full_duplex": False, "port_poe": True, "poe_enable": False, "poe_mode": "off", "poe_power": 0, "poe_voltage": 0},
                        {"port_idx": 8, "name": "Port 8", "up": True, "enable": True, "speed": 1000, "full_duplex": True, "port_poe": False, "poe_enable": False, "poe_mode": "off", "poe_power": 0, "poe_voltage": 0}
                    ]
                }
            ]
        elif "stat/sta" in endpoint:
            return [
                {
                    "mac": "AA:BB:CC:DD:EE:01",
                    "hostname": "laptop-01",
                    "ip": "192.168.1.100",
                    "ap_mac": "00:11:22:33:44:55",
                    "essid": "Office-WiFi",
                    "signal": -45,
                    "tx_rate": 866000,
                    "rx_rate": 866000,
                    "is_wired": False
                }
            ]
        elif "rest/wlanconf" in endpoint:
            # GET list of SSIDs, or PUT update of one (mock just echoes ok).
            return [
                {"_id": "wlan001", "name": "Office-WiFi", "enabled": True,
                 "security": "wpapsk", "wpa_mode": "wpa2", "wpa_enc": "ccmp",
                 "vlan_enabled": False, "vlan": ""},
                {"_id": "wlan002", "name": "Guest-WiFi", "enabled": True,
                 "security": "wpapsk", "wpa_mode": "wpa2", "wpa_enc": "ccmp",
                 "vlan_enabled": True, "vlan": "20"},
                {"_id": "wlan003", "name": "UAF-Mgmt", "enabled": True,
                 "security": "wpapsk", "wpa_mode": "wpa2", "wpa_enc": "ccmp",
                 "vlan_enabled": False, "vlan": ""},
            ]
        else:
            return []


# Factory function
def create_unifi_driver(device_config: Dict[str, Any], mock_mode: bool = False) -> UniFiDriver:
    """Factory function to create a UniFi driver instance."""
    return UniFiDriver(device_config, mock_mode)