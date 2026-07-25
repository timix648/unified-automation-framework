"""
Complete Cisco IOS/IOS-XE Driver Implementation
================================================
Implements all vendor-specific logic for Cisco devices using Netmiko.
Supports: Port control, VLAN management, MAC address queries, port security, and more.
"""

from netmiko import ConnectHandler
from typing import Dict, List, Optional, Any
import re
import time
from datetime import datetime

from .base_driver import BaseNetworkDriver


def _enable_legacy_ssh_algorithms():
    """Re-enable the legacy SSH algorithms that old IOS offers but modern
    Paramiko (3.x) disables by default.

    A Catalyst 2960 on IOS 12.2 only offers diffie-hellman-group14-sha1 (kex),
    ssh-rsa (host key), aes*-cbc (ciphers) and hmac-sha1 (MAC). Paramiko 3.x
    drops all of these from its defaults, so Netmiko fails with
    'no matching key exchange / cipher / mac / host key found'. We only APPEND
    the legacy algorithms to Paramiko's preferred lists, so modern devices still
    negotiate modern algorithms first — this just lets old gear connect.
    """
    try:
        import paramiko

        def _extend(attr, extra):
            cur = getattr(paramiko.Transport, attr, ())
            merged = tuple(cur) + tuple(a for a in extra if a not in cur)
            setattr(paramiko.Transport, attr, merged)

        _extend("_preferred_kex", ("diffie-hellman-group14-sha1",
                                   "diffie-hellman-group-exchange-sha1",
                                   "diffie-hellman-group1-sha1"))
        _extend("_preferred_ciphers", ("aes128-cbc", "aes192-cbc",
                                       "aes256-cbc", "3des-cbc"))
        _extend("_preferred_macs", ("hmac-sha1", "hmac-sha1-96",
                                    "hmac-md5", "hmac-md5-96"))
        _extend("_preferred_keys", ("ssh-rsa",))
    except Exception:
        # If paramiko internals change, fail open — modern devices unaffected.
        pass


class CiscoIOSDriver(BaseNetworkDriver):
    """
    Production-ready Cisco IOS/IOS-XE driver.
    Handles SSH connections, CLI command execution, and configuration parsing.
    """

    def __init__(self, device_config: Dict[str, Any], mock_mode: bool = False):
        """
        Initialize Cisco driver.
        
        Args:
            device_config: Dict containing host, username, password, secret
            mock_mode: If True, return mock data instead of real device interaction
        """
        super().__init__(device_config, mock_mode)
        self.device_type = "cisco_ios"
        self.connection = None
        
    def connect(self) -> bool:
        print(f"🔎 DEBUG cisco connect(): mock_mode={self.mock_mode} host={self.device_config.get('host')}")
        """Establish SSH connection to Cisco device."""
        if self.mock_mode:
            self.logger.info(f"[MOCK] Connected to Cisco device {self.device_config.get('host')}")
            return True
            
        try:
            # Old IOS (e.g. 12.2 on a 2960) only offers legacy SSH algorithms
            # that modern Paramiko disables by default; re-enable them so the
            # connection can negotiate. Safe: modern devices still prefer modern.
            _enable_legacy_ssh_algorithms()

            device_params = {
                'device_type': self.device_type,
                'host': self.device_config['host'],
                'username': self.device_config['username'],
                'password': self.device_config['password'],
                'secret': self.device_config.get('secret', ''),  # Enable password
                'port': self.device_config.get('port', 22),
                'timeout': 30,
                'session_timeout': 60,
                'auth_timeout': 30,
                'banner_timeout': 15,
                # Old/slow IOS (2960 on 12.2) returns prompts slowly and limits
                # concurrent SSH sessions. Give Netmiko more patience so a slow
                # prompt isn't mistaken for a failure ("Pattern not detected").
                'read_timeout_override': 30,
                'global_delay_factor': 2,
                # Let Paramiko fall back to the ssh-rsa host key old switches use
                # (it otherwise insists on the rsa-sha2 variants they don't have).
                'disabled_algorithms': {'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']},
            }

            # The 2960 can refuse a brand-new SSH session while it's still busy
            # with another. Retry the connect a few times so a momentary
            # "TCP connection failed" doesn't abort a kill-switch.
            last_err = None
            for attempt in range(3):
                try:
                    self.connection = ConnectHandler(**device_params)
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    time.sleep(2 * (attempt + 1))  # 2s, then 4s, then 6s
            if last_err is not None:
                raise last_err
            
            # Enter enable mode if secret is provided
            if device_params['secret']:
                self.connection.enable()
                
            self.logger.info(f"Connected to Cisco device {self.device_config['host']}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Cisco device: {str(e)}")
            raise ConnectionError(f"Cisco connection failed: {str(e)}")
    
    def disconnect(self) -> bool:
        """Close SSH connection."""
        if self.mock_mode:
            self.logger.info("[MOCK] Disconnected from Cisco device")
            return True
            
        try:
            if self.connection:
                self.connection.disconnect()
                self.logger.info("Disconnected from Cisco device")
            return True
        except Exception as e:
            self.logger.error(f"Error during disconnect: {str(e)}")
            return False
    
    def _execute_command(self, command: str, enable_mode: bool = False) -> str:
        """
        Execute a single command and return output.
        
        Args:
            command: CLI command to execute
            enable_mode: If True, ensure we're in enable mode
            
        Returns:
            Command output as string
        """
        if self.mock_mode:
            return self._get_mock_output(command)
            
        if not self.connection:
            raise ConnectionError("Not connected to device")
            
        try:
            if enable_mode and not self.connection.check_enable_mode():
                self.connection.enable()
                
            output = self.connection.send_command(command, delay_factor=2, read_timeout=45)
            print(f"🔎 RAW send_command({command!r}) ->\n{output[:400]}\n--- end raw ---")
            return output
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            raise
    
    def _execute_config_commands(self, commands: List[str]) -> str:
        """
        Execute multiple configuration commands.
        
        Args:
            commands: List of configuration commands
            
        Returns:
            Command output
        """
        if self.mock_mode:
            return f"[MOCK] Executed config commands: {commands}"
            
        if not self.connection:
            raise ConnectionError("Not connected to device")
            
        try:
            # Ensure we're in enable mode
            if not self.connection.check_enable_mode():
                self.connection.enable()
                
            # Slow legacy switches (e.g. 2960) can be sluggish returning the
            # config prompt; without a generous read_timeout Netmiko raises
            # 'Pattern not detected' and the change is reported as failed even
            # though it often applied. cmd_verify=False stops Netmiko from
            # waiting to echo each command back (another slow-switch stall).
            output = self.connection.send_config_set(
                commands,
                read_timeout=60,
                delay_factor=2,
                cmd_verify=False,
            )
            
            # Save configuration
            self.connection.save_config()
            
            self.logger.info(f"Config commands executed and saved")
            return output
            
        except Exception as e:
            self.logger.error(f"Config execution failed: {str(e)}")
            raise
    
    
    def enable_port(self, port_id: str) -> Dict[str, Any]:
        """Enable a specific interface."""
        self.logger.info(f"Enabling port {port_id}")
        
        commands = [
            f"interface {port_id}",
            "no shutdown",
            f"description Enabled by UAF at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "port": port_id,
            "action": "enabled",
            "timestamp": datetime.now().isoformat(),
            "output": output
        }
    
    def disable_port(self, port_id: str, reason: str = "Manual shutdown") -> Dict[str, Any]:
        """Disable a specific interface."""
        self.logger.warning(f"Disabling port {port_id} - Reason: {reason}")
        
        commands = [
            f"interface {port_id}",
            "shutdown",
            f"description *** DISABLED: {reason} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "port": port_id,
            "action": "disabled",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "output": output
        }
    
    def get_port_status(self, port_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get status of one or all interfaces.
        
        Args:
            port_id: Specific interface (e.g., "GigabitEthernet0/1") or None for all
            
        Returns:
            Dict with interface status information
        """
        if port_id:
            command = f"show interfaces {port_id} status"
        else:
            command = "show interfaces status"
            
        output = self._execute_command(command)
        print(f"🔎 GET_PORT_STATUS got {len(output)} chars; first line: {output.splitlines()[0] if output.splitlines() else 'EMPTY'!r}")
        
        # Parse output
        interfaces = self._parse_interface_status(output)
        print(f"🔎 GET_PORT_STATUS parsed {len(interfaces)} interfaces: {[i.get('interface') for i in interfaces]}")
        
        return {
            "success": True,
            "interfaces": interfaces,
            "count": len(interfaces),
            "timestamp": datetime.now().isoformat()
        }
    
    # Known values of the Status column in 'show interfaces status'.
    _CISCO_STATUS_WORDS = {
        "connected", "notconnect", "disabled", "err-disabled",
        "monitoring", "faulty", "inactive", "suspended", "sfpabsent",
        "up", "down",
    }

    def _parse_interface_status(self, output: str) -> List[Dict[str, Any]]:
        """Parse 'show interfaces status' output.

        The optional Name (description) column can contain spaces — and UAF
        itself writes multi-word descriptions like '*** DISABLED: ...'. A naive
        positional split then reads the description as the status. So instead we
        locate the Status column by matching a known status keyword, which keeps
        the parse correct no matter how wide the description is.
        """
        interfaces = []
        for line in output.split('\n'):
            if not line.strip() or line.startswith('Port') or line.startswith('---'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue

            port = parts[0]
            # Find the first token after the port that is a known status word.
            status_idx = next(
                (i for i in range(1, len(parts))
                 if parts[i].lower() in self._CISCO_STATUS_WORDS),
                None,
            )
            if status_idx is None:
                status, rest = parts[1], parts[2:]   # fallback: legacy layout
            else:
                status, rest = parts[status_idx], parts[status_idx + 1:]

            interfaces.append({
                "interface": port,
                "name": port,            # canonical alias for the frontend
                "status": status,
                "vlan": rest[0] if len(rest) > 0 else "N/A",
                "duplex": rest[1] if len(rest) > 1 else "N/A",
                "speed": rest[2] if len(rest) > 2 else "N/A",
                "type": " ".join(rest[3:]) if len(rest) > 3 else "N/A",
            })
        return interfaces
    
    def create_vlan(self, vlan_id: int, vlan_name: str) -> Dict[str, Any]:
        """Create a new VLAN."""
        self.logger.info(f"Creating VLAN {vlan_id} with name '{vlan_name}'")
        
        commands = [
            f"vlan {vlan_id}",
            f"name {vlan_name}",
            "exit"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "vlan_id": vlan_id,
            "vlan_name": vlan_name,
            "action": "created",
            "timestamp": datetime.now().isoformat()
        }
    
    def delete_vlan(self, vlan_id: int, ports: Optional[List[str]] = None) -> Dict[str, Any]:
        """Remove a VLAN and (optionally) clear it from the given access ports.

        De-provision counterpart of create_vlan/assign_vlan_to_port. If ports are
        supplied, each port is returned to the default VLAN before the VLAN itself
        is deleted, so no interface is left orphaned on a non-existent VLAN.
        """
        self.logger.info(f"Deleting VLAN {vlan_id} (clearing ports: {ports})")
        commands = []
        for port in (ports or []):
            port = port.strip()
            if not port:
                continue
            commands += [
                f"interface {port}",
                "no switchport access vlan",
                "exit",
            ]
        commands.append(f"no vlan {vlan_id}")
        output = self._execute_config_commands(commands)
        return {
            "success": True,
            "vlan_id": vlan_id,
            "ports_cleared": ports or [],
            "action": "deleted",
            "timestamp": datetime.now().isoformat(),
        }

    def assign_vlan_to_port(self, port_id: str, vlan_id: int, mode: str = "access") -> Dict[str, Any]:
        """
        Assign a VLAN to an interface.
        
        Args:
            port_id: Interface identifier
            vlan_id: VLAN ID to assign
            mode: "access" or "trunk"
        """
        self.logger.info(f"Assigning VLAN {vlan_id} to {port_id} in {mode} mode")
        
        if mode == "access":
            commands = [
                f"interface {port_id}",
                "switchport mode access",
                f"switchport access vlan {vlan_id}",
                "no shutdown"
            ]
        elif mode == "trunk":
            commands = [
                f"interface {port_id}",
                "switchport mode trunk",
                f"switchport trunk allowed vlan {vlan_id}",
                "no shutdown"
            ]
        else:
            raise ValueError(f"Invalid mode: {mode}. Must be 'access' or 'trunk'")
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "port": port_id,
            "vlan_id": vlan_id,
            "mode": mode,
            "timestamp": datetime.now().isoformat()
        }
    
    def configure_uplink_trunk(self, port_id: str, vlan_id: int,
                               native_vlan: int = 1) -> Dict[str, Any]:
        """Make an uplink/infrastructure port a trunk CARRYING an extra VLAN,
        without disturbing existing traffic.

        Safety-critical details (why this exists instead of using
        assign_vlan_to_port(mode="trunk")):
        - Uses 'switchport trunk allowed vlan add <id>' — the plain
          'allowed vlan <id>' form REPLACES the whole allowed list with only
          that VLAN, which would strip VLAN 1 off the uplink and cut
          management to the AP / router behind it.
        - Pins 'switchport trunk native vlan <native_vlan>' (default 1) so all
          existing UNTAGGED traffic (AP management, router management) keeps
          flowing exactly as before the port became a trunk.
        Idempotent: re-running for the same VLAN just re-adds it (IOS treats
        duplicate 'add' as a no-op).
        """
        self.logger.info(f"Trunking {port_id}: add VLAN {vlan_id}, native {native_vlan}")
        if self.mock_mode:
            return {"success": True, "port": port_id, "vlan_added": vlan_id,
                    "native_vlan": native_vlan, "mode": "trunk"}
        commands = [
            f"interface {port_id}",
            "switchport mode trunk",
            f"switchport trunk native vlan {native_vlan}",
            f"switchport trunk allowed vlan add {vlan_id}",
            "no shutdown",
        ]
        output = self._execute_config_commands(commands)
        return {
            "success": True,
            "port": port_id,
            "vlan_added": vlan_id,
            "native_vlan": native_vlan,
            "mode": "trunk",
            "timestamp": datetime.now().isoformat(),
        }

    def remove_vlan_from_trunk(self, port_id: str, vlan_id: int) -> Dict[str, Any]:
        """De-provision counterpart: remove one VLAN from a trunk's allowed list
        (leaves the port a trunk and all other VLANs untouched)."""
        self.logger.info(f"Removing VLAN {vlan_id} from trunk {port_id}")
        if self.mock_mode:
            return {"success": True, "port": port_id, "vlan_removed": vlan_id}
        commands = [
            f"interface {port_id}",
            f"switchport trunk allowed vlan remove {vlan_id}",
        ]
        self._execute_config_commands(commands)
        return {"success": True, "port": port_id, "vlan_removed": vlan_id,
                "timestamp": datetime.now().isoformat()}

    def get_vlans(self) -> List[Dict[str, Any]]:
        """Get all VLANs configured on the device."""
        output = self._execute_command("show vlan brief")
        vlans = self._parse_vlan_brief(output)
        
        return vlans
    
    def clear_vlans(self, keep_vlans: Optional[List[int]] = None) -> Dict[str, Any]:
        """Delete all user VLANs except protected ones.

        Protected by default: VLAN 1 (default), the Cisco-reserved 1002-1005, and
        any VLAN IDs passed in keep_vlans (e.g. the management VLAN UAF connects
        through — never removed, so the management path is preserved). This is the
        "replace mode" clear: it wipes operational VLANs but keeps the lifeline.
        """
        protected = {1, 1002, 1003, 1004, 1005}
        protected.update(int(v) for v in (keep_vlans or []))
        removed = []
        for v in self.get_vlans():
            try:
                vid = int(v.get("vlan_id"))
            except (TypeError, ValueError):
                continue
            if vid in protected:
                continue
            try:
                self._execute_config_commands([f"no vlan {vid}"])
                removed.append(vid)
            except Exception as e:
                self.logger.error(f"Failed to remove VLAN {vid}: {e}")
        return {"success": True, "removed_vlans": removed,
                "protected": sorted(protected),
                "timestamp": datetime.now().isoformat()}

    def _parse_vlan_brief(self, output: str) -> List[Dict[str, Any]]:
        """Parse 'show vlan brief' output."""
        vlans = []
        
        lines = output.split('\n')
        in_vlan_section = False
        
        for line in lines:
            # Skip until we find the VLAN section
            if '---' in line:
                in_vlan_section = True
                continue
                
            if in_vlan_section and line.strip():
                # Example: 1    default                          active    Gi0/1, Gi0/2
                parts = line.split()
                if parts and parts[0].isdigit():
                    vlan_id = parts[0]
                    vlan_name = parts[1] if len(parts) > 1 else "N/A"
                    status = parts[2] if len(parts) > 2 else "unknown"
                    
                    vlans.append({
                        "vlan_id": vlan_id,
                        "name": vlan_name,
                        "status": status
                    })
        
        return vlans
    
    # =========================================================================
    # MAC ADDRESS TABLE
    # =========================================================================
    
    def find_port_for_mac(self, mac_address: str) -> Optional[str]:
        """Discover WHICH switch port a given device's MAC is learned on.

        Replaces hardcoded uplink ports. UAF knows each managed device's MAC
        (from NetBox / the inventory), and the switch already knows which port
        it is reachable through — so the uplink can be DERIVED instead of
        configured. This is what makes stitching survive re-cabling: when the
        router was moved from Fa0/24 to Fa0/15, a hardcoded uplink silently
        trunked the wrong (empty) port while the device sat elsewhere.

        Accepts any MAC format (aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, bare hex)
        and normalises before comparing, since IOS reports dotted-quad.
        Returns the interface name (e.g. "Fa0/24") or None if not learned.
        """
        def _norm(m: str) -> str:
            return re.sub(r'[^0-9a-f]', '', (m or '').lower())

        target = _norm(mac_address)
        if len(target) != 12:
            self.logger.error(f"find_port_for_mac: invalid MAC {mac_address!r}")
            return None
        if self.mock_mode:
            return "Fa0/24"
        try:
            for entry in self.get_mac_address_table():
                if _norm(entry.get("mac_address", "")) == target:
                    port = entry.get("interface")
                    self.logger.info(f"Discovered {mac_address} on port {port}")
                    return port
        except Exception as e:
            self.logger.error(f"find_port_for_mac failed: {e}")
        self.logger.info(f"MAC {mac_address} not found in switch MAC table")
        return None

    def get_mac_address_table(self, vlan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get MAC address table.
        
        Args:
            vlan_id: Optional VLAN filter
            
        Returns:
            List of MAC address entries
        """
        if vlan_id:
            command = f"show mac address-table vlan {vlan_id}"
        else:
            command = "show mac address-table"
            
        output = self._execute_command(command)
        mac_table = self._parse_mac_address_table(output)
        
        return mac_table
    
    def _parse_mac_address_table(self, output: str) -> List[Dict[str, Any]]:
        """Parse MAC address table output."""
        mac_entries = []
        
        lines = output.split('\n')
        for line in lines:
            # Example: 1    001a.2b3c.4d5e    DYNAMIC     Gi0/1
            if re.match(r'\s*\d+\s+[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}', line, re.IGNORECASE):
                parts = line.split()
                if len(parts) >= 4:
                    mac_entries.append({
                        "vlan": parts[0],
                        "mac_address": parts[1],
                        "type": parts[2],
                        "interface": parts[3]
                    })
        
        return mac_entries
    
    # =========================================================================
    # PORT SECURITY
    # =========================================================================
    
    def configure_port_security(self, port_id: str, max_mac: int = 1, 
                               violation_action: str = "shutdown") -> Dict[str, Any]:
        """
        Configure port security on an interface.
        
        Args:
            port_id: Interface identifier
            max_mac: Maximum number of MAC addresses allowed
            violation_action: Action on violation (shutdown, restrict, protect)
        """
        self.logger.info(f"Configuring port security on {port_id}")
        
        commands = [
            f"interface {port_id}",
            "switchport mode access",
            "switchport port-security",
            f"switchport port-security maximum {max_mac}",
            f"switchport port-security violation {violation_action}",
            "switchport port-security mac-address sticky"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "port": port_id,
            "max_mac": max_mac,
            "violation_action": violation_action,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_port_security_status(self, port_id: Optional[str] = None) -> Dict[str, Any]:
        """Get port security status."""
        if port_id:
            command = f"show port-security interface {port_id}"
        else:
            command = "show port-security"
            
        output = self._execute_command(command)
        
        return {
            "success": True,
            "output": output,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # SNMP CONFIGURATION
    # =========================================================================
    
    def configure_snmp_trap(self, trap_server: str, community: str = "public") -> Dict[str, Any]:
        """
        Configure SNMP trap destination for security alerts.
        
        Args:
            trap_server: IP address of trap receiver
            community: SNMP community string
        """
        self.logger.info(f"Configuring SNMP trap to {trap_server}")
        
        commands = [
            f"snmp-server community {community} RO",
            f"snmp-server host {trap_server} version 2c {community}",
            "snmp-server enable traps port-security",
            "snmp-server enable traps config"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "trap_server": trap_server,
            "community": community,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # DEVICE INFORMATION
    # =========================================================================
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get device hostname, model, IOS version, uptime."""
        output = self._execute_command("show version")
        
        info = self._parse_show_version(output)
        
        return {
            "success": True,
            "device_info": info,
            "timestamp": datetime.now().isoformat()
        }
    
    def _parse_show_version(self, output: str) -> Dict[str, Any]:
        """Parse 'show version' output."""
        info = {
            "hostname": "Unknown",
            "model": "Unknown",
            "ios_version": "Unknown",
            "uptime": "Unknown",
            "serial_number": "Unknown"
        }
        
        # Extract hostname
        hostname_match = re.search(r'hostname\s+(\S+)', output, re.IGNORECASE)
        if hostname_match:
            info["hostname"] = hostname_match.group(1)
        
        # Extract model
        model_match = re.search(r'cisco\s+(\S+)\s+\(', output, re.IGNORECASE)
        if model_match:
            info["model"] = model_match.group(1)
        
        # Extract IOS version
        version_match = re.search(r'Version\s+([^,]+)', output)
        if version_match:
            info["ios_version"] = version_match.group(1).strip()
        
        # Extract uptime
        uptime_match = re.search(r'uptime is\s+(.+)', output, re.IGNORECASE)
        if uptime_match:
            info["uptime"] = uptime_match.group(1).strip()
        
        # Extract serial number
        serial_match = re.search(r'Processor board ID\s+(\S+)', output)
        if serial_match:
            info["serial_number"] = serial_match.group(1)
        
        return info
    
    def get_running_config(self) -> str:
        """Get the running configuration."""
        return self._execute_command("show running-config")
    
    # =========================================================================
    # POWER OVER ETHERNET (PoE)
    # =========================================================================
    
    def enable_poe(self, port_id: str) -> Dict[str, Any]:
        """Enable PoE on an interface."""
        self.logger.info(f"Enabling PoE on {port_id}")
        
        commands = [
            f"interface {port_id}",
            "power inline auto"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "port": port_id,
            "action": "poe_enabled",
            "timestamp": datetime.now().isoformat()
        }
    
    def disable_poe(self, port_id: str) -> Dict[str, Any]:
        """Disable PoE on an interface."""
        self.logger.info(f"Disabling PoE on {port_id}")
        
        commands = [
            f"interface {port_id}",
            "power inline never"
        ]
        
        output = self._execute_config_commands(commands)
        
        return {
            "success": True,
            "port": port_id,
            "action": "poe_disabled",
            "timestamp": datetime.now().isoformat()
        }
    
    def get_poe_status(self, port_id: Optional[str] = None) -> Dict[str, Any]:
        """Get PoE status for interface(s)."""
        if port_id:
            command = f"show power inline {port_id}"
        else:
            command = "show power inline"
            
        output = self._execute_command(command)
        
        return {
            "success": True,
            "output": output,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # MOCK DATA GENERATORS
    # =========================================================================
    
    def _get_mock_output(self, command: str) -> str:
        """Generate mock output for testing without real devices."""
        mock_responses = {
            "show interfaces status": """
Port      Name               Status       Vlan       Duplex  Speed Type
Gi0/1                        connected    1          a-full  a-100 10/100/1000BaseTX
Gi0/2                        disabled     1          auto    auto  10/100/1000BaseTX
Gi0/3                        connected    10         a-full  a-100 10/100/1000BaseTX
            """,
            "show vlan brief": """
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi0/1, Gi0/2
10   Management                       active    Gi0/3
20   Guest                            active    
            """,
            "show mac address-table": """
Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    0011.2233.4455    DYNAMIC     Gi0/1
   1    0022.3344.5566    DYNAMIC     Gi0/1
  10    0033.4455.6677    DYNAMIC     Gi0/3
            """,
            "show version": """
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2019 by Cisco Systems, Inc.

ROM: Bootstrap program is C2960 boot loader
Switch-01 uptime is 2 weeks, 3 days, 14 hours, 25 minutes

Cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Processor board ID FOC1234X5Y6
            """
        }
        
        for key, value in mock_responses.items():
            if key in command:
                return value
        
        return f"[MOCK OUTPUT] for command: {command}"


# Factory function for easy instantiation
def create_cisco_driver(device_config: Dict[str, Any], mock_mode: bool = False) -> CiscoIOSDriver:
    """Factory function to create a Cisco driver instance."""
    return CiscoIOSDriver(device_config, mock_mode)
