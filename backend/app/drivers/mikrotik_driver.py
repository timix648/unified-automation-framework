"""
Complete MikroTik RouterOS Driver Implementation
=================================================
Implements RouterOS API integration for MikroTik devices.
Supports: Interface control, DHCP management, firewall rules, queue management.
"""

import routeros_api
from typing import Dict, List, Optional, Any
from datetime import datetime
import ipaddress

from .base_driver import BaseNetworkDriver


def _truthy(value) -> bool:
    """Normalize a RouterOS flag to a real bool.

    The RouterOS *API* returns booleans as the strings 'true'/'false',
    while Winbox/CLI show 'yes'/'no'. Comparing only to 'yes' (the old bug)
    made disabled/running always read False over the API. Accept all forms.
    """
    return str(value).strip().lower() in ('yes', 'true', '1')


class MikroTikDriver(BaseNetworkDriver):
    """
    Production-ready MikroTik RouterOS driver.
    Uses RouterOS API for efficient programmatic access.
    """

    def __init__(self, device_config: Dict[str, Any], mock_mode: bool = False):
        """
        Initialize MikroTik driver.
        
        Args:
            device_config: Dict containing host, username, password, port (API port, default 8728)
            mock_mode: If True, return mock data
        """
        super().__init__(device_config, mock_mode)
        self.connection = None
        self.api_port = device_config.get('api_port', 8728)
        
    def connect(self) -> bool:
        """Establish API connection to MikroTik device."""
        if self.mock_mode:
            self.logger.info(f"[MOCK] Connected to MikroTik {self.device_config.get('host')}")
            return True
            
        try:
            self.connection = routeros_api.RouterOsApiPool(
                host=self.device_config['host'],
                username=self.device_config['username'],
                password=self.device_config['password'],
                port=self.api_port,
                plaintext_login=True  # Use SSL in production!
            )
            
            # Test connection
            api = self.connection.get_api()
            system_resource = api.get_resource('/system/resource')
            info = system_resource.get()
            
            self.logger.info(f"✅ Connected to MikroTik {self.device_config['host']}")
            self.logger.info(f"   Board: {info[0].get('board-name', 'Unknown')}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ MikroTik connection failed: {str(e)}")
            raise ConnectionError(f"MikroTik connection failed: {str(e)}")
    
    def disconnect(self) -> bool:
        """Close API connection."""
        if self.mock_mode:
            self.logger.info("[MOCK] Disconnected from MikroTik")
            return True
            
        try:
            if self.connection:
                self.connection.disconnect()
                self.logger.info("Disconnected from MikroTik")
            return True
        except Exception as e:
            self.logger.error(f"Disconnect error: {str(e)}")
            return False
    
    def _get_api(self):
        """Get API connection object."""
        if self.mock_mode:
            return None
        if not self.connection:
            raise ConnectionError("Not connected to MikroTik device")
        return self.connection.get_api()
    
    # =========================================================================
    # INTERFACE MANAGEMENT
    # =========================================================================
    
    def enable_port(self, port_id: str) -> Dict[str, Any]:
        """Enable an interface (bridge port, ether port, etc.)."""
        self.logger.info(f"Enabling interface {port_id}")
        
        if self.mock_mode:
            return {
                "success": True,
                "port": port_id,
                "action": "enabled",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            api = self._get_api()
            interface_resource = api.get_resource('/interface')
            
            # Find the interface by name
            interfaces = interface_resource.get(name=port_id)
            
            if not interfaces:
                raise ValueError(f"Interface {port_id} not found")
            
            interface_id = interfaces[0]['id']
            
            # Enable the interface (remove disabled flag)
            interface_resource.set(id=interface_id, disabled='no')
            
            return {
                "success": True,
                "port": port_id,
                "action": "enabled",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to enable port: {str(e)}")
            raise
    
    def disable_port(self, port_id: str, reason: str = "Manual shutdown") -> Dict[str, Any]:
        """Disable an interface."""
        self.logger.warning(f"Disabling interface {port_id} - Reason: {reason}")
        
        if self.mock_mode:
            return {
                "success": True,
                "port": port_id,
                "action": "disabled",
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            api = self._get_api()
            interface_resource = api.get_resource('/interface')
            
            # Find the interface
            interfaces = interface_resource.get(name=port_id)
            
            if not interfaces:
                raise ValueError(f"Interface {port_id} not found")
            
            interface_id = interfaces[0]['id']
            
            # Disable the interface
            interface_resource.set(
                id=interface_id,
                disabled='yes',
                comment=f"DISABLED: {reason} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            return {
                "success": True,
                "port": port_id,
                "action": "disabled",
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to disable port: {str(e)}")
            raise
    
    def get_port_status(self, port_id: Optional[str] = None) -> Dict[str, Any]:
        """Get interface status."""
        if self.mock_mode:
            return self._get_mock_interface_status()
        
        try:
            api = self._get_api()
            interface_resource = api.get_resource('/interface')
            
            if port_id:
                interfaces = interface_resource.get(name=port_id)
            else:
                interfaces = interface_resource.get()
            
            interface_list = []
            for iface in interfaces:
                interface_list.append({
                    "name": iface.get('name', ''),
                    "type": iface.get('type', ''),
                    "disabled": _truthy(iface.get('disabled', 'false')),
                    "running": _truthy(iface.get('running', 'false')),
                    "mac_address": iface.get('mac-address', ''),
                    "comment": iface.get('comment', '')
                })
            
            return {
                "success": True,
                "interfaces": interface_list,
                "count": len(interface_list),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get port status: {str(e)}")
            raise
    
    # =========================================================================
    # DHCP SERVER MANAGEMENT
    # =========================================================================
    
    def create_dhcp_pool(self, pool_name: str, network: str, 
                         gateway: str, dns_servers: List[str]) -> Dict[str, Any]:
        """
        Create a DHCP pool.
        
        Args:
            pool_name: Name for the DHCP pool
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            gateway: Gateway IP address
            dns_servers: List of DNS server IPs
        """
        self.logger.info(f"Creating DHCP pool '{pool_name}' for {network}")
        
        if self.mock_mode:
            return {
                "success": True,
                "pool_name": pool_name,
                "network": network,
                "action": "created"
            }
        
        try:
            api = self._get_api()
            
            # Create IP pool
            ip_pool_resource = api.get_resource('/ip/pool')
            
            # Calculate IP range from CIDR
            net = ipaddress.ip_network(network, strict=False)
            # Use addresses from .10 to .254
            range_str = f"{net.network_address + 10}-{net.broadcast_address - 1}"
            
            # Idempotent: if a pool with this name already exists, reuse it
            # instead of failing (re-running provision should be safe).
            existing = [p for p in ip_pool_resource.get()
                        if p.get("name") == f"{pool_name}-pool"]
            if existing:
                self.logger.info(f"DHCP pool '{pool_name}-pool' already exists — reusing")
            else:
                ip_pool_resource.add(
                    name=f"{pool_name}-pool",
                    ranges=range_str
                )
            
            # Create DHCP network
            dhcp_network_resource = api.get_resource('/ip/dhcp-server/network')
            # Idempotent: skip if a DHCP network for this subnet already exists.
            net_exists = [n for n in dhcp_network_resource.get()
                          if n.get('address') == network]
            if net_exists:
                self.logger.info(f"DHCP network {network} already exists — reusing")
            else:
                dhcp_network_resource.add(
                    address=network,
                    gateway=gateway,
                    dns_server=','.join(dns_servers),
                    comment=f"Created by UAF - {datetime.now().strftime('%Y-%m-%d')}"
                )
            
            self.logger.info(f"✅ DHCP pool '{pool_name}' created successfully")
            
            return {
                "success": True,
                "pool_name": pool_name,
                "network": network,
                "gateway": gateway,
                "dns_servers": dns_servers,
                "ip_range": range_str,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create DHCP pool: {str(e)}")
            raise
    
    def get_dhcp_leases(self) -> List[Dict[str, Any]]:
        """Get active DHCP leases."""
        if self.mock_mode:
            return self._get_mock_dhcp_leases()
        
        try:
            api = self._get_api()
            lease_resource = api.get_resource('/ip/dhcp-server/lease')
            leases = lease_resource.get()
            
            lease_list = []
            for lease in leases:
                lease_list.append({
                    "address": lease.get('address', ''),
                    "mac_address": lease.get('mac-address', ''),
                    "hostname": lease.get('host-name', 'Unknown'),
                    "server": lease.get('server', ''),
                    "status": lease.get('status', ''),
                    "expires_after": lease.get('expires-after', '')
                })
            
            return lease_list
            
        except Exception as e:
            self.logger.error(f"Failed to get DHCP leases: {str(e)}")
            raise
    
    # =========================================================================
    # FIREWALL RULES
    # =========================================================================
    
    def add_firewall_rule(self, chain: str, action: str, 
                         src_address: Optional[str] = None,
                         dst_address: Optional[str] = None,
                         protocol: Optional[str] = None,
                         dst_port: Optional[str] = None,
                         comment: str = "") -> Dict[str, Any]:
        """
        Add a firewall filter rule.
        
        Args:
            chain: Chain name (input, forward, output)
            action: Action (accept, drop, reject)
            src_address: Source IP/network (optional)
            dst_address: Destination IP/network (optional)
            protocol: Protocol (tcp, udp, icmp, etc.) (optional)
            dst_port: Destination port (optional)
            comment: Rule comment
        """
        self.logger.info(f"Adding firewall rule: {chain}/{action}")
        
        if self.mock_mode:
            return {
                "success": True,
                "chain": chain,
                "action": action,
                "rule_created": True
            }
        
        try:
            api = self._get_api()
            firewall_resource = api.get_resource('/ip/firewall/filter')
            
            rule_params = {
                'chain': chain,
                'action': action,
                'comment': comment or f"UAF Rule - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            }
            
            if src_address:
                rule_params['src-address'] = src_address
            if dst_address:
                rule_params['dst-address'] = dst_address
            if protocol:
                rule_params['protocol'] = protocol
            if dst_port:
                rule_params['dst-port'] = dst_port
            
            firewall_resource.add(**rule_params)
            
            self.logger.info(f"✅ Firewall rule added successfully")
            
            return {
                "success": True,
                "chain": chain,
                "action": action,
                "parameters": rule_params,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to add firewall rule: {str(e)}")
            raise
    
    def get_firewall_rules(self, chain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get firewall filter rules."""
        if self.mock_mode:
            return self._get_mock_firewall_rules()
        
        try:
            api = self._get_api()
            firewall_resource = api.get_resource('/ip/firewall/filter')
            
            if chain:
                rules = firewall_resource.get(chain=chain)
            else:
                rules = firewall_resource.get()
            
            rule_list = []
            for rule in rules:
                rule_list.append({
                    "id": rule.get('id', ''),
                    "chain": rule.get('chain', ''),
                    "action": rule.get('action', ''),
                    "src_address": rule.get('src-address', 'any'),
                    "dst_address": rule.get('dst-address', 'any'),
                    "protocol": rule.get('protocol', 'any'),
                    "dst_port": rule.get('dst-port', 'any'),
                    "disabled": _truthy(rule.get('disabled', 'false')),
                    "comment": rule.get('comment', '')
                })
            
            return rule_list
            
        except Exception as e:
            self.logger.error(f"Failed to get firewall rules: {str(e)}")
            raise
    
    def block_ip_address(self, ip_address: str, reason: str = "Security violation") -> Dict[str, Any]:
        """
        Block an IP address using firewall rule.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
        """
        self.logger.warning(f"Blocking IP {ip_address} - Reason: {reason}")
        
        return self.add_firewall_rule(
            chain="forward",
            action="drop",
            src_address=ip_address,
            comment=f"BLOCKED: {reason} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )
    
    # =========================================================================
    # QUEUE MANAGEMENT (QoS/Traffic Shaping)
    # =========================================================================
    
    def create_simple_queue(self, name: str, target: str, 
                           max_upload: str, max_download: str) -> Dict[str, Any]:
        """
        Create a simple queue for bandwidth management.
        
        Args:
            name: Queue name
            target: Target IP/network
            max_upload: Upload limit (e.g., "1M", "512k")
            max_download: Download limit
        """
        self.logger.info(f"Creating queue '{name}' for {target}")
        
        if self.mock_mode:
            return {
                "success": True,
                "name": name,
                "target": target
            }
        
        try:
            api = self._get_api()
            queue_resource = api.get_resource('/queue/simple')
            
            queue_resource.add(
                name=name,
                target=target,
                max_limit=f"{max_upload}/{max_download}",
                comment=f"Created by UAF - {datetime.now().strftime('%Y-%m-%d')}"
            )
            
            self.logger.info(f"✅ Queue '{name}' created")
            
            return {
                "success": True,
                "name": name,
                "target": target,
                "max_upload": max_upload,
                "max_download": max_download,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create queue: {str(e)}")
            raise
    
    # =========================================================================
    # DEVICE INFORMATION
    # =========================================================================
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get device information."""
        if self.mock_mode:
            return self._get_mock_device_info()
        
        try:
            api = self._get_api()
            
            # Get system resource info
            resource = api.get_resource('/system/resource')
            resource_info = resource.get()[0]
            
            # Get system identity
            identity = api.get_resource('/system/identity')
            identity_info = identity.get()[0]
            
            # Get RouterOS version
            routerboard = api.get_resource('/system/routerboard')
            routerboard_info = routerboard.get()[0]
            
            return {
                "success": True,
                "device_info": {
                    "hostname": identity_info.get('name', 'Unknown'),
                    "board_name": resource_info.get('board-name', 'Unknown'),
                    "model": routerboard_info.get('model', 'Unknown'),
                    "version": resource_info.get('version', 'Unknown'),
                    "architecture": resource_info.get('architecture-name', 'Unknown'),
                    "uptime": resource_info.get('uptime', 'Unknown'),
                    "cpu_load": resource_info.get('cpu-load', 'Unknown'),
                    "free_memory": resource_info.get('free-memory', 'Unknown'),
                    "total_memory": resource_info.get('total-memory', 'Unknown')
                },
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get device info: {str(e)}")
            raise
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics (temperature, voltage, etc.)."""
        if self.mock_mode:
            return {
                "success": True,
                "health": {
                    "temperature": "45C",
                    "voltage": "12.5V"
                }
            }
        
        try:
            api = self._get_api()
            health_resource = api.get_resource('/system/health')
            health_info = health_resource.get()
            
            if health_info:
                health_data = health_info[0]
            else:
                health_data = {"note": "No health data available on this device"}
            
            return {
                "success": True,
                "health": health_data,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system health: {str(e)}")
            # Not all devices have health monitoring
            return {
                "success": True,
                "health": {"note": "Health monitoring not available"},
                "timestamp": datetime.now().isoformat()
            }
    
    # =========================================================================
    # WIRELESS (for hAP devices)
    # =========================================================================
    
    def get_wireless_clients(self) -> List[Dict[str, Any]]:
        """Get connected wireless clients."""
        if self.mock_mode:
            return self._get_mock_wireless_clients()
        
        try:
            api = self._get_api()
            wireless_resource = api.get_resource('/interface/wireless/registration-table')
            clients = wireless_resource.get()
            
            client_list = []
            for client in clients:
                client_list.append({
                    "interface": client.get('interface', ''),
                    "mac_address": client.get('mac-address', ''),
                    "signal_strength": client.get('signal-strength', ''),
                    "tx_rate": client.get('tx-rate', ''),
                    "rx_rate": client.get('rx-rate', ''),
                    "uptime": client.get('uptime', '')
                })
            
            return client_list
            
        except Exception as e:
            self.logger.error(f"Failed to get wireless clients: {str(e)}")
            # Device might not have wireless
            return []
    
    # =========================================================================
    # MOCK DATA GENERATORS
    # =========================================================================
    
    def _get_mock_interface_status(self) -> Dict[str, Any]:
        """Mock interface status."""
        return {
            "success": True,
            "interfaces": [
                {"name": "ether1", "type": "ether", "disabled": False, "running": True, "mac_address": "00:11:22:33:44:55"},
                {"name": "ether2", "type": "ether", "disabled": False, "running": True, "mac_address": "00:11:22:33:44:56"},
                {"name": "ether3", "type": "ether", "disabled": True, "running": False, "mac_address": "00:11:22:33:44:57"},
                {"name": "wlan1", "type": "wlan", "disabled": False, "running": True, "mac_address": "00:11:22:33:44:58"}
            ],
            "count": 4,
            "timestamp": datetime.now().isoformat()
        }
    
    def _get_mock_dhcp_leases(self) -> List[Dict[str, Any]]:
        """Mock DHCP leases."""
        return [
            {"address": "192.168.1.100", "mac_address": "AA:BB:CC:DD:EE:01", "hostname": "laptop-01", "status": "bound"},
            {"address": "192.168.1.101", "mac_address": "AA:BB:CC:DD:EE:02", "hostname": "phone-01", "status": "bound"},
            {"address": "192.168.1.102", "mac_address": "AA:BB:CC:DD:EE:03", "hostname": "tablet-01", "status": "bound"}
        ]
    
    def _get_mock_firewall_rules(self) -> List[Dict[str, Any]]:
        """Mock firewall rules."""
        return [
            {"id": "*1", "chain": "input", "action": "accept", "protocol": "icmp", "comment": "Allow ICMP"},
            {"id": "*2", "chain": "forward", "action": "accept", "src_address": "192.168.1.0/24", "comment": "Allow LAN"},
            {"id": "*3", "chain": "forward", "action": "drop", "src_address": "10.0.0.50", "comment": "BLOCKED: Security violation"}
        ]
    
    def _get_mock_device_info(self) -> Dict[str, Any]:
        """Mock device info."""
        return {
            "success": True,
            "device_info": {
                "hostname": "MikroTik-Lab",
                "board_name": "hAP lite",
                "model": "RB941-2nD",
                "version": "6.49.7",
                "uptime": "2w3d14h25m",
                "cpu_load": "5%",
                "free_memory": "48MB",
                "total_memory": "64MB"
            },
            "timestamp": datetime.now().isoformat()
        }
    
    def _get_mock_wireless_clients(self) -> List[Dict[str, Any]]:
        """Mock wireless clients."""
        return [
            {"mac_address": "AA:BB:CC:DD:EE:04", "signal_strength": "-45dBm", "tx_rate": "54Mbps", "rx_rate": "54Mbps"},
            {"mac_address": "AA:BB:CC:DD:EE:05", "signal_strength": "-62dBm", "tx_rate": "48Mbps", "rx_rate": "36Mbps"}
        ]


# Factory function
def create_mikrotik_driver(device_config: Dict[str, Any], mock_mode: bool = False) -> MikroTikDriver:
    """Factory function to create a MikroTik driver instance."""
    return MikroTikDriver(device_config, mock_mode)