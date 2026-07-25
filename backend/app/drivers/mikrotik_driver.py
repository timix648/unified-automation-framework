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
    
    def create_vlan_segment(self, vlan_id: int, gateway_cidr: str,
                            pool_name: str,
                            uplink_interface: Optional[str] = None) -> Dict[str, Any]:
        """Create the ROUTER side of a VLAN's data path: a VLAN sub-interface on
        the uplink, the gateway IP on it, and a DHCP SERVER INSTANCE bound to it.

        Why this exists: create_dhcp_pool() creates the pool and the
        /ip/dhcp-server/network entry, but RouterOS only *serves* DHCP from a
        server INSTANCE bound to an interface. Without this, provisioned
        segments had scope definitions but no server actually answering on the
        VLAN — clients fell through to the untagged path and got management-
        subnet leases (the observed 192.168.1.199-on-a-provisioned-SSID issue).

        Args:
            vlan_id: 802.1Q VLAN id (e.g. 88)
            gateway_cidr: gateway address WITH prefix, e.g. "192.168.88.1/24"
            pool_name: base segment name; pool is "<pool_name>-pool" (matching
                       create_dhcp_pool's naming)
            uplink_interface: physical interface facing the switch trunk. If
                None, derived as the interface holding the management IP (the
                same derivation used by the clear-protection logic).
        Idempotent: safe to re-run; existing objects are reused.
        """
        vlan_name = f"vlan{vlan_id}"
        if self.mock_mode:
            return {"success": True, "vlan_interface": vlan_name,
                    "gateway": gateway_cidr, "dhcp_server": f"dhcp-{vlan_id}"}
        try:
            api = self._get_api()

            # Resolve the uplink: the physical interface carrying management is,
            # by definition, the one cabled to the switch — derive, don't hardcode.
            if not uplink_interface:
                mgmt_ip = self._mgmt_ip()
                uplink_interface = None
                try:
                    for a in api.get_resource('/ip/address').get():
                        addr = (a.get('address') or '').split('/')[0]
                        if addr == mgmt_ip:
                            uplink_interface = a.get('interface')
                            break
                except Exception as e:
                    self.logger.error(f"uplink derivation failed: {e}")
                if not uplink_interface:
                    raise ValueError("Could not derive uplink interface for VLAN segment")

            # 1. VLAN sub-interface (reuse if present)
            vlan_res = api.get_resource('/interface/vlan')
            existing = [v for v in vlan_res.get() if v.get('name') == vlan_name]
            if existing:
                self.logger.info(f"VLAN interface {vlan_name} exists — reusing")
            else:
                vlan_res.add(name=vlan_name, **{'vlan-id': str(vlan_id),
                                                'interface': uplink_interface})

            # 2. Gateway IP on the VLAN interface (reuse if present)
            addr_res = api.get_resource('/ip/address')
            if not any(a.get('address') == gateway_cidr and a.get('interface') == vlan_name
                       for a in addr_res.get()):
                addr_res.add(address=gateway_cidr, interface=vlan_name,
                             comment=f"UAF VLAN {vlan_id} gateway")

            # 3. DHCP SERVER INSTANCE bound to the VLAN interface, serving the
            #    segment's pool (this is what actually answers DISCOVERs).
            srv_res = api.get_resource('/ip/dhcp-server')
            srv_name = f"dhcp-{vlan_id}"
            if not any(s.get('name') == srv_name for s in srv_res.get()):
                srv_res.add(name=srv_name, interface=vlan_name,
                            **{'address-pool': f"{pool_name}-pool",
                               'disabled': 'no'})

            self.logger.info(f"✅ VLAN {vlan_id} segment live on {uplink_interface} "
                             f"({vlan_name}, gw {gateway_cidr}, server {srv_name})")
            return {"success": True, "vlan_interface": vlan_name,
                    "uplink": uplink_interface, "gateway": gateway_cidr,
                    "dhcp_server": srv_name,
                    "timestamp": datetime.now().isoformat()}
        except Exception as e:
            self.logger.error(f"create_vlan_segment failed: {e}")
            raise

    def delete_vlan_segment(self, vlan_id: int) -> Dict[str, Any]:
        """De-provision counterpart of create_vlan_segment: remove the DHCP
        server instance, gateway address, and VLAN sub-interface for a segment.
        Safe if any piece is already gone."""
        vlan_name = f"vlan{vlan_id}"
        removed = {"server": False, "address": False, "vlan": False}
        if self.mock_mode:
            return {"success": True, "removed": removed}
        try:
            api = self._get_api()
            srv_res = api.get_resource('/ip/dhcp-server')
            for s in srv_res.get():
                if s.get('name') == f"dhcp-{vlan_id}":
                    srv_res.remove(id=s['id']); removed["server"] = True
            addr_res = api.get_resource('/ip/address')
            for a in addr_res.get():
                if a.get('interface') == vlan_name:
                    addr_res.remove(id=a['id']); removed["address"] = True
            vlan_res = api.get_resource('/interface/vlan')
            for v in vlan_res.get():
                if v.get('name') == vlan_name:
                    vlan_res.remove(id=v['id']); removed["vlan"] = True
            return {"success": True, "removed": removed,
                    "timestamp": datetime.now().isoformat()}
        except Exception as e:
            self.logger.error(f"delete_vlan_segment failed: {e}")
            raise

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
    
    def delete_dhcp_network(self, pool_name: str, network: str) -> Dict[str, Any]:
        """Remove the DHCP pool and DHCP-server network created by provisioning.

        De-provision counterpart of create_dhcp_pool. Removes both the IP pool
        (named "<pool_name>-pool") and the /ip/dhcp-server/network entry for the
        given subnet. Safe to call if either is already gone.
        """
        self.logger.info(f"Removing DHCP pool '{pool_name}-pool' and network {network}")
        if self.mock_mode:
            return {"success": True, "pool_name": pool_name, "network": network,
                    "action": "deleted"}
        removed = {"pool": False, "network": False}
        try:
            api = self._get_api()

            # Remove the DHCP-server network for this subnet
            net_res = api.get_resource('/ip/dhcp-server/network')
            for n in net_res.get():
                if n.get("address") == network:
                    net_res.remove(id=n["id"])
                    removed["network"] = True

            # Remove the IP pool created for this segment
            pool_res = api.get_resource('/ip/pool')
            for pl in pool_res.get():
                if pl.get("name") == f"{pool_name}-pool":
                    pool_res.remove(id=pl["id"])
                    removed["pool"] = True

            return {
                "success": True,
                "pool_name": pool_name,
                "network": network,
                "removed": removed,
                "action": "deleted",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            self.logger.error(f"Failed to remove DHCP config: {e}")
            raise

    def _mgmt_ip(self) -> Optional[str]:
        """The IP UAF is connected to this router on — the management lifeline
        by definition. Used to derive what DHCP config must NEVER be cleared,
        without hardcoding any subnet or pool/server NAME (which vary per site)."""
        return self.device_config.get("host")

    def _protected_dhcp(self, api) -> Dict[str, set]:
        """Derive the management-critical DHCP config to protect during a clear,
        from the router's OWN state + the management IP — no hardcoded names.

        Protect:
          1. Any dhcp-server NETWORK whose subnet contains the management IP
             (the network the framework reaches the router through).
          2. Any POOL referenced by a DHCP server that serves a protected network
             (deleting a pool a live server depends on caused the 'unknown pool'
             error-storm that destabilised the router). Protect by DEPENDENCY.
          3. Any POOL whose ranges fall inside the management subnet.
        Returns {"networks": set(addresses), "pools": set(names)}.
        """
        protected = {"networks": set(), "pools": set()}
        mgmt_ip = self._mgmt_ip()
        if not mgmt_ip:
            # If we somehow don't know our own connect IP, protect nothing extra
            # here — but the caller's keep-lists still apply. Better to under-clear.
            self.logger.warning("clear: management IP unknown; relying on caller keep-lists only")
            return protected
        try:
            mgmt_addr = ipaddress.ip_address(mgmt_ip)
        except ValueError:
            return protected

        # 1. Networks whose subnet contains the management IP.
        mgmt_networks = []  # (address_str, ip_network) for protected nets
        try:
            for n in api.get_resource('/ip/dhcp-server/network').get():
                addr = n.get("address")
                if not addr:
                    continue
                try:
                    netobj = ipaddress.ip_network(addr, strict=False)
                except ValueError:
                    continue
                if mgmt_addr in netobj:
                    protected["networks"].add(addr)
                    mgmt_networks.append(netobj)
        except Exception as e:
            self.logger.error(f"clear: could not read dhcp networks for protection: {e}")

        # 2. Pools referenced by DHCP servers (protect by dependency). We can't
        #    perfectly map server->network, so conservatively protect every pool
        #    that ANY active dhcp-server uses — deleting an in-use pool is what
        #    broke the router. This errs toward safety.
        try:
            for srv in api.get_resource('/ip/dhcp-server').get():
                poolref = srv.get("address-pool")
                if poolref and poolref not in ("static-only", "none"):
                    protected["pools"].add(poolref)
        except Exception as e:
            self.logger.error(f"clear: could not read dhcp servers for protection: {e}")

        # 3. Pools whose ranges fall inside a protected (management) subnet.
        try:
            for pl in api.get_resource('/ip/pool').get():
                ranges = (pl.get("ranges") or "")
                first_ip = ranges.split("-")[0].split(",")[0].strip()
                if not first_ip:
                    continue
                try:
                    ip = ipaddress.ip_address(first_ip)
                except ValueError:
                    continue
                if any(ip in net for net in mgmt_networks):
                    protected["pools"].add(pl.get("name"))
        except Exception as e:
            self.logger.error(f"clear: could not read pools for protection: {e}")

        return protected

    def clear_dhcp_pools(self, keep_names: Optional[List[str]] = None,
                         keep_networks: Optional[List[str]] = None) -> Dict[str, Any]:
        """Remove operational DHCP pools and dhcp-server networks, while NEVER
        removing the management-critical config — derived automatically from the
        router's own state and the IP UAF connected on (no hardcoded names).

        This is the 'replace mode' clear for the router. It honours the Replace
        button's 'keep mgmt' guarantee: it wipes the operational DHCP config but
        preserves the management path so the framework never severs its own
        connection (and never leaves a DHCP server pointing at a deleted pool,
        which previously destabilised the router with 'unknown pool' errors).

        keep_names / keep_networks let the caller protect ADDITIONAL items; the
        management config is protected automatically regardless.
        """
        removed = {"pools": [], "networks": [], "protected": {}}
        if self.mock_mode:
            return {"success": True, "removed": removed}
        try:
            api = self._get_api()

            # Auto-derived management protection + caller-supplied extras.
            auto = self._protected_dhcp(api)
            keep_net = set(keep_networks or []) | auto["networks"]
            keep_n = set(keep_names or []) | auto["pools"]
            removed["protected"] = {"networks": sorted(keep_net), "pools": sorted(keep_n)}
            self.logger.info(f"clear_dhcp_pools protecting networks={sorted(keep_net)} "
                             f"pools={sorted(keep_n)} (mgmt IP={self._mgmt_ip()})")

            # Remove non-protected dhcp-server networks.
            net_res = api.get_resource('/ip/dhcp-server/network')
            for n in net_res.get():
                if n.get("address") in keep_net:
                    continue
                try:
                    net_res.remove(id=n["id"])
                    removed["networks"].append(n.get("address"))
                except Exception as e:
                    self.logger.error(f"Failed to remove network {n.get('address')}: {e}")

            # Remove non-protected pools.
            pool_res = api.get_resource('/ip/pool')
            for pl in pool_res.get():
                if pl.get("name") in keep_n:
                    continue
                try:
                    pool_res.remove(id=pl["id"])
                    removed["pools"].append(pl.get("name"))
                except Exception as e:
                    self.logger.error(f"Failed to remove pool {pl.get('name')}: {e}")

            # Self-heal safety check: ensure no DHCP server is left pointing at a
            # pool we just removed (the failure that caused the 'unknown pool'
            # error-storm). If found, log loudly — do NOT leave it dangling.
            try:
                removed_pool_set = set(removed["pools"])
                for srv in api.get_resource('/ip/dhcp-server').get():
                    if srv.get("address-pool") in removed_pool_set:
                        self.logger.error(
                            f"SAFETY: DHCP server '{srv.get('name')}' references "
                            f"removed pool '{srv.get('address-pool')}' — management "
                            f"DHCP may be broken. Investigate immediately.")
            except Exception as e:
                self.logger.error(f"clear: post-clear safety check failed: {e}")

            return {"success": True, "removed": removed,
                    "timestamp": datetime.now().isoformat()}
        except Exception as e:
            self.logger.error(f"clear_dhcp_pools failed: {e}")
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
