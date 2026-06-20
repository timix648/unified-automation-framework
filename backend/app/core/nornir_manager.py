"""
Nornir Integration Layer
=========================
Provides concurrent, multi-threaded network automation using Nornir.

Key Features:
- Execute tasks on multiple devices simultaneously
- NetBox-backed inventory
- Built-in logging and error handling
- Task result aggregation

FIXED:
- Renamed custom class F (line ~1366 in original) → DeviceFilter
  to avoid shadowing the nornir_utils F import at the top of the file
"""

from nornir import InitNornir
from nornir.core.task import Task, Result
from nornir.core.inventory import (
    Inventory, Hosts, Groups, Defaults, Host, Group, ParentGroups
)
from nornir.core.plugins.inventory import InventoryPluginRegister
from nornir_netmiko.tasks import netmiko_send_command, netmiko_send_config
#from nornir_napalm.plugins.tasks import napalm_get, napalm_configure, napalm_cli
from nornir_utils.plugins.functions import print_result
from typing import Dict, List, Optional, Any, Callable
import logging
from datetime import datetime
import json
from nornir.core.filter import F

# Import our custom drivers
from app.drivers.cisco_driver import CiscoIOSDriver
from app.drivers.mikrotik_driver import MikroTikDriver
from app.drivers.unifi_driver import UniFiDriver
from app.inventory.netbox_client import NetboxInventory



# Quiet Nornir's verbose per-task tracebacks in logs — we handle failures
# ourselves and log clean one-liners instead.
logging.getLogger("nornir").setLevel(logging.CRITICAL)
logging.getLogger("nornir.core").setLevel(logging.CRITICAL)
# Quiet the per-driver connection error logs during scans. The scheduler/task
# layer reports unreachable devices as clean one-liners, so we don't need the
# drivers' own \u274c error spam. Set to CRITICAL so genuine crashes still show.
logging.getLogger("CiscoIOSDriver").setLevel(logging.CRITICAL)
logging.getLogger("MikroTikDriver").setLevel(logging.CRITICAL)
logging.getLogger("UniFiDriver").setLevel(logging.CRITICAL)


class DictInventory:
    """
    Custom Nornir inventory plugin that loads hosts/groups from an in-memory dict.

    WHY THIS EXISTS:
    Nornir 3.x does NOT accept a raw dict passed to InitNornir(inventory=...).
    It expects a registered inventory *plugin* whose load() returns an Inventory
    object. Passing a dict caused:
        InventoryConfig.__init__() got an unexpected keyword argument 'hosts'
    This plugin converts our dict (built from NetBox/devices.json) into the
    proper Nornir Inventory objects.
    """

    def __init__(self, inv_dict):
        self.inv_dict = inv_dict

    def load(self) -> Inventory:
        d = self.inv_dict

        # Build groups first so hosts can reference them
        groups = Groups()
        for gname, gdata in d.get("groups", {}).items():
            groups[gname] = Group(
                name=gname,
                platform=gdata.get("platform"),
                data={k: v for k, v in gdata.items() if k != "platform"},
            )

        # Build hosts, linking to group objects
        hosts = Hosts()
        for hname, hdata in d.get("hosts", {}).items():
            host_group_objs = [groups[g] for g in hdata.get("groups", []) if g in groups]
            hosts[hname] = Host(
                name=hname,
                hostname=hdata.get("hostname"),
                platform=hdata.get("platform"),
                groups=ParentGroups(host_group_objs),
                data=hdata.get("data", {}),
            )

        defaults = Defaults(data=d.get("defaults", {}))
        return Inventory(hosts=hosts, groups=groups, defaults=defaults)


class NornirManager:
    """
    Manages Nornir automation framework for concurrent device operations.
    
    This class bridges our custom drivers with Nornir's parallel execution engine.
    """
    
    def __init__(self, netbox_inventory: NetboxInventory, mock_mode: bool = False):
        """
        Initialize Nornir manager.
        
        Args:
            netbox_inventory: NetboxInventory instance for device data
            mock_mode: If True, use mock devices
        """
        self.logger = logging.getLogger(__name__)
        self.netbox = netbox_inventory
        self.mock_mode = mock_mode
        
        # Initialize Nornir
        self.nr = self._init_nornir()
        
        self.logger.info(f"Nornir initialized with {len(self.nr.inventory.hosts)} hosts")
    
    def _init_nornir(self) -> InitNornir:
        """Initialize Nornir with our custom dict-based inventory plugin.

        FIXED: Nornir 3.x requires a registered inventory plugin, not a raw dict.
        We build the dict as before, register DictInventory, and point
        InitNornir at it via the plugin name.
        """

        inventory_dict = self._build_inventory_from_netbox()

        # Register our custom plugin (idempotent-safe: re-registering is fine)
        try:
            InventoryPluginRegister.register("DictInventory", DictInventory)
        except Exception:
            # Already registered on a previous init; ignore
            pass

        nr = InitNornir(
            runner={
                "plugin": "threaded",
                "options": {"num_workers": 10}
            },
            logging={"enabled": False},
            inventory={
                "plugin": "DictInventory",
                "options": {"inv_dict": inventory_dict},
            },
        )

        return nr
    
    def _build_inventory_from_netbox(self) -> Dict:
        """
        Build Nornir inventory structure from NetBox devices.
        
        Returns:
            Dictionary in Nornir inventory format
        """
        devices = self.netbox.get_all_devices()
        
        hosts = {}
        for device in devices:
            device_name = device["name"]
            platform = device["platform"].lower()
            
            # Determine group
            if "cisco" in platform:
                group = "cisco"
            elif "mikrotik" in platform or "routeros" in platform:
                group = "mikrotik"
            elif "unifi" in platform or "ubiquiti" in platform:
                group = "unifi"
            else:
                group = "unknown"
            
            # Add to inventory — store full device info so tasks can create drivers
            hosts[device_name] = {
                "hostname": device["primary_ip"],
                "groups": [group],
                "platform": platform,
                "data": {
                    "device_info": device,
                    "device_id": device.get("id"),
                    "device_role": device.get("device_role"),
                    "site": device.get("site"),
                    "rack": device.get("rack"),
                    "manufacturer": device.get("manufacturer")
                }
            }
        
        groups = {
            "cisco": {"platform": "cisco_ios"},
            "mikrotik": {"platform": "mikrotik_routeros"},
            "unifi": {"platform": "unifi"}
        }
        
        inventory = {"hosts": hosts, "groups": groups, "defaults": {}}
        
        self.logger.info(f"Built Nornir inventory: {len(inventory['hosts'])} hosts")
        return inventory
    
    # =========================================================================
    # HIGH-LEVEL BATCH OPERATIONS
    # =========================================================================
    
    def run_on_all_devices(self, task_func: Callable, **kwargs) -> Dict[str, Any]:
        """
        Run a task on all devices in parallel.
        
        Args:
            task_func: Function to execute (Nornir task)
            **kwargs: Arguments to pass to task_func
            
        Returns:
            Aggregated results from all devices
        """
        self.logger.info(f"Running task '{task_func.__name__}' on all devices")
        
        results = self.nr.run(task=task_func, **kwargs)
        
        return self._aggregate_results(results)
    
    def run_on_filtered_devices(self, filter_func: Callable, 
                                task_func: Callable, **kwargs) -> Dict[str, Any]:
        """
        Run a task on devices matching a filter.
        
        Args:
            filter_func: Function to filter devices (returns True/False)
            task_func: Task to execute
            **kwargs: Task arguments
            
        Returns:
            Aggregated results
        """
        filtered_nr = self.nr.filter(filter_func=filter_func)
        
        self.logger.info(f"Running task on {len(filtered_nr.inventory.hosts)} filtered devices")
        
        results = filtered_nr.run(task=task_func, **kwargs)
        
        return self._aggregate_results(results)
    
    def run_on_group(self, group_name: str, task_func: Callable, **kwargs) -> Dict[str, Any]:
        """
        Run a task on all devices in a specific group (e.g., 'cisco', 'mikrotik').
        
        Args:
            group_name: Group name
            task_func: Task to execute
            **kwargs: Task arguments
            
        Returns:
            Aggregated results
        """
        filtered_nr = self.nr.filter(F(groups__contains=group_name))
        
        self.logger.info(f"Running task on group '{group_name}': {len(filtered_nr.inventory.hosts)} devices")
        
        results = filtered_nr.run(task=task_func, **kwargs)
        
        return self._aggregate_results(results)
    
    # =========================================================================
    # DRIVER HELPER — creates our custom driver from Nornir host data
    # =========================================================================

    @staticmethod
    def _get_driver_for_host(task: Task):
        """
        Create the appropriate vendor driver from the device_info stored in
        the Nornir host's data dict.  This replaces the broken
        task.host.get_connection("driver", ...) calls that required a
        Nornir connection plugin we never registered.
        """
        from app.services.device_manager import DeviceFactory
        device_info = task.host.data.get("device_info")
        if not device_info:
            raise ValueError(f"No device_info in host data for {task.host.name}")
        driver = DeviceFactory.get_driver(device_info)
        driver.connect()
        return driver

    # =========================================================================
    # COMMON NETWORK TASKS (Nornir Task Functions)
    # =========================================================================
    
    @staticmethod
    def task_get_device_info(task: Task) -> Result:
        """
        Nornir task: Get device information.
        """
        driver = NornirManager._get_driver_for_host(task)
        try:
            device_info = driver.get_device_info()
            return Result(host=task.host, result=device_info)
        finally:
            driver.disconnect()
    
    @staticmethod
    def task_disable_port(task: Task, port_id: str, reason: str = "Security violation") -> Result:
        """Nornir task: Disable a port on a device."""
        driver = NornirManager._get_driver_for_host(task)
        try:
            result = driver.disable_port(port_id, reason)
            return Result(host=task.host, result=result)
        finally:
            driver.disconnect()
    
    @staticmethod
    def task_enable_port(task: Task, port_id: str) -> Result:
        """Nornir task: Enable a port."""
        driver = NornirManager._get_driver_for_host(task)
        try:
            result = driver.enable_port(port_id)
            return Result(host=task.host, result=result)
        finally:
            driver.disconnect()
    
    @staticmethod
    def task_get_mac_table(task: Task, vlan_id: Optional[int] = None) -> Result:
        """Nornir task: Get MAC address table."""
        driver = NornirManager._get_driver_for_host(task)
        try:
            result = driver.get_mac_address_table(vlan_id)
            return Result(host=task.host, result=result)
        finally:
            driver.disconnect()
    
    @staticmethod
    def task_create_vlan(task: Task, vlan_id: int, vlan_name: str) -> Result:
        """Nornir task: Create a VLAN."""
        driver = NornirManager._get_driver_for_host(task)
        try:
            result = driver.create_vlan(vlan_id, vlan_name)
            return Result(host=task.host, result=result)
        finally:
            driver.disconnect()
    
    @staticmethod
    def task_configure_port_security(task: Task, port_id: str, 
                                     max_mac: int = 1, 
                                     violation_action: str = "shutdown") -> Result:
        """Nornir task: Configure port security."""
        driver = NornirManager._get_driver_for_host(task)
        try:
            result = driver.configure_port_security(port_id, max_mac, violation_action)
            return Result(host=task.host, result=result)
        finally:
            driver.disconnect()
    
    @staticmethod
    def task_check_for_rogue_devices(task: Task, authorized_macs: List[str]) -> Result:
        """
        Nornir task: Check for unauthorized MAC addresses.

        FIX (clean logs): Unreachable devices (e.g. an unplugged Cisco/UniFi)
        no longer raise and trigger Nornir's full red traceback. Instead we
        catch the connection error and return a clean, non-failed Result marked
        unreachable=True with rogue_count=0. The scheduler then logs a tidy
        one-line "skipped" message. This makes the scan output demo-friendly
        while still scanning every reachable device.
        """
        import logging as _logging
        _log = _logging.getLogger("scheduler")

        # Attempt to connect; if the device is unreachable, return cleanly.
        try:
            driver = NornirManager._get_driver_for_host(task)
        except Exception as e:
            # Keep it short — no traceback. One clean line.
            short = str(e).splitlines()[0] if str(e) else "connection failed"
            _log.info(f"   -> {task.host.name} unreachable ({short}) — skipped")
            return Result(
                host=task.host,
                result={
                    "rogue_count": 0,
                    "rogue_devices": [],
                    "unreachable": True,
                    "reason": short,
                },
            )

        try:
            mac_table = driver.get_mac_address_table()

            rogue_devices = []
            for entry in mac_table:
                mac = entry.get('mac_address', '').lower()
                if mac not in [m.lower() for m in authorized_macs]:
                    rogue_devices.append({
                        "mac": mac,
                        "interface": entry.get('interface'),
                        "vlan": entry.get('vlan'),
                        "type": entry.get('type')
                    })

            return Result(
                host=task.host,
                result={
                    "rogue_count": len(rogue_devices),
                    "rogue_devices": rogue_devices
                }
            )
        except Exception as e:
            short = str(e).splitlines()[0] if str(e) else "scan error"
            _log.info(f"   -> {task.host.name} scan error ({short}) — skipped")
            return Result(
                host=task.host,
                result={
                    "rogue_count": 0,
                    "rogue_devices": [],
                    "unreachable": True,
                    "reason": short,
                },
            )
        finally:
            try:
                driver.disconnect()
            except Exception:
                pass
    
    # =========================================================================
    # BATCH OPERATIONS WITH HIGH-LEVEL ABSTRACTIONS
    # =========================================================================
    
    def bulk_disable_ports(self, port_mappings: Dict[str, List[str]], 
                          reason: str = "Bulk shutdown") -> Dict[str, Any]:
        """
        Disable multiple ports across multiple devices.
        
        Args:
            port_mappings: Dict of {device_name: [port_id1, port_id2, ...]}
            reason: Reason for shutdown
            
        Returns:
            Aggregated results
        """
        self.logger.warning(f"Bulk disabling ports across {len(port_mappings)} devices")
        
        results = {}
        for device_name, ports in port_mappings.items():
            device_results = []
            for port_id in ports:
                # Filter to specific device
                filtered_nr = self.nr.filter(name=device_name)
                
                # Run disable task
                result = filtered_nr.run(
                    task=self.task_disable_port,
                    port_id=port_id,
                    reason=reason
                )
                
                device_results.append(self._aggregate_results(result))
            
            results[device_name] = device_results
        
        return {
            "success": True,
            "operation": "bulk_disable_ports",
            "devices_affected": len(port_mappings),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    def scan_all_for_rogues(self, authorized_macs: List[str]) -> Dict[str, Any]:
        """
        Scan all devices for unauthorized MAC addresses.
        
        Args:
            authorized_macs: List of authorized MAC addresses
            
        Returns:
            Dict with rogue device findings
        """
        self.logger.info("Scanning all devices for rogue MAC addresses")
        
        results = self.nr.run(
            task=self.task_check_for_rogue_devices,
            authorized_macs=authorized_macs
        )
        
        aggregated = self._aggregate_results(results)
        
        # Calculate total rogues
        # FIX: failed hosts (e.g. unreachable Cisco/UniFi) have result=None.
        # r.get('result', {}) returns None when the key exists with value None,
        # so we must guard against None before calling .get() on it.
        total_rogues = 0
        for r in aggregated['results'].values():
            res = r.get('result') or {}
            total_rogues += res.get('rogue_count', 0)
        
        return {
            "success": True,
            "total_rogues_found": total_rogues,
            "devices_scanned": len(aggregated['results']),
            "details": aggregated,
            "timestamp": datetime.now().isoformat()
        }
    
    def deploy_vlan_to_all_switches(self, vlan_id: int, vlan_name: str) -> Dict[str, Any]:
        """
        Create a VLAN on all switches.
        
        Args:
            vlan_id: VLAN ID
            vlan_name: VLAN name
            
        Returns:
            Aggregated results
        """
        self.logger.info(f"Deploying VLAN {vlan_id} ({vlan_name}) to all switches")
        
        # Filter to only Cisco devices (switches)
        results = self.run_on_group(
            group_name="cisco",
            task_func=self.task_create_vlan,
            vlan_id=vlan_id,
            vlan_name=vlan_name
        )
        
        return results
    
    def bulk_configure_port_security(self, device_port_pairs: List[tuple],
                                     max_mac: int = 1,
                                     violation_action: str = "shutdown") -> Dict[str, Any]:
        """
        Configure port security on multiple ports across multiple devices.
        
        Args:
            device_port_pairs: List of (device_name, port_id) tuples
            max_mac: Maximum MAC addresses allowed
            violation_action: Action on violation (shutdown, restrict, protect)
            
        Returns:
            Aggregated results
        """
        self.logger.info(f"Configuring port security on {len(device_port_pairs)} ports")
        
        results = {}
        for device_name, port_id in device_port_pairs:
            filtered_nr = self.nr.filter(name=device_name)
            
            result = filtered_nr.run(
                task=self.task_configure_port_security,
                port_id=port_id,
                max_mac=max_mac,
                violation_action=violation_action
            )
            
            results[f"{device_name}:{port_id}"] = self._aggregate_results(result)
        
        return {
            "success": True,
            "operation": "bulk_configure_port_security",
            "ports_configured": len(device_port_pairs),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def _aggregate_results(self, nornir_results) -> Dict[str, Any]:
        """
        Aggregate Nornir results into a structured format.
        
        Args:
            nornir_results: Nornir AggregatedResult object
            
        Returns:
            Dict with success count, failure count, and per-host results
        """
        aggregated = {
            "success_count": 0,
            "failure_count": 0,
            "results": {}
        }
        
        for host, multi_result in nornir_results.items():
            # Nornir returns a MultiResult, we want the first result
            if len(multi_result) > 0:
                result = multi_result[0]
                
                if result.failed:
                    aggregated["failure_count"] += 1
                    aggregated["results"][host] = {
                        "success": False,
                        "error": str(result.exception) if result.exception else "Unknown error",
                        "result": None
                    }
                else:
                    aggregated["success_count"] += 1
                    aggregated["results"][host] = {
                        "success": True,
                        "error": None,
                        "result": result.result
                    }
        
        return aggregated
    
    def get_inventory_summary(self) -> Dict[str, Any]:
        """Get summary of managed devices."""
        hosts = list(self.nr.inventory.hosts.keys())
        groups = list(self.nr.inventory.groups.keys())
        
        return {
            "total_hosts": len(hosts),
            "hosts": hosts,
            "groups": groups,
            "group_counts": {
                group: len([h for h in hosts if group in self.nr.inventory.hosts[h].groups])
                for group in groups
            }
        }
    
    def refresh_inventory(self):
        """Refresh inventory from NetBox."""
        self.logger.info("Refreshing inventory from NetBox")
        self.nr = self._init_nornir()
        self.logger.info(f"✅ Inventory refreshed: {len(self.nr.inventory.hosts)} hosts")
    
    # =========================================================================
    # NAPALM-BASED METHODS (Vendor Abstraction)
    # =========================================================================
    
    def get_facts_all_devices(self) -> Dict[str, Any]:
        """
        Get device facts using NAPALM (vendor-agnostic).
        Returns unified facts: hostname, model, serial, uptime, etc.
        
        Returns:
            Dict with device facts for all devices
        """
        self.logger.info("Getting facts from all devices using NAPALM")
        
        def napalm_get_facts(task: Task) -> Result:
            """Task to get facts via NAPALM"""
            result = task.run(
                task=napalm_get,
                getters=["facts"]
            )
            return result
        
        results = self.nr.run(task=napalm_get_facts)
        
        # Extract facts
        facts = {}
        for host, multi_result in results.items():
            if not multi_result.failed:
                # NAPALM returns nested structure
                raw_facts = multi_result[0].result.get("facts", {})
                facts[host] = {
                    "vendor": raw_facts.get("vendor"),
                    "model": raw_facts.get("model"),
                    "serial_number": raw_facts.get("serial_number"),
                    "hostname": raw_facts.get("hostname"),
                    "uptime": raw_facts.get("uptime"),
                    "interface_list": raw_facts.get("interface_list", [])
                }
            else:
                facts[host] = {"error": str(multi_result.exception)}
        
        return {
            "success": True,
            "device_count": len(facts),
            "facts": facts,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_interfaces_all_devices(self) -> Dict[str, Any]:
        """
        Get interface status from all devices using NAPALM.
        
        Returns:
            Dict with interface data for all devices
        """
        self.logger.info("Getting interface status from all devices")
        
        def napalm_get_interfaces(task: Task) -> Result:
            result = task.run(
                task=napalm_get,
                getters=["interfaces"]
            )
            return result
        
        results = self.nr.run(task=napalm_get_interfaces)
        
        interfaces = {}
        for host, multi_result in results.items():
            if not multi_result.failed:
                interfaces[host] = multi_result[0].result.get("interfaces", {})
            else:
                interfaces[host] = {"error": str(multi_result.exception)}
        
        return {
            "success": True,
            "device_count": len(interfaces),
            "interfaces": interfaces,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_config_all_devices(self, config_type: str = "running") -> Dict[str, Any]:
        """
        Get device configurations using NAPALM.
        
        Args:
            config_type: Type of config ("running", "startup", "candidate")
        
        Returns:
            Dict with configurations
        """
        self.logger.info(f"Getting {config_type} config from all devices")
        
        def napalm_get_config(task: Task) -> Result:
            result = task.run(
                task=napalm_get,
                getters=["config"]
            )
            return result
        
        results = self.nr.run(task=napalm_get_config)
        
        configs = {}
        for host, multi_result in results.items():
            if not multi_result.failed:
                config_data = multi_result[0].result.get("config", {})
                configs[host] = config_data.get(config_type, "")
            else:
                configs[host] = {"error": str(multi_result.exception)}
        
        return {
            "success": True,
            "device_count": len(configs),
            "configs": configs,
            "timestamp": datetime.now().isoformat()
        }
    
    def health_check_all_devices(self) -> Dict[str, Any]:
        """
        Quick health check - verify all devices are reachable.
        
        Returns:
            Dict with reachability status
        """
        self.logger.info("Performing health check on all devices")
        
        def ping_check(task: Task) -> Result:
            """Simple reachability test"""
            try:
                # Try to get facts (lightweight operation)
                result = task.run(
                    task=napalm_get,
                    getters=["facts"]
                )
                return Result(
                    host=task.host,
                    result={"reachable": True, "response_time": result.diff}
                )
            except Exception as e:
                return Result(
                    host=task.host,
                    failed=True,
                    exception=e
                )
        
        results = self.nr.run(task=ping_check)
        
        health = {}
        for host, multi_result in results.items():
            if not multi_result.failed:
                health[host] = multi_result[0].result
            else:
                health[host] = {
                    "reachable": False,
                    "error": str(multi_result.exception)
                }
        
        # Calculate statistics
        reachable_count = sum(1 for h in health.values() if h.get("reachable"))
        
        return {
            "success": True,
            "total_devices": len(health),
            "reachable": reachable_count,
            "unreachable": len(health) - reachable_count,
            "health_status": health,
            "timestamp": datetime.now().isoformat()
        }


# ============================================================================
# FILTER HELPERS (for use with run_on_filtered_devices)
# FIXED: Renamed from class F → DeviceFilter to avoid shadowing the
# nornir_utils F import at the top of the file
# ============================================================================

class DeviceFilter:
    """Filter helpers for Nornir device selection."""
    
    @staticmethod
    def has_platform(platform: str):
        """Filter by platform."""
        def filter_func(host):
            return platform.lower() in host.platform.lower()
        return filter_func
    
    @staticmethod
    def in_site(site_name: str):
        """Filter by site."""
        def filter_func(host):
            return host.data.get('site', '').lower() == site_name.lower()
        return filter_func
    
    @staticmethod
    def has_role(role: str):
        """Filter by device role."""
        def filter_func(host):
            return host.data.get('device_role', '').lower() == role.lower()
        return filter_func


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    """Example usage of Nornir manager."""
    
    logging.basicConfig(level=logging.INFO)
    
    from app.inventory.netbox_client import NetboxInventory
    
    # Initialize
    netbox = NetboxInventory()
    nornir_mgr = NornirManager(netbox, mock_mode=True)
    
    # Get inventory summary
    print("\n=== Inventory Summary ===")
    summary = nornir_mgr.get_inventory_summary()
    print(json.dumps(summary, indent=2))
    
    # Run a task on all devices
    print("\n=== Getting device info from all devices ===")
    results = nornir_mgr.run_on_all_devices(NornirManager.task_get_device_info)
    print(json.dumps(results, indent=2))
    
    # Scan for rogue devices
    print("\n=== Scanning for rogue devices ===")
    authorized_macs = ["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]
    rogue_results = nornir_mgr.scan_all_for_rogues(authorized_macs)
    print(json.dumps(rogue_results, indent=2))
