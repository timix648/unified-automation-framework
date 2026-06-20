"""
UAF Network Monitor Service
=============================
Provides real-time monitoring of network devices, interfaces, and health metrics.
"""

from datetime import datetime
from typing import Dict, List, Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor

from app.inventory.netbox_client import NetboxInventory
from app.services.device_manager import DeviceFactory
from app.core.config import settings

class NetworkMonitor:
    """
    Network monitoring service that collects and aggregates metrics from all devices.
    
    Key Features:
    - Real-time interface status monitoring
    - Device connectivity health checks
    - Aggregated network-wide metrics
    - Historical data tracking (future enhancement)
    """
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    async def get_network_health(self) -> Dict:
        """
        Get a comprehensive overview of the entire network's health.
        
        Returns:
            Dictionary containing network-wide health metrics
        """
        
        print(f"\n{'='*60}")
        print(f"📊 NETWORK HEALTH CHECK - {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*60}\n")
        
        try:
            # Fetch all devices from NetBox
            nb = NetboxInventory()
            devices = nb.get_all_devices()
            
            if not devices:
                return {
                    "status": "warning",
                    "message": "No devices found in inventory",
                    "timestamp": datetime.now().isoformat(),
                    "metrics": {}
                }
            
            # Collect metrics from all devices in parallel
            device_metrics = await self._collect_all_device_metrics(devices)
            
            # Aggregate network-wide statistics
            network_stats = self._calculate_network_statistics(device_metrics)
            
            print(f"✅ Health check complete\n")
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "metrics": {
                    "total_devices": len(devices),
                    "devices_online": network_stats['online_count'],
                    "devices_offline": network_stats['offline_count'],
                    "total_interfaces": network_stats['total_interfaces'],
                    "interfaces_up": network_stats['interfaces_up'],
                    "interfaces_down": network_stats['interfaces_down'],
                    "network_availability": network_stats['availability_percentage'],
                    "device_details": device_metrics
                }
            }
        
        except Exception as e:
            print(f"❌ ERROR during health check: {str(e)}\n")
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().isoformat(),
                "metrics": {}
            }
    
    async def _collect_all_device_metrics(self, devices: List[Dict]) -> List[Dict]:
        """
        Collect metrics from all devices concurrently using asyncio.
        
        Args:
            devices: List of device dictionaries from NetBox
        
        Returns:
            List of device metrics
        """
        
        tasks = [self._get_single_device_metrics(device) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return valid results
        return [r for r in results if isinstance(r, dict)]
    
    async def _get_single_device_metrics(self, device: Dict) -> Dict:
        """
        Get metrics for a single device.
        
        Args:
            device: Device dictionary from NetBox
        
        Returns:
            Device metrics dictionary
        """
        
        device_name = device['name']
        
        try:
            # Run the blocking driver operations in a thread pool
            loop = asyncio.get_event_loop()
            metrics = await loop.run_in_executor(
                self.executor,
                self._fetch_device_metrics_sync,
                device
            )
            
            return metrics
        
        except Exception as e:
            print(f"⚠️  Failed to collect metrics from {device_name}: {str(e)}")
            return {
                "device_name": device_name,
                "status": "error",
                "error": str(e),
                "reachable": False
            }
    
    def _fetch_device_metrics_sync(self, device: Dict) -> Dict:
        """
        Synchronous method to fetch device metrics (runs in thread pool).
        
        Args:
            device: Device dictionary from NetBox
        
        Returns:
            Device metrics dictionary
        """
        
        device_name = device['name']
        
        if settings.MOCK_MODE:
            # Return mock data in MOCK_MODE
            return self._generate_mock_metrics(device)
        
        try:
            # Get the appropriate driver
            driver = DeviceFactory.get_driver(device)
            
            # Attempt to connect
            driver.connect()
            
            # Fetch interface information
            interfaces = driver.get_interfaces()
            
            # Calculate interface statistics
            total_interfaces = len(interfaces)
            # Vendor-aware 'up' check: MikroTik reports running=True, Cisco
            # reports status='connected', UniFi reports status='up'. Counting
            # only status=='up' undercounted two of the three vendors.
            def _iface_up(iface):
                if iface.get('running') is True:
                    return True
                return str(iface.get('status', '')).lower() in ('up', 'connected')
            up_interfaces = sum(1 for iface in interfaces if _iface_up(iface))
            down_interfaces = total_interfaces - up_interfaces
            
            driver.disconnect()
            
            return {
                "device_name": device_name,
                "device_ip": device['primary_ip'],
                "platform": device['platform'],
                "device_role": device['device_role'],
                "status": "online",
                "reachable": True,
                "interfaces": {
                    "total": total_interfaces,
                    "up": up_interfaces,
                    "down": down_interfaces
                },
                "interface_details": interfaces,
                "last_checked": datetime.now().isoformat()
            }
        
        except Exception as e:
            return {
                "device_name": device_name,
                "device_ip": device.get('primary_ip', 'unknown'),
                "platform": device['platform'],
                "status": "offline",
                "reachable": False,
                "error": str(e),
                "last_checked": datetime.now().isoformat()
            }
    
    def _generate_mock_metrics(self, device: Dict) -> Dict:
        """
        Generate realistic mock metrics for testing.
        
        Args:
            device: Device dictionary from NetBox
        
        Returns:
            Mock metrics dictionary
        """
        
        import random
        
        # Generate random but realistic interface data
        num_interfaces = random.randint(4, 24)
        up_interfaces = random.randint(int(num_interfaces * 0.6), num_interfaces)
        
        mock_interfaces = []
        for i in range(1, num_interfaces + 1):
            status = "up" if i <= up_interfaces else "down"
            mock_interfaces.append({
                "name": f"GigabitEthernet0/{i}",
                "status": status,
                "mac": f"AA:BB:CC:DD:{i:02d}:{random.randint(1, 99):02d}"
            })
        
        return {
            "device_name": device['name'],
            "device_ip": device['primary_ip'],
            "platform": device['platform'],
            "device_role": device['device_role'],
            "status": "online",
            "reachable": True,
            "interfaces": {
                "total": num_interfaces,
                "up": up_interfaces,
                "down": num_interfaces - up_interfaces
            },
            "interface_details": mock_interfaces,
            "last_checked": datetime.now().isoformat(),
            "mock_data": True
        }
    
    def _calculate_network_statistics(self, device_metrics: List[Dict]) -> Dict:
        """
        Calculate aggregate statistics across all devices.
        
        Args:
            device_metrics: List of device metric dictionaries
        
        Returns:
            Aggregated network statistics
        """
        
        online_count = 0
        offline_count = 0
        total_interfaces = 0
        interfaces_up = 0
        interfaces_down = 0
        
        for metrics in device_metrics:
            if metrics.get('reachable', False):
                online_count += 1
                
                # Aggregate interface stats
                if 'interfaces' in metrics:
                    total_interfaces += metrics['interfaces'].get('total', 0)
                    interfaces_up += metrics['interfaces'].get('up', 0)
                    interfaces_down += metrics['interfaces'].get('down', 0)
            else:
                offline_count += 1
        
        total_devices = online_count + offline_count
        availability_percentage = (online_count / total_devices * 100) if total_devices > 0 else 0
        
        return {
            "online_count": online_count,
            "offline_count": offline_count,
            "total_interfaces": total_interfaces,
            "interfaces_up": interfaces_up,
            "interfaces_down": interfaces_down,
            "availability_percentage": round(availability_percentage, 2)
        }
    
    async def get_device_metrics(self, device_name: str) -> Dict:
        """
        Get detailed metrics for a specific device.
        
        Args:
            device_name: Name of the device to monitor
        
        Returns:
            Device-specific metrics
        """
        
        try:
            # Fetch device from NetBox
            nb = NetboxInventory()
            devices = nb.get_all_devices()
            
            device = next((d for d in devices if d['name'] == device_name), None)
            
            if not device:
                return {
                    "status": "error",
                    "message": f"Device '{device_name}' not found in inventory"
                }
            
            # Get metrics for this specific device
            metrics = await self._get_single_device_metrics(device)
            
            return {
                "status": "success",
                "metrics": metrics
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def get_interface_bandwidth_simulation(self, device_name: str, interface: str) -> Dict:
        """
        Simulate bandwidth monitoring (placeholder for future enhancement).
        In a real implementation, this would use SNMP to query interface counters.
        
        Args:
            device_name: Name of the device
            interface: Interface identifier
        
        Returns:
            Simulated bandwidth metrics
        """
        
        import random
        
        if settings.MOCK_MODE:
            # Generate realistic mock bandwidth data
            return {
                "device": device_name,
                "interface": interface,
                "bandwidth_in_mbps": round(random.uniform(0.5, 100), 2),
                "bandwidth_out_mbps": round(random.uniform(0.5, 100), 2),
                "utilization_percentage": round(random.uniform(5, 85), 2),
                "timestamp": datetime.now().isoformat(),
                "mock_data": True
            }
        
        return {
            "status": "not_implemented",
            "message": "SNMP bandwidth monitoring requires physical devices"
        }