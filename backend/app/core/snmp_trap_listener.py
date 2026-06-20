"""
SNMP Trap Listener Service
===========================
Listens for SNMP traps from network devices (especially port security violations)
and triggers automated responses via the Kill-Switch service.

This runs as a background service and processes traps in real-time.

NOTE ON TECHNICAL DEBT:
- This module uses the asyncore-based pysnmp API (pysnmp.carrier.asyncore.dgram)
  which is DEPRECATED and removed in pysnmp 6.x+.
- Our requirements.txt pins pysnmp==4.4.12 which still includes asyncore support.
- For future migration, consider switching to pysnmp-lextudio (community fork)
  which replaces asyncore with asyncio-native transports.
- Migration path: pysnmp-lextudio + pysnmp.hlapi.v3arch.asyncio
"""

from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
import logging
import asyncio
from typing import Callable, Dict, Any
from datetime import datetime
import threading


class SNMPTrapListener:
    """
    SNMP Trap receiver that listens for network security events.
    
    Key Features:
    - Listens on UDP 162 (standard SNMP trap port)
    - Parses trap OIDs to identify event types
    - Triggers callbacks for specific trap types
    - Logs all received traps
    """
    
    # OID Constants for Cisco Port Security Traps
    CISCO_PORT_SECURITY_VIOLATION_OID = '1.3.6.1.4.1.9.9.315.0.0.1'  # cpsSecureMacAddrViolation
    CISCO_PORT_SECURITY_IFINDEX_OID = '1.3.6.1.2.1.2.2.1.1'  # ifIndex
    CISCO_PORT_SECURITY_MAC_OID = '1.3.6.1.4.1.9.9.315.1.2.1.1.10'  # cpsSecureMacAddress
    
    def __init__(self, 
                 listen_address: str = '0.0.0.0', 
                 listen_port: int = 162,
                 community: str = 'public'):
        """
        Initialize SNMP trap listener.
        
        Args:
            listen_address: IP address to bind to (0.0.0.0 for all interfaces)
            listen_port: UDP port to listen on (default 162)
            community: Expected SNMP community string
        """
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.community = community
        
        self.logger = logging.getLogger(__name__)
        
        # Callback registry
        self.callbacks = {
            'port_security_violation': [],
            'link_down': [],
            'link_up': [],
            'config_change': [],
            'generic_trap': []
        }
        
        # SNMP Engine
        self.snmp_engine = None
        self.running = False
        
        # Statistics
        self.stats = {
            'traps_received': 0,
            'violations_detected': 0,
            'last_trap_time': None
        }
    
    def register_callback(self, trap_type: str, callback: Callable):
        """
        Register a callback function for a specific trap type.
        
        Args:
            trap_type: Type of trap (e.g., 'port_security_violation')
            callback: Function to call when trap is received
                     Signature: callback(trap_data: Dict[str, Any]) -> None
        """
        if trap_type not in self.callbacks:
            raise ValueError(f"Unknown trap type: {trap_type}")
        
        self.callbacks[trap_type].append(callback)
        self.logger.info(f"Registered callback for {trap_type}")
    
    def start(self):
        """Start the SNMP trap listener in a background thread."""
        if self.running:
            self.logger.warning("Trap listener already running")
            return
        
        self.logger.info(f"Starting SNMP trap listener on {self.listen_address}:{self.listen_port}")
        
        # Create SNMP engine
        self.snmp_engine = engine.SnmpEngine()
        
        # UDP transport
        config.addTransport(
            self.snmp_engine,
            udp.domainName,
            udp.UdpTransport().openServerMode((self.listen_address, self.listen_port))
        )
        
        # Configure community string
        config.addV1System(self.snmp_engine, 'my-area', self.community)
        
        # Register callback for trap reception
        ntfrcv.NotificationReceiver(self.snmp_engine, self._trap_callback)
        
        self.running = True
        
        # Run in background thread
        listener_thread = threading.Thread(target=self._run_listener, daemon=True)
        listener_thread.start()
        
        self.logger.info("✅ SNMP trap listener started successfully")
    
    def _run_listener(self):
        """Run the SNMP engine (blocking)."""
        try:
            self.snmp_engine.transportDispatcher.jobStarted(1)
            self.snmp_engine.transportDispatcher.runDispatcher()
        except Exception as e:
            self.logger.error(f"Trap listener error: {str(e)}")
            self.running = False
    
    def stop(self):
        """Stop the trap listener."""
        if not self.running:
            return
        
        self.logger.info("Stopping SNMP trap listener")
        self.running = False
        
        if self.snmp_engine:
            self.snmp_engine.transportDispatcher.closeDispatcher()
        
        self.logger.info("SNMP trap listener stopped")
    
    def _trap_callback(self, snmpEngine, stateReference, contextEngineId, 
                      contextName, varBinds, cbCtx):
        """
        Callback function called by PySNMP when a trap is received.
        
        This parses the trap and triggers appropriate registered callbacks.
        """
        self.stats['traps_received'] += 1
        self.stats['last_trap_time'] = datetime.now()
        
        # Extract trap information
        trap_data = self._parse_trap(varBinds)
        
        self.logger.info(f"📨 Trap received from {trap_data['source_ip']}")
        self.logger.debug(f"   Trap OID: {trap_data['trap_oid']}")
        
        # Determine trap type and trigger callbacks
        trap_type = self._identify_trap_type(trap_data)
        
        if trap_type:
            self.logger.info(f"   Trap Type: {trap_type}")
            
            # Execute all registered callbacks for this trap type
            for callback in self.callbacks[trap_type]:
                try:
                    callback(trap_data)
                except Exception as e:
                    self.logger.error(f"Callback error: {str(e)}")
        else:
            # Unknown trap - call generic handlers
            for callback in self.callbacks['generic_trap']:
                try:
                    callback(trap_data)
                except Exception as e:
                    self.logger.error(f"Generic callback error: {str(e)}")
    
    def _parse_trap(self, varBinds) -> Dict[str, Any]:
        """
        Parse SNMP trap var-binds into a structured dictionary.
        
        Args:
            varBinds: Variable bindings from PySNMP
            
        Returns:
            Dictionary with trap information
        """
        trap_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': 'Unknown',
            'trap_oid': '',
            'varbinds': {},
            'interface_index': None,
            'interface_name': None,
            'mac_address': None,
            'raw_data': []
        }
        
        # Process each var-bind
        for name, val in varBinds:
            oid = name.prettyPrint()
            value = val.prettyPrint()
            
            trap_data['varbinds'][oid] = value
            trap_data['raw_data'].append({'oid': oid, 'value': value})
            
            # Extract common fields
            if 'snmpTrapOID' in oid or '1.3.6.1.6.3.1.1.4.1.0' in oid:
                trap_data['trap_oid'] = value
            
            # Extract interface index (ifIndex)
            if self.CISCO_PORT_SECURITY_IFINDEX_OID in oid:
                trap_data['interface_index'] = value
            
            # Extract MAC address from trap
            if 'MacAddress' in oid or '1.3.6.1.4.1.9.9.315' in oid:
                trap_data['mac_address'] = value
        
        return trap_data
    
    def _identify_trap_type(self, trap_data: Dict[str, Any]) -> str:
        """
        Identify the type of trap based on OID and varbinds.
        
        Returns:
            Trap type string or None if unrecognized
        """
        trap_oid = trap_data.get('trap_oid', '')
        
        # Cisco Port Security Violation
        if self.CISCO_PORT_SECURITY_VIOLATION_OID in trap_oid:
            self.stats['violations_detected'] += 1
            return 'port_security_violation'
        
        # Link Down (RFC 2863)
        if '1.3.6.1.6.3.1.1.5.3' in trap_oid:
            return 'link_down'
        
        # Link Up (RFC 2863)
        if '1.3.6.1.6.3.1.1.5.4' in trap_oid:
            return 'link_up'
        
        # Config Change
        if 'ccmHistoryRunningLastChanged' in trap_oid or '1.3.6.1.4.1.9.9.43' in trap_oid:
            return 'config_change'
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get listener statistics."""
        return {
            'running': self.running,
            'listen_address': f"{self.listen_address}:{self.listen_port}",
            'stats': self.stats.copy(),
            'registered_callbacks': {
                trap_type: len(callbacks) 
                for trap_type, callbacks in self.callbacks.items()
            }
        }


# ============================================================================
# INTEGRATION WITH KILL-SWITCH SERVICE
# ============================================================================

class TrapToKillSwitchBridge:
    """
    Bridge between SNMP trap listener and Kill-Switch service.
    
    This class connects the trap listener to the automated response system.
    """
    
    def __init__(self, kill_switch_service, device_manager):
        """
        Initialize the bridge.
        
        Args:
            kill_switch_service: Instance of KillSwitchService
            device_manager: Instance of DeviceFactory/Manager
        """
        self.kill_switch = kill_switch_service
        self.device_manager = device_manager
        self.logger = logging.getLogger(__name__)
        
        # Create trap listener
        self.trap_listener = SNMPTrapListener()
        
        # Register our handler
        self.trap_listener.register_callback(
            'port_security_violation',
            self.handle_port_security_violation
        )
    
    def handle_port_security_violation(self, trap_data: Dict[str, Any]):
        """
        Handle a port security violation trap.
        
        This is called automatically when the trap listener receives a violation.
        """
        self.logger.critical("🚨 PORT SECURITY VIOLATION DETECTED!")
        self.logger.critical(f"   Time: {trap_data['timestamp']}")
        self.logger.critical(f"   Interface: {trap_data.get('interface_index', 'Unknown')}")
        self.logger.critical(f"   MAC: {trap_data.get('mac_address', 'Unknown')}")
        
        # Extract device and port information
        # In a real scenario, you'd map interface_index to actual port ID
        # and map source IP to device name
        
        # For now, trigger the kill-switch
        # You would need to implement reverse lookup from interface_index to port_id
        
        try:
            # Example: If you know the device name and can map ifIndex to port
            device_name = self._resolve_device_from_trap(trap_data)
            port_id = self._resolve_port_from_ifindex(trap_data.get('interface_index'))
            
            if device_name and port_id:
                # Trigger automated shutdown
                result = self.kill_switch.handle_security_alert(
                    device_name=device_name,
                    port_id=port_id,
                    threat_type='rogue_device',
                    threat_details={"description": f"Port security violation - MAC: {trap_data.get('mac_address', 'Unknown')}"}
                )
                
                self.logger.info(f"✅ Kill-switch activated: {result}")
            else:
                self.logger.error("Could not resolve device/port from trap")
                
        except Exception as e:
            self.logger.error(f"Failed to execute kill-switch: {str(e)}")
    
    def _resolve_device_from_trap(self, trap_data: Dict[str, Any]) -> str:
        """
        Resolve device name from trap source IP.
        
        Queries NetBox inventory to match the trap sender IP to a device name.
        Falls back to a default if no match is found.
        """
        source_ip = trap_data.get('source_ip', '')
        try:
            from app.inventory.netbox_client import NetboxInventory
            nb = NetboxInventory()
            devices = nb.get_all_devices()
            for dev in devices:
                if dev.get('ip') == source_ip or dev.get('primary_ip') == source_ip:
                    return dev['name']
        except Exception as e:
            self.logger.warning(f"NetBox lookup failed for IP {source_ip}: {e}")
        
        # Fallback for mock/dev mode
        return "cisco-switch-01"
    
    def _resolve_port_from_ifindex(self, ifindex: str) -> str:
        """
        Map SNMP interface index to actual port ID.
        
        Uses common Cisco IOS ifIndex-to-interface conventions.
        For devices with non-standard mappings, extend the lookup table
        or query IF-MIB::ifDescr on the device.
        """
        # Standard Cisco ifIndex mapping (covers most Catalyst 2960/3560)
        ifindex_to_port = {
            "10001": "GigabitEthernet0/1",
            "10002": "GigabitEthernet0/2",
            "10003": "GigabitEthernet0/3",
            "10004": "GigabitEthernet0/4",
            "10005": "GigabitEthernet0/5",
            "10006": "GigabitEthernet0/6",
            "10007": "GigabitEthernet0/7",
            "10008": "GigabitEthernet0/8",
            "10101": "GigabitEthernet1/0/1",
            "10102": "GigabitEthernet1/0/2",
            "10103": "GigabitEthernet1/0/3",
            "10104": "GigabitEthernet1/0/4",
        }
        
        return ifindex_to_port.get(str(ifindex), f"Port-{ifindex}")
    
    def start(self):
        """Start the trap listener."""
        self.trap_listener.start()
        self.logger.info("✅ Trap-to-KillSwitch bridge started")
    
    def stop(self):
        """Stop the trap listener."""
        self.trap_listener.stop()
        self.logger.info("Trap-to-KillSwitch bridge stopped")
    
    def get_status(self) -> Dict[str, Any]:
        """Get bridge status."""
        return {
            'active': self.trap_listener.running,
            'statistics': self.trap_listener.get_statistics()
        }


# ============================================================================
# STANDALONE TESTING
# ============================================================================

if __name__ == "__main__":
    """
    Standalone test mode.
    Run this to test the trap listener without the full application.
    """
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    # Create listener
    listener = SNMPTrapListener(listen_address='0.0.0.0', listen_port=162)
    
    # Register test callback
    def test_callback(trap_data):
        logger.info("=" * 60)
        logger.info("TEST CALLBACK TRIGGERED")
        logger.info(f"Trap OID: {trap_data['trap_oid']}")
        logger.info(f"Interface: {trap_data.get('interface_index', 'N/A')}")
        logger.info(f"MAC: {trap_data.get('mac_address', 'N/A')}")
        logger.info(f"Timestamp: {trap_data['timestamp']}")
        logger.info("=" * 60)
    
    listener.register_callback('port_security_violation', test_callback)
    listener.register_callback('generic_trap', test_callback)
    
    # Start listening
    try:
        listener.start()
        logger.info("Trap listener running. Press Ctrl+C to stop.")
        logger.info(f"Listening on {listener.listen_address}:{listener.listen_port}")
        logger.info("")
        logger.info("To test, send a trap from a Cisco device:")
        logger.info("  Switch(config)# snmp-server host <THIS_SERVER_IP> version 2c public")
        logger.info("  Switch(config)# snmp-server enable traps port-security")
        logger.info("")
        
        # Keep running
        import time
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Stopping...")
        listener.stop()
        logger.info("Stopped")
