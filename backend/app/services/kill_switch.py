"""
UAF Kill-Switch Service
========================
Automated security response system that isolates threats by shutting down ports.
This is the "Self-Defending Network" component of the framework.

FIXED:
- Added execute_response() method as alias for handle_security_alert()
  (endpoints.py line 452 and scheduler.py line 5425 both call execute_response)
"""

from datetime import datetime
from typing import List, Dict, Optional
import json
import threading
from pathlib import Path

from app.inventory.netbox_client import NetboxInventory
from app.services.device_manager import DeviceFactory
from app.core.config import settings

# Per-device SSH locks. Operations to the SAME device are serialized (a slow
# legacy switch refuses simultaneous SSH sessions), while operations to
# DIFFERENT devices still run in parallel — each device has its own lock.
# "Parallel across devices, serial within a device."
_DEVICE_LOCKS: Dict[str, threading.Lock] = {}
_DEVICE_LOCKS_GUARD = threading.Lock()


def _get_device_lock(device_name: str) -> threading.Lock:
    with _DEVICE_LOCKS_GUARD:
        lock = _DEVICE_LOCKS.get(device_name)
        if lock is None:
            lock = threading.Lock()
            _DEVICE_LOCKS[device_name] = lock
        return lock

class KillSwitchService:
    """
    The Kill-Switch is an automated security response system that:
    1. Detects threats (via external triggers or scheduled scans)
    2. Immediately isolates the affected port
    3. Logs the incident for audit trails
    4. Optionally alerts administrators
    """
    
    def __init__(self):
        self.threat_log_file = Path("logs/security_threats.json")
        self.threat_log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize threat log if it doesn't exist
        if not self.threat_log_file.exists():
            self.threat_log_file.write_text("[]")
    
    def handle_security_alert(self, device_name: str, port_id: str, threat_type: str, 
                        threat_details: Optional[Dict] = None) -> Dict:
        """
        Execute the Kill-Switch response sequence:
        1. Connect to the device
        2. Shutdown the compromised port
        3. Log the incident
        4. Return the execution result
        
        Args:
            device_name: Name of the device (as registered in NetBox)
            port_id: The interface/port identifier (e.g., "GigabitEthernet0/5")
            threat_type: Type of threat detected (e.g., "rogue_device", "mac_spoofing")
            threat_details: Additional context about the threat
        
        Returns:
            Dict containing the execution status and details
        """
        
        print(f"\n{'='*60}")
        print(f"🚨 KILL-SWITCH ACTIVATED")
        print(f"{'='*60}")
        print(f"Device: {device_name}")
        print(f"Port: {port_id}")
        print(f"Threat Type: {threat_type}")
        print(f"{'='*60}\n")
        
        try:
            # 1. Fetch device information from NetBox
            nb = NetboxInventory()
            devices = nb.get_all_devices()
            device = next((d for d in devices if d['name'] == device_name), None)
            
            if not device:
                error_msg = f"Device '{device_name}' not found in inventory"
                print(f"❌ ERROR: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "timestamp": datetime.now().isoformat()
                }
            
            # 2. Get the appropriate driver and connect.
            #    Hold the per-device lock for the whole SSH session so two
            #    shutdowns to the SAME switch don't open simultaneous sessions
            #    (the 2960 refuses that). Different devices use different locks,
            #    so cross-device responses still run in parallel.
            driver = DeviceFactory.get_driver(device)
            with _get_device_lock(device_name):
                driver.connect()

                # 3. Execute the shutdown command
                print(f"⚡ Executing port shutdown on {device_name}:{port_id}...")
                shutdown_result = driver.shutdown_port(port_id)

                driver.disconnect()
            
            # 4. Log the incident
            incident = self._log_incident(
                device_name=device_name,
                device_ip=device.get('primary_ip', device.get('ip', 'unknown')),
                port_id=port_id,
                threat_type=threat_type,
                threat_details=threat_details,
                action_result=shutdown_result
            )
            
            print(f"✅ SUCCESS: Port {port_id} isolated")
            print(f"📝 Incident logged: {incident['incident_id']}\n")

            # Real-time push: this is the central detect-respond path used by
            # both the scheduled rogue scan and the SNMP trap bridge, so any
            # automatic kill-switch action reaches live dashboards instantly.
            try:
                from app.services.event_bus import event_bus
                event_bus.publish(
                    "threat", device=device_name, port=port_id,
                    threat_type=threat_type, severity="critical",
                    incident_id=incident.get("incident_id"),
                    auto=True,
                )
            except Exception:
                pass

            return {
                "success": True,
                "device": device_name,
                "port": port_id,
                "threat_type": threat_type,
                "incident_id": incident['incident_id'],
                "timestamp": incident['timestamp'],
                "action_result": shutdown_result
            }
        
        except Exception as e:
            error_msg = f"Failed to execute Kill-Switch: {str(e)}"
            print(f"❌ ERROR: {error_msg}\n")
            
            # Log the failed attempt
            self._log_incident(
                device_name=device_name,
                device_ip="unknown",
                port_id=port_id,
                threat_type=threat_type,
                threat_details=threat_details,
                action_result={"status": "failed", "error": str(e)},
                success=False
            )
            
            return {
                "success": False,
                "error": error_msg,
                "timestamp": datetime.now().isoformat()
            }
    
    # =========================================================================
    # FIX: Alias so endpoints.py and scheduler.py calls work
    # Both call ks_service.execute_response(...) which didn't exist
    # =========================================================================
    def execute_response(self, device_name: str, port_id: str, threat_type: str,
                         threat_details: Optional[Dict] = None) -> Dict:
        """Alias for handle_security_alert (called by endpoints.py and scheduler.py)."""
        return self.handle_security_alert(device_name, port_id, threat_type, threat_details)

    def record_detection(self, device_name: str, port_id: str, threat_type: str,
                         threat_details: Optional[Dict] = None,
                         device_ip: str = "unknown") -> Dict:
        """
        LEARNING-MODE detection: record an unrecognized device to the threat
        log WITHOUT shutting its port. This surfaces the device in the Security
        page (so an admin can review and Trust it) while the network stays in
        observe-only mode. De-duplicates on (device_name, port, mac) so repeated
        scans don't pile up the same device every 5 minutes.
        """
        mac = (threat_details or {}).get("mac_address", "")

        # De-dupe: if this exact (device, port, mac) is already in the log as a
        # learning-mode detection, don't add it again.
        try:
            with open(self.threat_log_file, 'r') as f:
                existing = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            existing = []
        for inc in existing:
            if (inc.get("device_name") == device_name
                    and inc.get("port_id") == port_id
                    and (inc.get("threat_details") or {}).get("mac_address", "") == mac
                    and inc.get("action_taken") == "detected_only"):
                return inc  # already recorded — no duplicate

        incident_id = f"DET-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        incident = {
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "device_name": device_name,
            "device_ip": device_ip,
            "port_id": port_id,
            "threat_type": threat_type,
            "threat_details": threat_details or {},
            "action_taken": "detected_only",   # learning mode — nothing shut
            "action_result": {"success": True, "message": "Detected (learning mode — not isolated)"},
            "success": True,
        }
        existing.append(incident)
        with open(self.threat_log_file, 'w') as f:
            json.dump(existing, f, indent=2)

        # Push to live dashboards so the detection shows up in real time.
        try:
            from app.services.event_bus import event_bus
            event_bus.publish(
                "threat", device=device_name, port=port_id,
                threat_type=threat_type, severity="info",
                incident_id=incident_id, auto=True, detected_only=True,
            )
        except Exception:
            pass

        return incident
    
    def _log_incident(self, device_name: str, device_ip: str, port_id: str,
                     threat_type: str, threat_details: Optional[Dict],
                     action_result: Dict, success: bool = True) -> Dict:
        """
        Log a security incident to the threat log file.
        
        Returns:
            The logged incident record
        """
        
        # Generate unique incident ID
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        incident = {
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "device_name": device_name,
            "device_ip": device_ip,
            "port_id": port_id,
            "threat_type": threat_type,
            "threat_details": threat_details or {},
            "action_taken": "port_shutdown" if success else "attempted_shutdown",
            "action_result": action_result,
            "success": success
        }
        
        # Read existing log
        try:
            with open(self.threat_log_file, 'r') as f:
                log = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            log = []
        
        # Append new incident
        log.append(incident)
        
        # Write back to file
        with open(self.threat_log_file, 'w') as f:
            json.dump(log, f, indent=2)
        
        return incident
    
    def get_active_threats(self, limit: Optional[int] = 50) -> List[Dict]:
        """
        Retrieve the most recent security incidents.
        
        Args:
            limit: Maximum number of incidents to return
        
        Returns:
            List of incident records
        """
        try:
            with open(self.threat_log_file, 'r') as f:
                log = json.load(f)
            
            # Return most recent incidents first
            sorted_log = sorted(log, key=lambda x: x['timestamp'], reverse=True)
            return sorted_log[:limit] if limit is not None else sorted_log
        
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    
    def get_threat_statistics(self) -> Dict:
        """
        Generate statistics about security threats.
        
        Returns:
            Dictionary containing threat statistics
        """
        threats = self.get_active_threats(limit=None)  # Get all threats
        
        if not threats:
            return {
                "total_incidents": 0,
                "successful_responses": 0,
                "failed_responses": 0,
                "threats_by_type": {},
                "devices_affected": []
            }
        
        # Calculate statistics
        threat_types = {}
        devices_affected = set()
        successful = 0
        failed = 0
        
        for threat in threats:
            # Count by threat type
            t_type = threat['threat_type']
            threat_types[t_type] = threat_types.get(t_type, 0) + 1
            
            # Track affected devices
            devices_affected.add(threat['device_name'])
            
            # Count successes/failures
            if threat.get('success', False):
                successful += 1
            else:
                failed += 1
        
        return {
            "total_incidents": len(threats),
            "successful_responses": successful,
            "failed_responses": failed,
            "threats_by_type": threat_types,
            "devices_affected": list(devices_affected),
            "most_recent_incident": threats[0]['timestamp'] if threats else None
        }
    
    def restore_port(self, device_name: str, port_id: str, reason: str = "Threat cleared") -> Dict:
        """
        Re-enable a port that was previously shutdown by the Kill-Switch.
        This should be done after verifying the threat has been mitigated.
        
        Args:
            device_name: Name of the device
            port_id: The port to re-enable
            reason: Justification for re-enabling the port
        
        Returns:
            Dict containing the restoration status
        """
        
        print(f"\n{'='*60}")
        print(f"🔓 PORT RESTORATION")
        print(f"{'='*60}")
        print(f"Device: {device_name}")
        print(f"Port: {port_id}")
        print(f"Reason: {reason}")
        print(f"{'='*60}\n")
        
        try:
            # Fetch device information
            nb = NetboxInventory()
            devices = nb.get_all_devices()
            device = next((d for d in devices if d['name'] == device_name), None)
            
            if not device:
                return {
                    "success": False,
                    "error": f"Device '{device_name}' not found"
                }
            
            # Get driver and enable port
            driver = DeviceFactory.get_driver(device)
            driver.connect()
            
            print(f"⚡ Enabling port {port_id}...")
            result = driver.enable_port(port_id)
            
            driver.disconnect()
            
            # Log the restoration
            restoration = {
                "timestamp": datetime.now().isoformat(),
                "device_name": device_name,
                "port_id": port_id,
                "action": "port_enabled",
                "reason": reason,
                "result": result
            }
            
            print(f"✅ SUCCESS: Port {port_id} restored\n")
            
            return {
                "success": True,
                **restoration
            }
        
        except Exception as e:
            print(f"❌ ERROR: Failed to restore port: {str(e)}\n")
            return {
                "success": False,
                "error": str(e)
            }
    
    def clear_threat_log(self) -> Dict:
        """
        Clear the threat log (use with caution - for maintenance/testing).
        
        Returns:
            Confirmation message
        """
        try:
            self.threat_log_file.write_text("[]")
            return {
                "success": True,
                "message": "Threat log cleared"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }