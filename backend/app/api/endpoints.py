"""
UAF API Endpoints
==================
REST API routes for controlling network devices, security, and automation.

ADDITIONS:
- /api/audit/logs — Retrieve persistent audit trail
- /api/security/stats — Security threat statistics
- /api/provision/network — High-level network provisioning endpoint
  (user describes a network, system auto-configures all devices)
"""

import asyncio
import socket
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from typing import List, Optional

from app.core.security import decode_access_token
from app.services.event_bus import event_bus

from app.inventory.netbox_client import NetboxInventory
from app.inventory import authorized_registry
from app.services import schedule_policy
from app.services import enforcement_state
from app.services.device_manager import DeviceFactory
from app.services.kill_switch import KillSwitchService
from app.services.monitor import NetworkMonitor
from app.services.wol import send_magic_packet
from app.services.scheduler import auto_enforce_time_policy, auto_scan_for_rogues
from app.core.config import settings
from app.core.security import audit_logger, get_current_user, RoleChecker
from app.core.security import user_db

router = APIRouter()

# Role-based access control dependencies
require_operator = RoleChecker(["admin", "operator"])
require_admin = RoleChecker(["admin"])


# ============================================================================
# REAL-TIME EVENT CHANNEL (WebSocket)
# Pushes security alerts and device-status changes to the frontend the instant
# they happen, rather than waiting for a poll cycle (Report objective 4.7).
# Authentication is via the JWT passed as a query param, since browser
# WebSocket clients can't set Authorization headers cleanly.
# ============================================================================


@router.websocket("/ws/events")
async def ws_events(websocket: WebSocket, token: str = ""):
    """Stream backend events to one connected client.

    On connect we authenticate the JWT, then deliver two things:
      1. Every published event (threat detected, port shut/restored,
         provisioning finished) the moment it occurs — the real-time
         security-alert feed.
      2. A periodic device-status snapshot (online/offline per device) so the
         dashboard's status dots stay live without HTTP polling.
    Both flow through this connection's single queue, so there is exactly one
    task writing to the socket (Starlette WebSockets are not safe for
    concurrent sends).
    """
    try:
        payload = decode_access_token(token)
        user = payload.get("sub", "unknown")
    except Exception:
        await websocket.close(code=4401)  # policy violation / unauthorized
        return

    await websocket.accept()
    queue = await event_bus.subscribe()

    async def push_health(q: asyncio.Queue):
        """Enqueue a device-status snapshot for THIS client every 10s."""
        while True:
            try:
                nb = NetboxInventory()
                devices = nb.get_all_devices()

                async def probe(d):
                    host = d.get("ip") or d.get("primary_ip", "")
                    port = _management_port(d)
                    up = await asyncio.to_thread(_tcp_probe, host, port, 2.0)
                    return d.get("name", host), ("online" if up else "offline")

                results = await asyncio.gather(*[probe(d) for d in devices])
                snapshot = {
                    "type": "device_status",
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "health": {name: status for name, status in results},
                }
                try:
                    q.put_nowait(snapshot)
                except asyncio.QueueFull:
                    pass
            except Exception:
                pass
            await asyncio.sleep(10)

    health_task = asyncio.create_task(push_health(queue))
    try:
        await websocket.send_json({
            "type": "connected", "user": user,
            "ts": datetime.now().isoformat(timespec="seconds"),
        })
        # Non-blocking drain: wait for an event but time out periodically so the
        # socket event loop keeps cycling. While blocked forever on queue.get(),
        # Starlette never services the client's WebSocket ping frames, which the
        # client then reaps as a 1011 keepalive timeout. Waking every few seconds
        # lets the automatic ping/pong flow and sends our own heartbeat so even a
        # silent channel proves it is alive.
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({
                    "type": "heartbeat",
                    "ts": datetime.now().isoformat(timespec="seconds"),
                })
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        health_task.cancel()
        event_bus.unsubscribe(queue)


# ============================================================================
# REACHABILITY PROBE HELPERS
# A lightweight TCP connect to each device's management port. This answers
# "is the device on the network right now?" without a full authenticated
# login, so the dashboard can color status dots in ~2s instead of waiting on
# per-vendor session setup. The deeper check still happens on Inspect.
# ============================================================================

def _management_port(device: dict) -> int:
    """The TCP port UAF actually talks to for this platform."""
    platform = (device.get("platform") or "").lower()
    overrides = device.get("credentials", {}) or {}
    if "cisco" in platform:
        return int(overrides.get("port", settings.CISCO_PORT))
    if "mikrotik" in platform or "routeros" in platform:
        # MikroTik driver connects over the RouterOS API port, not SSH.
        return int(overrides.get("api_port", 8728))
    if "unifi" in platform or "ubiquiti" in platform:
        return int(overrides.get("port", settings.UNIFI_PORT))
    return 22


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""
    if not host:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False

# ============================================================================
# DATA MODELS (Request/Response Schemas)
# ============================================================================


class PortControlRequest(BaseModel):
    device_name: str
    port_id: str
    action: str  # "shutdown" or "enable"


class WoLRequest(BaseModel):
    mac_address: str
    broadcast_ip: Optional[str] = "255.255.255.255"


class WoLBatchRequest(BaseModel):
    macs: List[str] = Field(default_factory=list, description="MAC addresses to wake")
    broadcast_ip: Optional[str] = "255.255.255.255"


class SecurityAlertRequest(BaseModel):
    device_name: str
    port_id: str
    threat_type: str  # "rogue_device", "mac_spoofing", etc.


class PortRestoreRequest(BaseModel):
    device_name: str
    port_id: str
    reason: str = "Threat cleared"


class SchedulerControlRequest(BaseModel):
    action: str  # "trigger_security", "trigger_time_policy"


class NetworkProvisionRequest(BaseModel):
    """
    High-level network provisioning request.
    The user describes WHAT they want (network name, subnet, VLAN, etc.)
    and the system figures out HOW to configure all devices automatically.
    This is the "Vendor-Agnostic Abstraction Layer" in action.
    """
    network_name: str = Field(..., description="Human-readable name for this network segment")
    vlan_id: int = Field(..., ge=2, le=4094, description="VLAN ID (2-4094)")
    subnet: str = Field(..., description="Subnet in CIDR notation, e.g. '192.168.10.0/24'")
    gateway: str = Field(..., description="Default gateway IP, e.g. '192.168.10.1'")
    dns_servers: List[str] = Field(
        default=["8.8.8.8", "8.8.4.4"],
        description="DNS servers for this network"
    )
    enable_dhcp: bool = Field(default=True, description="Enable DHCP on the MikroTik router")
    enable_port_security: bool = Field(
        default=True, description="Enable port security on Cisco switch ports"
    )
    wifi_ssid: Optional[str] = Field(
        default=None, description="If provided, creates a WiFi SSID on UniFi AP"
    )
    wifi_password: Optional[str] = Field(
        default=None, description="WiFi password (required if wifi_ssid is provided)"
    )
    switch_ports: List[str] = Field(
        default=["GigabitEthernet0/1", "GigabitEthernet0/2", "GigabitEthernet0/3"],
        description="Switch ports to assign to this VLAN"
    )


class WlanUpdateRequest(BaseModel):
    """Partial edit to an existing UniFi SSID. Any field left None is untouched."""
    name: Optional[str] = None
    passphrase: Optional[str] = None
    vlan: Optional[int] = None
    enabled: Optional[bool] = None
    security: Optional[str] = None


# ============================================================================
# DEVICE MANAGEMENT ENDPOINTS
# ============================================================================


@router.get("/devices")
async def get_all_devices(current_user: dict = Depends(get_current_user)):
    """Fetch all network devices from NetBox inventory."""
    try:
        nb = NetboxInventory()
        devices = nb.get_all_devices()
        return {"status": "success", "count": len(devices), "devices": devices}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices/health")
async def get_devices_health(current_user: dict = Depends(get_current_user)):
    """Probe reachability of every device in inventory, concurrently.

    Returns a name -> {status, ip, port} map so the dashboard can show live
    online/offline status for the *registered* devices without the user
    having to inspect each one. This is a reachability check (TCP), not a
    network discovery scan — it reports on known inventory only.
    """
    nb = NetboxInventory()
    devices = nb.get_all_devices()

    async def probe(device: dict):
        host = device.get("ip") or device.get("primary_ip", "")
        port = _management_port(device)
        reachable = await asyncio.to_thread(_tcp_probe, host, port, 2.0)
        return device.get("name", host), {
            "status": "online" if reachable else "offline",
            "ip": host,
            "port": port,
        }

    results = await asyncio.gather(*[probe(d) for d in devices])
    health = {name: info for name, info in results}
    online = sum(1 for v in health.values() if v["status"] == "online")
    return {
        "status": "success",
        "count": len(health),
        "online": online,
        "offline": len(health) - online,
        "health": health,
    }


@router.get("/devices/{device_name}")
async def get_device_details(device_name: str, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific device."""
    try:
        nb = NetboxInventory()
        devices = nb.get_all_devices()
        device = next((d for d in devices if d["name"] == device_name), None)
        if not device:
            raise HTTPException(status_code=404, detail=f"Device '{device_name}' not found")
        return {"status": "success", "device": device}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices/{device_name}/interfaces")
async def get_device_interfaces(device_name: str, current_user: dict = Depends(get_current_user)):
    """Get all interfaces for a specific device.

    GRACEFUL OFFLINE HANDLING: if the device is not reachable (not yet
    provisioned, powered off, or cable unplugged), we DO NOT raise a 500.
    Instead we return 200 with status="unreachable" so the dashboard can show
    a clean OFFLINE state rather than an error. This matches the framework's
    partial-failure design: one offline device never looks like a crash.
    """
    nb = NetboxInventory()
    devices = nb.get_all_devices()
    device = next((d for d in devices if d["name"] == device_name), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_name}' not found")

    driver = DeviceFactory.get_driver(device)
    try:
        driver.connect()
        interfaces = driver.get_interfaces()
        return {
            "status": "success",
            "device": device_name,
            "interfaces": interfaces,
        }
    except Exception as e:
        # Device unreachable — clean, expected response (not a 500)
        return {
            "status": "unreachable",
            "device": device_name,
            "interfaces": [],
            "reason": str(e).splitlines()[0] if str(e) else "device unreachable",
        }
    finally:
        try:
            driver.disconnect()
        except Exception:
            pass


# ============================================================================
# PORT CONTROL ENDPOINTS (Kill-Switch Interface)
# ============================================================================


@router.get("/devices/{device_name}/wlans")
async def get_device_wlans(device_name: str,
                           current_user: dict = Depends(get_current_user)):
    """List the wireless networks (SSIDs) configured on a UniFi controller.

    Surfaces the Wi-Fi side of the time-based access policy: the scheduler
    enables/disables these SSIDs on the same admin-configured window as the
    wired Cisco/MikroTik enforcement (Proposal Objective 3).
    """
    nb = NetboxInventory()
    devices = nb.get_all_devices()
    device = next((d for d in devices if d["name"] == device_name), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_name} not found")
    platform = (device.get("platform") or "").lower()
    if "unifi" not in platform and "ubiquiti" not in platform:
        raise HTTPException(status_code=400,
                            detail="WLANs are only available on UniFi controllers")
    try:
        driver = DeviceFactory.get_driver(device)
        driver.connect()
        wlans = driver.get_wlan_groups()
        driver.disconnect()
        return {"status": "success", "device": device_name,
                "count": len(wlans), "wlans": wlans}
    except Exception as e:
        # Honest reachability signal, same convention as /interfaces
        return {"status": "unreachable", "device": device_name,
                "wlans": [], "error": str(e)}


def _resolve_unifi_device(device_name: str) -> dict:
    """Shared lookup for the WLAN edit/delete routes: find the device and
    confirm it's a UniFi controller, or raise the right HTTP error."""
    nb = NetboxInventory()
    device = next((d for d in nb.get_all_devices() if d["name"] == device_name), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_name} not found")
    platform = (device.get("platform") or "").lower()
    if "unifi" not in platform and "ubiquiti" not in platform:
        raise HTTPException(status_code=400,
                            detail="WLANs are only available on UniFi controllers")
    return device


@router.put("/devices/{device_name}/wlans/{wlan_id}")
async def update_device_wlan(device_name: str, wlan_id: str,
                             request: WlanUpdateRequest,
                             current_user: dict = Depends(require_operator)):
    """Edit an existing SSID's settings (name, password, VLAN, security, enabled)
    directly from UAF — no UniFi controller GUI required. Completes the SSID
    lifecycle alongside create (/provision/network) and toggle (the scheduler)."""
    device = _resolve_unifi_device(device_name)
    try:
        driver = DeviceFactory.get_driver(device)
        driver.connect()
        result = driver.update_wlan(
            wlan_id, name=request.name, passphrase=request.passphrase,
            vlan=request.vlan, enabled=request.enabled, security=request.security,
        )
        driver.disconnect()
        audit_logger.log_security_event(
            "WLAN_UPDATE", f"SSID {wlan_id} on {device_name} updated")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/devices/{device_name}/wlans/{wlan_id}")
async def delete_device_wlan(device_name: str, wlan_id: str,
                             current_user: dict = Depends(require_admin)):
    """Remove an SSID from the UniFi controller entirely. Admin-only (destructive)."""
    device = _resolve_unifi_device(device_name)
    try:
        driver = DeviceFactory.get_driver(device)
        driver.connect()
        result = driver.delete_wlan(wlan_id)
        driver.disconnect()
        audit_logger.log_security_event(
            "WLAN_DELETE", f"SSID {wlan_id} on {device_name} deleted")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/port-control")
async def control_port(request: PortControlRequest, current_user: dict = Depends(require_operator)):
    """Enable or disable a specific port on a device (manual Kill-Switch)."""
    try:
        nb = NetboxInventory()
        devices = nb.get_all_devices()
        device = next((d for d in devices if d["name"] == request.device_name), None)
        if not device:
            raise HTTPException(
                status_code=404, detail=f"Device '{request.device_name}' not found"
            )

        driver = DeviceFactory.get_driver(device)
        driver.connect()

        if request.action == "shutdown":
            result = driver.shutdown_port(request.port_id)
        elif request.action == "enable":
            result = driver.enable_port(request.port_id)
        else:
            raise HTTPException(status_code=400, detail="Action must be 'shutdown' or 'enable'")

        driver.disconnect()

        # Log the port control action
        audit_logger.log_security_event(
            "PORT_CONTROL",
            f"Port {request.port_id} on {request.device_name} — action: {request.action}"
        )

        # Push the action to any live dashboards in real time (4.7).
        event_bus.publish(
            "port_control", device=request.device_name,
            port=request.port_id, action=request.action,
            user=current_user.get("sub", ""),
        )

        return {
            "status": "success",
            "action": request.action,
            "device": request.device_name,
            "port": request.port_id,
            "result": result,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SECURITY ENDPOINTS
# ============================================================================


@router.post("/security/alert")
async def trigger_security_response(
    request: SecurityAlertRequest, background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_operator)
):
    """Trigger the Kill-Switch security response (manual or from external IDS)."""
    try:
        kill_switch = KillSwitchService()

        background_tasks.add_task(
            kill_switch.handle_security_alert,
            device_name=request.device_name,
            port_id=request.port_id,
            threat_type=request.threat_type,
        )

        # Log the security alert
        audit_logger.log_security_event(
            "SECURITY_ALERT_TRIGGERED",
            f"Kill-switch alert: {request.threat_type} on {request.device_name}:{request.port_id}"
        )

        # Push the threat to live dashboards immediately (4.7).
        event_bus.publish(
            "threat", device=request.device_name, port=request.port_id,
            threat_type=request.threat_type, severity="critical",
        )

        return {
            "status": "accepted",
            "message": "Security response initiated",
            "device": request.device_name,
            "port": request.port_id,
            "threat": request.threat_type,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/security/threats")
async def get_active_threats(current_user: dict = Depends(get_current_user)):
    """Retrieve a list of currently detected threats.

    Flattens the nested mac_address up to a top-level 'mac' field so the
    dashboard can render it directly (the frontend can't index nested dicts).
    """
    try:
        kill_switch = KillSwitchService()
        threats = kill_switch.get_active_threats()
        flattened = []
        for t in threats:
            details = t.get("threat_details") or {}
            flattened.append({
                "mac": details.get("mac_address", "unknown"),
                "device_name": t.get("device_name", ""),
                "port_id": t.get("port_id", ""),
                "threat_type": t.get("threat_type", ""),
                "timestamp": t.get("timestamp", ""),
                "success": t.get("success", False),
            })
        return {"status": "success", "count": len(flattened), "threats": flattened}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/security/stats")
async def get_security_statistics(current_user: dict = Depends(get_current_user)):
    """Get aggregated security threat statistics."""
    try:
        kill_switch = KillSwitchService()
        stats = kill_switch.get_threat_statistics()
        return {"status": "success", "statistics": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security/scan")
async def trigger_security_scan(background_tasks: BackgroundTasks, current_user: dict = Depends(require_operator)):
    """Manually trigger a network-wide security scan for rogue devices."""
    background_tasks.add_task(auto_scan_for_rogues)
    audit_logger.log_security_event("MANUAL_SCAN_TRIGGERED", "Manual security scan initiated")
    return {"status": "accepted", "message": "Security scan initiated"}


@router.post("/security/restore")
async def restore_port(request: PortRestoreRequest, current_user: dict = Depends(require_operator)):
    """Re-enable a previously shut-down port after threat is cleared."""
    try:
        kill_switch = KillSwitchService()
        result = kill_switch.restore_port(
            device_name=request.device_name,
            port_id=request.port_id,
            reason=request.reason,
        )

        audit_logger.log_security_event(
            "PORT_RESTORED",
            f"Port {request.port_id} on {request.device_name} restored — reason: {request.reason}"
        )

        event_bus.publish(
            "port_restored", device=request.device_name,
            port=request.port_id, reason=request.reason,
        )

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# AUTHORIZED DEVICES REGISTRY (editable source-of-truth)
# The admin manages which MAC addresses are trusted. The rogue scanner treats
# anything NOT in this registry (and not a managed device's own MAC) as a
# potential rogue. This is what lets the admin distinguish real devices from
# rogues — replacing the old hardcoded trusted-MAC list.
# ============================================================================


class AuthorizedDeviceRequest(BaseModel):
    mac: str = Field(..., description="MAC address to authorize")
    label: Optional[str] = Field("", description="Friendly label, e.g. 'Reception PC'")


@router.get("/security/authorized")
async def list_authorized_devices(current_user: dict = Depends(get_current_user)):
    """List all admin-authorized devices (the editable source of truth)."""
    try:
        entries = authorized_registry.list_authorized()
        return {"status": "success", "count": len(entries), "authorized": entries}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security/authorized")
async def add_authorized_device(request: AuthorizedDeviceRequest,
                                current_user: dict = Depends(require_operator)):
    """Authorize a device by MAC (with optional label). Idempotent."""
    try:
        entry = authorized_registry.add_authorized(request.mac, request.label)
        audit_logger.log_security_event(
            "DEVICE_AUTHORIZED",
            f"MAC {entry['mac']} authorized as '{entry['label']}'"
        )
        return {"status": "success", "authorized": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/security/authorized/{mac}")
async def remove_authorized_device(mac: str,
                                   current_user: dict = Depends(require_operator)):
    """Remove a device from the authorized registry."""
    try:
        removed = authorized_registry.remove_authorized(mac)
        if removed:
            audit_logger.log_security_event(
                "DEVICE_DEAUTHORIZED", f"MAC {mac} removed from authorized registry"
            )
            return {"status": "success", "removed": mac}
        raise HTTPException(status_code=404, detail=f"MAC '{mac}' not in registry")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security/authorized/trust-threat")
async def trust_discovered_device(request: AuthorizedDeviceRequest,
                                  current_user: dict = Depends(require_operator)):
    """One-click: trust a device that was flagged as a rogue/threat.

    Same effect as adding to the registry, but semantically this is the
    'this detected device is actually legitimate' action from the Security page.
    After this, the next scan will no longer flag this MAC.
    """
    try:
        label = request.label or "Trusted from detection"
        entry = authorized_registry.add_authorized(request.mac, label)
        audit_logger.log_security_event(
            "THREAT_WHITELISTED",
            f"Previously-flagged MAC {entry['mac']} marked trusted as '{entry['label']}'"
        )
        return {"status": "success", "authorized": entry}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security/clear-threats")
async def clear_threats(current_user: dict = Depends(require_operator)):
    """Clear the resolved-threat log. Used after trusting devices so the
    threat list reflects only currently-detected rogues on the next scan."""
    try:
        kill_switch = KillSwitchService()
        result = kill_switch.clear_threat_log()
        audit_logger.log_security_event("THREAT_LOG_CLEARED", "Threat log cleared by admin")
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ENFORCEMENT MODE (learning vs armed)
# A fresh install starts in "learning": the scanner detects and reports
# unrecognized devices but shuts nothing, so the admin can build a trusted
# baseline first. Switching to "armed" turns on the automated kill-switch.
# ============================================================================


class EnforcementRequest(BaseModel):
    mode: str = Field(..., description="Enforcement mode: 'learning' or 'armed'")


@router.get("/security/enforcement")
async def get_enforcement(current_user: dict = Depends(get_current_user)):
    """Return the current enforcement mode (learning / armed)."""
    try:
        return {"status": "success", "enforcement": enforcement_state.get_state()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security/enforcement")
async def set_enforcement(request: EnforcementRequest,
                          current_user: dict = Depends(require_admin)):
    """Switch enforcement mode. Only an admin can arm/disarm the kill-switch."""
    try:
        state = enforcement_state.set_mode(
            request.mode, updated_by=current_user.get("username", "admin"))
        verb = "ARMED — kill-switch active" if state["mode"] == "armed" \
            else "set to LEARNING — detection only, no auto-block"
        audit_logger.log_security_event(
            "ENFORCEMENT_CHANGED", f"Enforcement {verb}")
        event_bus.publish("enforcement", mode=state["mode"],
                          summary=f"Enforcement {verb}")
        return {"status": "success", "enforcement": state}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# TIME-BASED ACCESS POLICY (admin-configurable schedule)
# ============================================================================


class SchedulePolicyRequest(BaseModel):
    block_start_hour: int = Field(..., ge=0, le=23, description="Hour (0-23) to START restricting access")
    block_end_hour: int = Field(..., ge=0, le=23, description="Hour (0-23) to STOP restricting access")
    enabled: bool = Field(True, description="Whether time-based restriction is active")


@router.get("/scheduler/policy")
async def get_schedule_policy(current_user: dict = Depends(get_current_user)):
    """Return the current configurable time-based access policy."""
    try:
        return {"status": "success", "policy": schedule_policy.get_policy()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scheduler/policy")
async def set_schedule_policy(request: SchedulePolicyRequest,
                              current_user: dict = Depends(require_operator)):
    """Set the time-based access policy (block start/stop hours + enabled)."""
    try:
        policy = schedule_policy.set_policy(
            request.block_start_hour, request.block_end_hour, request.enabled
        )
        audit_logger.log_security_event(
            "SCHEDULE_POLICY_UPDATED",
            f"Restriction window set to {policy['block_start_hour']:02d}:00–"
            f"{policy['block_end_hour']:02d}:00, enabled={policy['enabled']}"
        )
        return {"status": "success", "policy": policy}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MONITORING ENDPOINTS
# ============================================================================


@router.get("/monitor/network-health")
async def get_network_health(current_user: dict = Depends(get_current_user)):
    """Get real-time network health metrics across all devices."""
    try:
        monitor = NetworkMonitor()
        health_data = await monitor.get_network_health()
        return {
            "status": "success",
            "timestamp": health_data["timestamp"],
            "metrics": health_data["metrics"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitor/device/{device_name}/metrics")
async def get_device_metrics(device_name: str, current_user: dict = Depends(get_current_user)):
    """Get detailed metrics for a specific device."""
    try:
        monitor = NetworkMonitor()
        metrics = await monitor.get_device_metrics(device_name)
        return {"status": "success", "device": device_name, "metrics": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# AUTOMATION/SCHEDULER ENDPOINTS
# ============================================================================


@router.post("/scheduler/control")
async def control_scheduler(
    request: SchedulerControlRequest, background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin)
):
    """Control the background automation scheduler."""
    try:
        if request.action == "trigger_security":
            background_tasks.add_task(auto_scan_for_rogues)
            return {"status": "success", "message": "Security scan triggered"}
        elif request.action == "trigger_time_policy":
            background_tasks.add_task(auto_enforce_time_policy)
            return {"status": "success", "message": "Time-based policy enforcement triggered"}
        else:
            raise HTTPException(status_code=400, detail="Invalid action")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scheduler/status")
async def get_scheduler_status(current_user: dict = Depends(get_current_user)):
    """Get the current status of scheduled automation tasks."""
    from app.services.scheduler import scheduler

    return {
        "status": "success",
        "running": scheduler.running,
        "jobs": [
            {
                "id": job.id,
                "name": job.name,
                "next_run": str(job.next_run_time) if job.next_run_time else None,
            }
            for job in scheduler.get_jobs()
        ],
    }


# ============================================================================
# POWER MANAGEMENT ENDPOINTS (Wake-on-LAN)
# ============================================================================


@router.post("/power/wake")
async def wake_device(request: WoLRequest, current_user: dict = Depends(require_operator)):
    """Send a Wake-on-LAN magic packet to power on a device."""
    try:
        send_magic_packet(request.mac_address, request.broadcast_ip)
        audit_logger.log_security_event(
            "WOL_PACKET_SENT",
            f"Magic packet sent to {request.mac_address}"
        )
        return {
            "status": "success",
            "message": f"Magic packet sent to {request.mac_address}",
            "broadcast_ip": request.broadcast_ip,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/power/wake-batch")
async def wake_devices_batch(request: WoLBatchRequest,
                             current_user: dict = Depends(require_operator)):
    """Send Wake-on-LAN magic packets to multiple devices at once."""
    results = []
    for mac in request.macs:
        try:
            send_magic_packet(mac, request.broadcast_ip)
            results.append({"mac": mac, "sent": True})
        except Exception as e:
            results.append({"mac": mac, "sent": False, "error": str(e)})
    sent = sum(1 for r in results if r["sent"])
    audit_logger.log_security_event(
        "WOL_BATCH_SENT", f"Batch WoL: {sent}/{len(request.macs)} packets sent"
    )
    return {"status": "success", "sent": sent, "total": len(request.macs), "results": results}


# ============================================================================
# NETWORK PROVISIONING ENDPOINT
# (The "smart setup" — user describes a network, system configures all devices)
# ============================================================================


@router.post("/provision/network")
async def provision_network(request: NetworkProvisionRequest, current_user: dict = Depends(require_admin)):
    """
    Provision a complete network segment across all device types.

    This is the Vendor-Agnostic Abstraction Layer in action:
    - Creates VLAN on the Cisco switch
    - Assigns ports to the VLAN
    - Optionally enables port security on assigned ports
    - Creates DHCP pool on MikroTik router
    - Optionally creates WiFi SSID on UniFi AP

    The user only provides high-level intent (network name, subnet, VLAN ID, etc.)
    and the system handles the vendor-specific implementation automatically.
    """
    results = {
        "network_name": request.network_name,
        "vlan_id": request.vlan_id,
        "subnet": request.subnet,
        "steps_completed": [],
        "steps_failed": [],
    }

    nb = NetboxInventory()
    devices = nb.get_all_devices()

    # ---- Step 1: Create VLAN on Cisco switches ----
    cisco_devices = [d for d in devices if "cisco" in d.get("platform", "").lower()]
    for device in cisco_devices:
        try:
            driver = DeviceFactory.get_driver(device)
            driver.connect()

            # Create VLAN
            vlan_result = driver.create_vlan(request.vlan_id, request.network_name)
            results["steps_completed"].append({
                "step": "create_vlan",
                "device": device["name"],
                "result": vlan_result
            })

            # Assign ports to VLAN
            for port in request.switch_ports:
                try:
                    assign_result = driver.assign_vlan_to_port(port, request.vlan_id, mode="access")
                    results["steps_completed"].append({
                        "step": "assign_vlan_to_port",
                        "device": device["name"],
                        "port": port,
                        "result": assign_result
                    })
                except Exception as e:
                    results["steps_failed"].append({
                        "step": "assign_vlan_to_port",
                        "device": device["name"],
                        "port": port,
                        "error": str(e)
                    })

            # Enable port security if requested
            if request.enable_port_security:
                for port in request.switch_ports:
                    try:
                        sec_result = driver.configure_port_security(port, max_mac=1, violation_action="shutdown")
                        results["steps_completed"].append({
                            "step": "configure_port_security",
                            "device": device["name"],
                            "port": port,
                            "result": sec_result
                        })
                    except Exception as e:
                        results["steps_failed"].append({
                            "step": "configure_port_security",
                            "device": device["name"],
                            "port": port,
                            "error": str(e)
                        })

            driver.disconnect()

        except Exception as e:
            results["steps_failed"].append({
                "step": "cisco_setup",
                "device": device["name"],
                "error": str(e)
            })

    # ---- Step 2: Create DHCP pool on MikroTik routers ----
    if request.enable_dhcp:
        mikrotik_devices = [d for d in devices if "mikrotik" in d.get("platform", "").lower()
                            or "routeros" in d.get("platform", "").lower()]
        for device in mikrotik_devices:
            try:
                driver = DeviceFactory.get_driver(device)
                driver.connect()

                dhcp_result = driver.create_dhcp_pool(
                    pool_name=request.network_name,
                    network=request.subnet,
                    gateway=request.gateway,
                    dns_servers=request.dns_servers
                )
                results["steps_completed"].append({
                    "step": "create_dhcp_pool",
                    "device": device["name"],
                    "result": dhcp_result
                })

                driver.disconnect()

            except Exception as e:
                results["steps_failed"].append({
                    "step": "create_dhcp_pool",
                    "device": device["name"],
                    "error": str(e)
                })

    # ---- Step 3: Create WiFi SSID on UniFi APs ----
    if request.wifi_ssid and request.wifi_password:
        unifi_devices = [d for d in devices if "unifi" in d.get("platform", "").lower()
                         or "ubiquiti" in d.get("platform", "").lower()]
        for device in unifi_devices:
            try:
                driver = DeviceFactory.get_driver(device)
                driver.connect()

                wifi_result = driver.create_guest_network(
                    ssid=request.wifi_ssid,
                    password=request.wifi_password,
                    guest_portal=False
                )
                results["steps_completed"].append({
                    "step": "create_wifi_ssid",
                    "device": device["name"],
                    "result": wifi_result
                })

                driver.disconnect()

            except Exception as e:
                results["steps_failed"].append({
                    "step": "create_wifi_ssid",
                    "device": device["name"],
                    "error": str(e)
                })

    # Log the provisioning action
    audit_logger.log_security_event(
        "NETWORK_PROVISIONED",
        f"Network '{request.network_name}' (VLAN {request.vlan_id}, subnet {request.subnet}) "
        f"provisioned: {len(results['steps_completed'])} steps OK, "
        f"{len(results['steps_failed'])} steps failed"
    )

    total_steps = len(results["steps_completed"]) + len(results["steps_failed"])
    success = len(results["steps_failed"]) == 0

    event_bus.publish(
        "provision_done", device=request.network_name,
        summary=f"{len(results['steps_completed'])} ok / {len(results['steps_failed'])} failed",
    )

    return {
        "status": "success" if success else "partial",
        "message": (
            f"Network '{request.network_name}' provisioned successfully across all devices."
            if success else
            f"Network '{request.network_name}' provisioned with {len(results['steps_failed'])} errors."
        ),
        "total_steps": total_steps,
        "successful_steps": len(results["steps_completed"]),
        "failed_steps": len(results["steps_failed"]),
        "details": results,
    }


# ============================================================================
# AUDIT LOG ENDPOINTS
# ============================================================================


@router.get("/audit/logs")
async def get_audit_logs(limit: int = 100, current_user: dict = Depends(require_admin)):
    """Retrieve recent audit log entries for security review."""
    try:
        logs = audit_logger.get_recent_logs(limit=limit)
        return {
            "status": "success",
            "count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CONFIGURATION ENDPOINTS
# ============================================================================


@router.get("/config/system")
async def get_system_config(current_user: dict = Depends(require_admin)):
    """Retrieve current system configuration settings."""
    return {
        "status": "success",
        "config": {
            "project_name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "mock_mode": settings.MOCK_MODE,
            "netbox_url": settings.NETBOX_URL,
            "features": {
                "kill_switch": True,
                "scheduler": True,
                "wake_on_lan": True,
                "monitoring": True,
                "network_provisioning": True,
                "audit_logging": True,
                "rate_limiting": True,
            },
        },
    }


# ============================================================================
# HEALTH CHECK
# ============================================================================


@router.get("/health")
async def health_check():
    """Quick health check for the API service."""
    return {
        "status": "healthy",
        "service": "UAF Backend API",
        "version": settings.VERSION,
        "mock_mode": settings.MOCK_MODE,
    }


# ============================================================================
# USER MANAGEMENT (admin-only)
# Accounts are provisioned by an administrator with a role — not self-service
# registration, which is inappropriate for a privileged network tool.
# NOTE: the user store is in-memory; accounts added at runtime reset when the
# backend restarts (the three default roles always exist).
# ============================================================================


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=2, description="Login username")
    password: str = Field(..., min_length=6, description="Initial password (min 6 chars)")
    role: str = Field("viewer", description="Role: admin / operator / viewer")


class ResetPasswordRequest(BaseModel):
    password: str = Field(..., min_length=6, description="New password (min 6 chars)")


@router.get("/users")
async def list_users(current_user: dict = Depends(require_admin)):
    """List all user accounts and their roles (admin-only). No password hashes."""
    try:
        return {"status": "success", "users": user_db.list_users()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users")
async def create_user(request: CreateUserRequest,
                      current_user: dict = Depends(require_admin)):
    """Provision a new user account with a role (admin-only)."""
    if request.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400,
                            detail="Role must be admin, operator, or viewer")
    try:
        user = user_db.create_user(request.username, request.password, request.role)
        audit_logger.log_security_event(
            "USER_CREATED",
            f"User '{user['username']}' created with role '{user['role']}' "
            f"by {current_user.get('username', 'admin')}")
        return {"status": "success",
                "user": {"username": user["username"], "role": user["role"]}}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/users/{username}")
async def delete_user(username: str, current_user: dict = Depends(require_admin)):
    """Remove a user account (admin-only). Cannot delete the last admin."""
    try:
        user_db.delete_user(username)
        audit_logger.log_security_event(
            "USER_DELETED",
            f"User '{username}' deleted by {current_user.get('username', 'admin')}")
        return {"status": "success", "deleted": username}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/{username}/reset-password")
async def reset_user_password(username: str, request: ResetPasswordRequest,
                              current_user: dict = Depends(require_admin)):
    """Admin resets another user's password (admin-only)."""
    try:
        user_db.admin_set_password(username, request.password)
        audit_logger.log_security_event(
            "USER_PASSWORD_RESET",
            f"Password reset for '{username}' by {current_user.get('username', 'admin')}")
        return {"status": "success", "username": username}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))