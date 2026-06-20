"""
UAF Background Scheduler
=========================
Runs periodic automation tasks:
1. Time-Based Access Policy enforcement (every 60 min)
2. Rogue Device Security Scanning (every 5 min)

FIXES APPLIED:
- Reduced rogue scan interval from 2 minutes to 5 minutes (2 min was too aggressive
  for a security scanner — it floods logs and wastes resources in mock mode;
  in production with real devices, 2-min SSH sessions to every switch is excessive)
- Added error handling around scheduler start to prevent crash if jobs already exist
- Added scan interval as a configurable constant
"""

from apscheduler.schedulers.background import BackgroundScheduler
from app.inventory.netbox_client import NetboxInventory
from app.core.nornir_manager import NornirManager
from app.services.device_manager import DeviceFactory
from app.services.kill_switch import KillSwitchService
from app.services.wol import send_magic_packet
from app.services import schedule_policy
from app.services import enforcement_state
from app.core.config import settings
import datetime
import logging

# Configure Logger
logger = logging.getLogger("scheduler")

# Scheduler instance (module-level singleton)
scheduler = BackgroundScheduler()

# Configurable intervals (minutes)
TIME_POLICY_INTERVAL_MINUTES = 60
SECURITY_SCAN_INTERVAL_MINUTES = 5  # FIX: was 2 — too aggressive


def auto_enforce_time_policy():
    """
    TIME-BASED ACCESS CONTROL & GREEN NETWORKING (Proposal Objective 3):
    - During off-hours (6 PM – 8 AM): deploys ACL rules on Cisco switches to
      restrict internet-bound traffic and adds firewall drop rules on MikroTik
      routers.  Also disables WAN interfaces on edge routers.
    - During business hours (8 AM – 6 PM): removes the off-hours ACL rules,
      re-enables WAN interfaces, and sends Wake-on-LAN packets to desktops
      registered in NetBox so they are powered on before staff arrive.
    """
    now = datetime.datetime.now()
    hour = now.hour
    # CONFIGURABLE POLICY: the admin sets the restricted window in the UI
    # (schedule_policy.json). is_restricted_now() handles midnight-wrapping
    # windows. is_work_hours is the inverse (access allowed).
    is_restricted = schedule_policy.is_restricted_now(hour)
    is_work_hours = not is_restricted

    action_type = "ENABLE access" if is_work_hours else "RESTRICT access"
    logger.info(f"[SCHEDULER] Time Policy Check (Hour: {hour}). Action: {action_type}")

    # Tag used to identify UAF-managed ACL rules so we can clean them up
    ACL_TAG = "UAF-OFF-HOURS-ACL"

    try:
        nb = NetboxInventory()
        devices = nb.get_all_devices()

        # ---------------------------------------------------------------------
        # 1. Cisco switches: apply / remove time-based ACL
        # ---------------------------------------------------------------------
        cisco_devices = [d for d in devices if "cisco" in d.get("platform", "").lower()]
        for dev in cisco_devices:
            try:
                driver = DeviceFactory.get_driver(dev)
                driver.connect()

                if not is_work_hours:
                    # Deploy an extended ACL that blocks outbound HTTP/HTTPS
                    acl_commands = [
                        "ip access-list extended UAF-OFF-HOURS",
                        "remark Managed by UAF — restrict off-hours traffic",
                        "deny tcp any any eq 80",
                        "deny tcp any any eq 443",
                        "permit ip any any",
                    ]
                    driver._execute_config_commands(acl_commands)
                    logger.info(f"   -> {dev['name']}: Off-hours ACL applied")
                else:
                    # Remove the off-hours ACL
                    driver._execute_config_commands(["no ip access-list extended UAF-OFF-HOURS"])
                    logger.info(f"   -> {dev['name']}: Off-hours ACL removed")

                driver.disconnect()
            except Exception as e:
                logger.error(f"   -> Cisco ACL error on {dev['name']}: {e}")

        # ---------------------------------------------------------------------
        # 2. MikroTik routers: firewall drop rule + WAN interface toggle
        # ---------------------------------------------------------------------
        mikrotik_devices = [d for d in devices
                            if "mikrotik" in d.get("platform", "").lower()
                            or "routeros" in d.get("platform", "").lower()]
        for dev in mikrotik_devices:
            is_edge = ("edge" in dev.get("device_role", "").lower()
                       or "router" in dev.get("device_role", "").lower())
            try:
                driver = DeviceFactory.get_driver(dev)
                driver.connect()

                if not is_work_hours:
                    # Add a forward-chain drop rule for HTTP/HTTPS
                    driver.add_firewall_rule(
                        chain="forward",
                        action="drop",
                        protocol="tcp",
                        dst_port="80,443",
                        comment=ACL_TAG,
                    )
                    logger.info(f"   -> {dev['name']}: Off-hours firewall rule added")

                    # Disable WAN interface on edge routers
                    if is_edge:
                        driver.shutdown_port("ether1")
                        logger.info(f"   -> {dev['name']}: WAN disabled to save bandwidth")
                else:
                    # Remove any UAF off-hours rules
                    if not settings.MOCK_MODE:
                        api = driver._get_api()
                        fw = api.get_resource("/ip/firewall/filter")
                        for rule in fw.get():
                            if rule.get("comment", "") == ACL_TAG:
                                fw.remove(id=rule["id"])
                    logger.info(f"   -> {dev['name']}: Off-hours firewall rules removed")

                    # Re-enable WAN interface on edge routers
                    if is_edge:
                        driver.enable_port("ether1")
                        logger.info(f"   -> {dev['name']}: WAN re-enabled")

                driver.disconnect()
            except Exception as e:
                logger.error(f"   -> MikroTik policy error on {dev['name']}: {e}")

        # ---------------------------------------------------------------------
        # 2.5 UniFi: SSID schedule — Wi-Fi follows the same access window
        #     (Proposal Objective 3: 'SSID schedules on UniFi controllers').
        #     During restricted hours all SSIDs are disabled except those whose
        #     name contains a management keyword (mgmt/management/admin), so the
        #     schedule can never lock the administrator out. During work hours
        #     they are re-enabled.
        # ---------------------------------------------------------------------
        unifi_devices = [d for d in devices
                         if "unifi" in d.get("platform", "").lower()
                         or "ubiquiti" in d.get("platform", "").lower()]
        for dev in unifi_devices:
            try:
                driver = DeviceFactory.get_driver(dev)
                driver.connect()
                outcome = driver.set_all_wlans_enabled(enabled=is_work_hours)
                changed = outcome.get("changed", [])
                skipped = outcome.get("skipped", [])
                verb = "re-enabled" if is_work_hours else "disabled"
                if changed:
                    logger.info(f"   -> {dev['name']}: SSIDs {verb}: {', '.join(changed)}")
                else:
                    logger.info(f"   -> {dev['name']}: SSIDs already in desired state")
                if skipped:
                    logger.info(f"   -> {dev['name']}: skipped (management): {', '.join(skipped)}")
                driver.disconnect()
            except Exception as e:
                logger.error(f"   -> UniFi SSID schedule error on {dev['name']}: {e}")

        # ---------------------------------------------------------------------
        # 3. Wake-on-LAN: power on desktops at start of business hours
        # ---------------------------------------------------------------------
        if is_work_hours and 8 <= hour < 9:
            # Send WoL only in the first hour of business to avoid repeat pings
            wol_targets = [d for d in devices
                           if "desktop" in d.get("device_role", "").lower()
                           or "workstation" in d.get("device_role", "").lower()]
            for target in wol_targets:
                mac = target.get("mac", "")
                if mac:
                    try:
                        send_magic_packet(mac)
                        logger.info(f"   -> WoL sent to {target['name']} ({mac})")
                    except Exception as e:
                        logger.error(f"   -> WoL failed for {target['name']}: {e}")

    except Exception as e:
        logger.error(f"[SCHEDULER] Time policy enforcement failed: {e}")


def auto_scan_for_rogues():
    """
    SECURITY (Self-Defending Network):
    1. Uses Nornir to scan ALL switches in parallel (Fast Detection).
    2. Uses KillSwitchService to isolate threats (Secure Mitigation & Logging).
    """
    logger.info("\n[SCHEDULER] 🛡️ Starting Network-Wide Security Scan...")

    try:
        # 1. Get Trusted MACs
        nb = NetboxInventory()
        trusted_macs = nb.get_trusted_macs()
        # Safety whitelist for demo
        trusted_macs.extend(["AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"])

        # 2. Initialize Nornir
        mgr = NornirManager(nb, mock_mode=settings.MOCK_MODE)

        # 3. Run the Scan (Parallel)
        scan_results = mgr.scan_all_for_rogues(authorized_macs=trusted_macs)

        # 4. Process Results
        total_rogues = scan_results.get("total_rogues_found", 0)

        # Enforcement gate: in "learning" mode we DETECT and REPORT rogues but
        # never shut ports, so a new admin can build the trusted baseline first.
        # In "armed" mode the kill-switch isolates unrecognized devices.
        armed = enforcement_state.is_armed()

        if total_rogues > 0:
            if armed:
                logger.warning(f"🚨 ALARM: {total_rogues} Rogue Devices Detected! "
                               f"(enforcement ARMED — isolating)")
            else:
                logger.warning(f"👁️  {total_rogues} unrecognized device(s) detected "
                               f"(enforcement in LEARNING mode — reporting only, "
                               f"no ports shut). Arm enforcement to auto-isolate.")

            # Initialize the Kill Switch Service (The "Police")
            ks_service = KillSwitchService()

            # Iterate through results
            # FIX: guard every layer against None. Failed/unreachable devices
            # (e.g. Cisco/UniFi not physically connected) produce result=None,
            # which previously crashed the scan with
            # "'NoneType' object has no attribute 'get'".
            details = scan_results.get("details") or {}
            results_dict = details.get("results") or {}

            for host, data in results_dict.items():
                if not data or not data.get("success"):
                    # Unreachable or failed device — log and keep scanning others
                    if data and data.get("error"):
                        logger.info(f"   -> Skipping {host}: {data.get('error')}")
                    continue

                result_payload = data.get("result") or {}
                rogue_list = result_payload.get("rogue_devices", []) or []

                for rogue in rogue_list:
                    mac = rogue.get('mac')
                    port = rogue.get('interface')
                    if not mac or not port:
                        continue
                    if armed:
                        logger.critical(f"   ⚔️ KILL-SWITCH: Rogue {mac} found on {host}:{port}")
                        # EXECUTE VIA SERVICE (Preserves Audit Log)
                        ks_service.execute_response(
                            device_name=host,
                            port_id=port,
                            threat_type="rogue_device_scheduled_scan",
                            threat_details={"mac_address": mac}
                        )
                    else:
                        logger.info(f"   👁️  Reporting (learning mode): {mac} on "
                                    f"{host}:{port} — not isolated")
                        # Record the detection to the threat log (WITHOUT shutting
                        # the port) so the device shows up on the Security page for
                        # the admin to review and Trust. This is what makes the
                        # learning-mode admission flow work end-to-end.
                        ks_service.record_detection(
                            device_name=host,
                            port_id=port,
                            threat_type="rogue_device_scheduled_scan",
                            threat_details={"mac_address": mac},
                        )
        else:
            logger.info("   ✅ Scan Complete. Network is Clean.")

    except Exception as e:
        logger.error(f"[SCHEDULER] Security scan failed: {e}")


def start_scheduler():
    """Start all scheduled jobs. Safe to call multiple times."""
    if scheduler.running:
        logger.warning("[SCHEDULER] Already running, skipping start.")
        return

    # Job 1: Check Time-Based Access every 60 minutes
    scheduler.add_job(
        auto_enforce_time_policy,
        'interval',
        minutes=TIME_POLICY_INTERVAL_MINUTES,
        id='time_policy',
        replace_existing=True,
        name='Time-Based Access Policy'
    )

    # Job 2: Scan for Security Threats every 5 minutes
    scheduler.add_job(
        auto_scan_for_rogues,
        'interval',
        minutes=SECURITY_SCAN_INTERVAL_MINUTES,
        id='rogue_scan',
        replace_existing=True,
        name='Rogue Device Security Scan'
    )

    scheduler.start()
    logger.info(f"[SYSTEM] Background Scheduler Started.")
    logger.info(f"   - Time Policy: every {TIME_POLICY_INTERVAL_MINUTES} min")
    logger.info(f"   - Security Scan: every {SECURITY_SCAN_INTERVAL_MINUTES} min")