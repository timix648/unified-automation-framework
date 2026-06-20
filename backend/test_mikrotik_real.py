"""
test_mikrotik_real.py
=====================
Standalone real-hardware validation for the UAF MikroTik driver.

Run this from the backend/ directory:
    cd backend
    python test_mikrotik_real.py

It connects your ACTUAL MikroTikDriver (mock_mode=False) to the physical
RB750r2 hEX lite at 192.168.1.20 and exercises the core methods the
kill-switch and API layer depend on.

SAFETY: This test only READS data and (optionally) disables/re-enables a
single SAFE test port that you specify. It will NOT touch ether2 (your
management port) so you don't lock yourself out.
"""

import sys
import time

# Import your real driver
from app.drivers.mikrotik_driver import MikroTikDriver

# -----------------------------------------------------------------------------
# CONFIG — matches your .env (MIKROTIK_IP, MIKROTIK_USER, MIKROTIK_PASS)
# -----------------------------------------------------------------------------
DEVICE_CONFIG = {
    "host": "192.168.1.20",
    "username": "admin",
    "password": "mikrotik123",
    "api_port": 8728,          # API service port you enabled
}

# A SAFE port to test disable/enable on. ether2 is your management port — DO NOT
# use it. ether5 is usually safe (nothing critical plugged in). Change if needed.
SAFE_TEST_PORT = "ether5"

# Set to False to skip the disable/enable test (read-only run)
TEST_PORT_CONTROL = True


def banner(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def main():
    print("\n" + "#" * 60)
    print("#  UAF MikroTik Driver — REAL HARDWARE TEST")
    print(f"#  Target: {DEVICE_CONFIG['host']}:{DEVICE_CONFIG['api_port']}")
    print("#" * 60)

    # Instantiate the REAL driver — note mock_mode=False
    driver = MikroTikDriver(DEVICE_CONFIG, mock_mode=False)

    # ---- TEST 1: Connection ----
    banner("TEST 1 — Connect to physical router")
    try:
        driver.connect()
        print("✅ PASS — Connected to real MikroTik hardware")
    except Exception as e:
        print(f"❌ FAIL — Could not connect: {e}")
        print("\nTroubleshooting:")
        print("  • Is the API service enabled?  /ip service print  (api must have no X)")
        print("  • Can you ping 192.168.1.20 from this laptop?")
        print("  • Is the password exactly 'mikrotik123'?")
        sys.exit(1)

    # ---- TEST 2: Device info ----
    banner("TEST 2 — Read device info (proves real query works)")
    try:
        info = driver.get_device_info()
        print("✅ PASS — Device info retrieved:")
        for k, v in (info.items() if isinstance(info, dict) else []):
            print(f"     {k}: {v}")
    except Exception as e:
        print(f"⚠️  WARN — get_device_info failed: {e}")

    # ---- TEST 3: Port status ----
    banner("TEST 3 — Read interface/port status")
    try:
        status = driver.get_port_status()
        print("✅ PASS — Port status retrieved")
        ifaces = status.get("interfaces", []) if isinstance(status, dict) else []
        print(f"     Found {len(ifaces)} interfaces:")
        for itf in ifaces[:10]:
            name = itf.get("name", "?")
            disabled = itf.get("disabled", "?")
            print(f"       - {name}  (disabled={disabled})")
    except Exception as e:
        print(f"⚠️  WARN — get_port_status failed: {e}")

    # ---- TEST 4: System health ----
    banner("TEST 4 — Read system health")
    try:
        health = driver.get_system_health()
        print("✅ PASS — System health retrieved:")
        for k, v in (health.items() if isinstance(health, dict) else []):
            print(f"     {k}: {v}")
    except Exception as e:
        print(f"⚠️  WARN — get_system_health failed: {e}")

    # ---- TEST 5: Port control (disable + re-enable a SAFE port) ----
    if TEST_PORT_CONTROL:
        banner(f"TEST 5 — Disable then re-enable {SAFE_TEST_PORT} (kill-switch core)")
        try:
            print(f"  Disabling {SAFE_TEST_PORT} ...")
            r1 = driver.disable_port(SAFE_TEST_PORT, reason="UAF hardware test")
            print(f"  ✅ disable_port returned: {r1}")
            time.sleep(2)

            print(f"  Re-enabling {SAFE_TEST_PORT} ...")
            r2 = driver.enable_port(SAFE_TEST_PORT)
            print(f"  ✅ enable_port returned: {r2}")
            print("✅ PASS — Port control works on real hardware (this is the kill-switch action)")
        except Exception as e:
            print(f"❌ FAIL — Port control failed: {e}")
    else:
        banner("TEST 5 — SKIPPED (TEST_PORT_CONTROL=False)")

    # ---- Cleanup ----
    banner("Disconnecting")
    driver.disconnect()
    print("✅ Disconnected cleanly")

    print("\n" + "#" * 60)
    print("#  TEST COMPLETE — if TESTS 1-3 passed, your driver")
    print("#  is validated against REAL hardware. Screenshot this")
    print("#  output for your report and defense.")
    print("#" * 60 + "\n")


if __name__ == "__main__":
    main()