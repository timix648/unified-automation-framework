"""
UAF — Unified Automation Framework | Operations Console (Reflex)
=================================================================
Industry-standard multi-page admin console.

PAGES:
  /login       Sign-in (JWT, role-aware — admin / operator / viewer)
  /            Dashboard  — KPIs, live status, recent activity
  /devices     Devices    — searchable inventory + live interface table + port control
  /security    Security   — rogue threats, one-click trust, manual scan
  /schedule    Schedule   — admin-set access window, jobs, Wake-on-LAN
  /audit       Audit      — server-side audit trail (who did what, when)
  /settings    Settings   — connection info + authorized-device registry
  /how         How It Works — plain-language explainer

Run:
  Backend  (term 1): cd backend ; python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
  Frontend (term 2): cd frontend ; python -m reflex run --backend-port 8001
  Open: http://localhost:3000   (sign in: admin / admin123)

LIVE BACKGROUND: drop your video at frontend/assets/bg.mp4 and set USE_VIDEO_BG = True.
"""

import reflex as rx
import httpx
import asyncio
import os
from datetime import datetime
from typing import List, Dict, Any

# API_BASE is env-overridable so the same image works locally and in containers.
# Local default talks to a backend on the host; in Docker set API_BASE to the
# backend's service address (e.g. http://uaf-backend:8000/api).
API_BASE = os.getenv("API_BASE", "http://localhost:8000/api")

USE_VIDEO_BG = True
VIDEO_FILE = "bg.mp4"
POLL_SECONDS = 5

# Design tokens ---------------------------------------------------------------
INK = "#0a0e14"
PANEL = "rgba(18, 26, 38, 0.55)"
PANEL_BORDER = "rgba(120, 160, 200, 0.18)"
ACCENT = "#34d399"
ACCENT_DIM = "rgba(52, 211, 153, 0.15)"
DANGER = "#f87171"
DANGER_DIM = "rgba(248, 113, 113, 0.14)"
WARN = "#fbbf24"
WARN_DIM = "rgba(251, 191, 36, 0.12)"
INFO = "#60a5fa"
INFO_DIM = "rgba(96, 165, 250, 0.14)"
TEXT = "#e6edf3"
MUTED = "#7d8da1"
MONO = "'JetBrains Mono', 'SF Mono', 'Consolas', monospace"
SANS = "'Inter', 'Segoe UI', system-ui, sans-serif"


# ── 12h <-> 24h helpers (Python-side, used in event handlers) ────────────────
def _to_12h(hour24: int):
    """0-23 -> (hour 1-12, 'AM'/'PM')."""
    ampm = "AM" if hour24 < 12 else "PM"
    h12 = hour24 % 12
    if h12 == 0:
        h12 = 12
    return h12, ampm


def _to_24h(hour12_str: str, ampm: str) -> int:
    """(hour 1-12 as str, 'AM'/'PM') -> 0-23."""
    try:
        h = int(hour12_str)
    except (ValueError, TypeError):
        h = 12
    h = h % 12  # 12 -> 0
    if ampm.upper() == "PM":
        h += 12
    return h


HOURS_12 = [str(h) for h in range(1, 13)]


def _fmt_ts(ts: str) -> str:
    """ISO timestamp -> 'YYYY-MM-DD HH:MM:SS' for table display."""
    if not ts:
        return "—"
    return ts[:19].replace("T", " ")


# ── State ────────────────────────────────────────────────────────────────────
class State(rx.State):
    # session / auth — token + identity persist in browser LocalStorage so a
    # page refresh restores the session (industry-standard console behavior).
    # The session ends when the user logs out or the JWT expires (401).
    token: str = rx.LocalStorage("", name="uaf_token")
    current_user: str = rx.LocalStorage("", name="uaf_user")
    current_role: str = rx.LocalStorage("", name="uaf_role")
    connected: bool = False  # runtime flag, rebuilt by guard() after refresh
    username_input: str = "admin"
    password_input: str = ""
    login_error: str = ""

    # global UI
    status_msg: str = "Standby."
    loading: bool = False
    live_enabled: bool = True
    live_running: bool = False

    # data
    devices: List[Dict[str, Any]] = []
    device_search: str = ""
    selected_device: str = ""
    selected_status: str = "unknown"
    interfaces: List[Dict[str, Any]] = []
    action_log: List[str] = []
    busy_port: str = ""

    # security
    threats: List[Dict[str, Any]] = []
    threat_count: int = 0
    enforcement_mode: str = "learning"   # "learning" or "armed"
    enforcement_by: str = ""
    # user management (admin)
    users: List[Dict[str, Any]] = []
    nu_username: str = ""
    nu_password: str = ""
    nu_role: str = "viewer"
    confirm_del_user: str = ""

    # real-time alerts (pushed over WebSocket, Report 4.7)
    alerts: List[Dict[str, Any]] = []
    ws_running: bool = False
    ws_connected: bool = False

    # scheduler
    scheduler_running: bool = False
    scheduler_jobs: List[Dict[str, Any]] = []

    # authorized devices registry (editable source of truth)
    authorized: List[Dict[str, Any]] = []
    new_mac: str = ""
    new_label: str = ""

    # account: change own password
    old_pw: str = ""
    new_pw: str = ""
    confirm_pw: str = ""

    # audit trail (server-side)
    audit_logs: List[Dict[str, Any]] = []

    # schedule policy — stored internally as 0-23
    block_start: int = 18
    block_end: int = 8
    policy_enabled: bool = True
    start_hour12: str = "6"
    start_ampm: str = "PM"
    end_hour12: str = "8"
    end_ampm: str = "AM"

    # monitoring
    net_availability: str = "—"
    net_if_up: int = 0
    net_if_down: int = 0
    net_if_total: int = 0
    monitor_rows: List[Dict[str, Any]] = []
    monitor_loading: bool = False

    # wireless networks (UniFi SSIDs)
    wlans: List[Dict[str, Any]] = []
    wlan_device: str = ""
    wlan_note: str = ""

    # SSID editing (edit/delete lifecycle)
    editing_wlan_id: str = ""
    edit_ssid_name: str = ""
    edit_ssid_pass: str = ""
    edit_ssid_vlan: str = ""
    confirm_delete_wlan: str = ""

    # network provisioning (admin)
    prov_name: str = ""
    prov_vlan: str = "20"
    prov_subnet: str = "192.168.20.0/24"
    prov_gateway: str = "192.168.20.1"
    prov_ports: str = "GigabitEthernet0/1, GigabitEthernet0/2"
    prov_ssid: str = ""
    prov_psk: str = ""
    prov_dhcp: bool = True
    prov_sec: bool = True
    prov_running: bool = False
    prov_results: List[Dict[str, Any]] = []
    prov_summary: str = ""

    # wake-on-lan
    wol_selected: List[str] = []
    confirm_wake_all: bool = False
    confirm_remove_mac: str = ""

    # ── helpers ──
    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.action_log = [f"[{ts}] {msg}"] + self.action_log[:14]

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    @rx.var
    def device_count(self) -> int:
        return len(self.devices)

    @rx.var
    def online_count(self) -> int:
        return len([d for d in self.devices if d.get("status") == "online"])

    @rx.var
    def filtered_devices(self) -> List[Dict[str, Any]]:
        q = self.device_search.strip().lower()
        if not q:
            return self.devices
        return [d for d in self.devices
                if q in d.get("name", "").lower()
                or q in d.get("ip", "").lower()
                or q in d.get("platform", "").lower()]

    @rx.var
    def role_can_operate(self) -> bool:
        return self.current_role in ("admin", "operator")

    @rx.var
    def role_is_admin(self) -> bool:
        return self.current_role == "admin"

    # ── auth flow ──
    def set_username_input(self, v: str):
        self.username_input = v

    def set_password_input(self, v: str):
        self.password_input = v

    def set_device_search(self, v: str):
        self.device_search = v

    async def guard(self):
        """Page gate. No token -> /login. Token but fresh browser session
        (e.g. after a refresh) -> validate the token, restore data + live feed.
        Expired/invalid token -> clear it and return to /login."""
        if not self.token:
            yield rx.redirect("/login")
            return
        if self.connected:
            return
        # Rehydrate after refresh: validate the stored token with a real call.
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{API_BASE}/devices", headers=self._headers())
            if r.status_code == 401:
                self.token = ""
                self.current_user = ""
                self.current_role = ""
                self.status_msg = "Session expired — please sign in again."
                yield rx.redirect("/login")
                return
        except Exception:
            # Backend briefly unreachable: keep the session; loaders will report.
            pass
        self.connected = True
        self.status_msg = f"Session restored — {self.current_user} ({self.current_role})."
        self._log(f"Session restored for {self.current_user}")
        async for _ in self.load_devices():
            pass
        await self.probe_health()
        yield State.live_feed
        yield State.alert_ws_feed

    def guard_login(self):
        """If already signed in, skip the login page."""
        if self.token:
            return rx.redirect("/")

    async def login(self):
        if not self.username_input.strip() or not self.password_input:
            self.login_error = "Enter a username and password."
            return
        self.loading = True
        self.login_error = ""
        yield
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/auth/login",
                                      json={"username": self.username_input.strip(),
                                            "password": self.password_input})
                r.raise_for_status()
                data = r.json()
                self.token = data["access_token"]
                user = data.get("user", {}) or {}
                self.current_user = user.get("username", self.username_input.strip())
                self.current_role = user.get("role", "user")
                self.connected = True
                self.password_input = ""
                self.status_msg = f"Signed in as {self.current_user} ({self.current_role})."
                self._log(f"Authenticated as {self.current_user} — role: {self.current_role}")
        except httpx.HTTPStatusError:
            self.loading = False
            self.login_error = "Invalid username or password."
            return
        except Exception as e:
            self.loading = False
            self.login_error = f"Backend unreachable: {e}"
            return
        async for _ in self.load_devices():
            pass
        await self.probe_health()
        self.loading = False
        yield rx.redirect("/")
        yield State.live_feed
        yield State.alert_ws_feed

    async def logout(self):
        self.token = ""
        self.connected = False
        self.current_user = ""
        self.current_role = ""
        self.live_enabled = True
        self.status_msg = "Signed out."
        self.devices = []
        self.interfaces = []
        self.selected_device = ""
        self.alerts = []
        self.ws_connected = False
        return rx.redirect("/login")

    # ── data loaders ──
    async def load_devices(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/devices", headers=self._headers())
                r.raise_for_status()
                devs = r.json().get("devices", [])
                for d in devs:
                    d["status"] = "unknown"
                self.devices = devs
                self._log(f"Loaded {len(self.devices)} devices from inventory")
        except Exception as e:
            self._log(f"Device load failed: {e}")
        yield

    async def probe_health(self):
        """TCP-probe every inventory device so status dots are live."""
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(f"{API_BASE}/devices/health", headers=self._headers())
                r.raise_for_status()
                data = r.json()
                health = data.get("health", {})
                self.devices = [
                    {**d, "status": health.get(d["name"], {}).get("status", "unknown")}
                    for d in self.devices
                ]
                if self.selected_device:
                    self.selected_status = health.get(
                        self.selected_device, {}
                    ).get("status", self.selected_status)
                self.status_msg = (f"Reachability: {data.get('online', 0)}/"
                                   f"{data.get('count', len(self.devices))} devices online")
        except Exception as e:
            self._log(f"Health probe failed: {e}")

    def _apply_status(self, name: str, status: str):
        self.devices = [{**d, "status": status} if d["name"] == name else d for d in self.devices]
        if name == self.selected_device:
            self.selected_status = status

    async def select_device(self, name: str):
        self.selected_device = name
        self.interfaces = []
        self.selected_status = "unknown"
        self.loading = True
        self.status_msg = f"Reading interfaces from {name}…"
        yield
        await self._fetch_interfaces(name)
        self.loading = False

    async def _fetch_interfaces(self, name: str):
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                r = await client.get(f"{API_BASE}/devices/{name}/interfaces", headers=self._headers())
                r.raise_for_status()
                data = r.json()
                if data.get("status") == "unreachable":
                    self.interfaces = []
                    self._apply_status(name, "offline")
                    self.status_msg = f"{name} is offline — not reachable."
                    self._log(f"{name} unreachable — device offline")
                else:
                    self.interfaces = data.get("interfaces", [])
                    self._apply_status(name, "online")
                    self.status_msg = f"{name}: {len(self.interfaces)} interfaces (live)"
                    self._log(f"Read {len(self.interfaces)} interfaces from {name}")
        except Exception:
            self.interfaces = []
            self._apply_status(name, "offline")
            self.status_msg = f"{name} is offline — not reachable."
            self._log(f"{name} unreachable — device offline")

    async def toggle_port(self, port_id: str, currently_disabled: bool):
        if not self.selected_device:
            return
        action = "enable" if currently_disabled else "shutdown"
        verb = "Enabling" if currently_disabled else "Disabling"
        self.busy_port = port_id
        self.status_msg = f"{verb} {port_id} on {self.selected_device}…"
        yield
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                r = await client.post(f"{API_BASE}/devices/port-control", headers=self._headers(),
                                      json={"device_name": self.selected_device,
                                            "port_id": port_id, "action": action})
                r.raise_for_status()
                done = "Enabled" if currently_disabled else "Disabled"
                self._log(f"{done} {port_id} → success (live on hardware)")
                self.status_msg = f"{done} {port_id} ✓"
        except Exception as e:
            self.status_msg = f"Port action failed on {port_id}."
            self._log(f"Port action failed on {port_id}: {e}")
            self.busy_port = ""
            return
        await asyncio.sleep(1.2)
        await self._fetch_interfaces(self.selected_device)
        self.busy_port = ""

    # ── live telemetry (background polling over Reflex's WebSocket) ──
    def toggle_live(self):
        self.live_enabled = not self.live_enabled
        self.status_msg = "Live updates resumed." if self.live_enabled else "Live updates paused."
        if self.live_enabled and self.token and not self.live_running:
            return State.live_feed

    @rx.event(background=True)
    async def live_feed(self):
        async with self:
            if self.live_running:
                return
            self.live_running = True
        try:
            while True:
                async with self:
                    tok = self.token
                    keep = bool(tok) and self.live_enabled
                if not keep:
                    break
                health = threats = sched = None
                expired = False
                try:
                    async with httpx.AsyncClient(timeout=15) as client:
                        hdr = {"Authorization": f"Bearer {tok}"}
                        r1 = await client.get(f"{API_BASE}/devices/health", headers=hdr)
                        if r1.status_code == 401:
                            expired = True
                        health = r1.json() if r1.status_code == 200 else None
                        r2 = await client.get(f"{API_BASE}/security/threats", headers=hdr)
                        threats = r2.json() if r2.status_code == 200 else None
                        r3 = await client.get(f"{API_BASE}/scheduler/status", headers=hdr)
                        sched = r3.json() if r3.status_code == 200 else None
                except Exception:
                    pass
                if expired:
                    async with self:
                        self.token = ""
                        self.current_user = ""
                        self.current_role = ""
                        self.connected = False
                        self.status_msg = "Session expired — please sign in again."
                    break
                async with self:
                    if health:
                        h = health.get("health", {})
                        self.devices = [
                            {**d, "status": h.get(d["name"], {}).get("status", d.get("status", "unknown"))}
                            for d in self.devices
                        ]
                        if self.selected_device and self.selected_device in h:
                            self.selected_status = h[self.selected_device].get(
                                "status", self.selected_status)
                    if threats:
                        self.threats = threats.get("threats", [])
                        self.threat_count = threats.get("count", len(self.threats))
                    if sched:
                        self.scheduler_running = sched.get("running", False)
                        self.scheduler_jobs = sched.get("jobs", [])
                await asyncio.sleep(POLL_SECONDS)
        finally:
            async with self:
                self.live_running = False

    # ── real-time alert channel (WebSocket push, Report 4.7) ──
    def _handle_ws_event(self, ev: Dict[str, Any]):
        """Apply one pushed event to state. Called inside `async with self`."""
        t = ev.get("type", "")
        if t == "connected":
            self.ws_connected = True
            self.status_msg = "Real-time alert channel connected."
            return
        if t == "heartbeat":
            # Keep-alive tick from the server; confirms the channel is live.
            self.ws_connected = True
            return
        if t == "device_status":
            h = ev.get("health", {}) or {}
            self.devices = [
                {**d, "status": h.get(d["name"], d.get("status", "unknown"))}
                for d in self.devices
            ]
            if self.selected_device and self.selected_device in h:
                self.selected_status = h[self.selected_device]
            return
        # security-relevant events -> prepend to the live feed + surface a toast
        label = {
            "threat": "Threat detected",
            "port_control": "Port action",
            "port_restored": "Port restored",
            "provision_done": "Provision complete",
        }.get(t, t)
        bits = [ev.get("device"), ev.get("port"), ev.get("threat_type"),
                ev.get("action"), ev.get("reason"), ev.get("summary")]
        detail = " · ".join(str(b) for b in bits if b)
        entry = {"ts": ev.get("ts", "")[11:19], "label": label,
                 "detail": detail, "kind": t}
        self.alerts = [entry] + self.alerts[:30]
        self.status_msg = f"{label}: {detail}" if detail else label
        self._log(f"[live] {label} {detail}".rstrip())

    @rx.event(background=True)
    async def alert_ws_feed(self):
        """Connect to the backend WebSocket and stream events into state.

        Runs alongside the polling live_feed: the WebSocket delivers security
        alerts and status changes instantly, while polling remains a resilient
        fallback if the socket drops. Reconnects with backoff while signed in.
        """
        import json
        try:
            import websockets
        except Exception:
            async with self:
                self._log("websockets package missing — real-time alerts disabled")
            return

        async with self:
            if self.ws_running:
                return
            self.ws_running = True

        ws_base = API_BASE.replace("https://", "wss://").replace("http://", "ws://")
        url = f"{ws_base}/ws/events"
        backoff = 2
        try:
            while True:
                async with self:
                    tok = self.token
                    keep = bool(tok) and self.live_enabled
                if not keep:
                    break
                try:
                    async with websockets.connect(f"{url}?token={tok}",
                                                  ping_interval=20,
                                                  ping_timeout=60,
                                                  open_timeout=30,
                                                  close_timeout=5,
                                                  max_queue=64) as ws:
                        backoff = 2  # reset on a good connection
                        async for raw in ws:
                            try:
                                ev = json.loads(raw)
                            except Exception:
                                continue
                            async with self:
                                if not self.token or not self.live_enabled:
                                    break
                                self._handle_ws_event(ev)
                except Exception as e:
                    async with self:
                        self.ws_connected = False
                        self._log(f"Alert channel reconnecting ({e})")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 30)
        finally:
            async with self:
                self.ws_running = False
                self.ws_connected = False

    async def refresh_all(self):
        self.status_msg = "Refreshing…"
        yield
        async for _ in self.load_devices():
            pass
        await self.probe_health()
        async for _ in self.load_security():
            pass
        async for _ in self.load_scheduler():
            pass

    # ── security page ──
    async def load_security(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/security/threats", headers=self._headers())
                r.raise_for_status()
                data = r.json()
                self.threats = data.get("threats", [])
                self.threat_count = data.get("count", 0)
        except Exception as e:
            self._log(f"Threat load failed: {e}")
        yield

    async def run_scan(self):
        if not self.token:
            return
        self.status_msg = "Triggering network-wide security scan…"
        self._log("Manual security scan initiated")
        yield
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(f"{API_BASE}/security/scan", headers=self._headers())
                r.raise_for_status()
                self.status_msg = "Scan running in background — results update live."
        except Exception as e:
            self.status_msg = f"Scan trigger failed: {e}"
            self._log(f"Scan trigger failed: {e}")
        await asyncio.sleep(3)
        async for _ in self.load_security():
            pass

    @rx.var
    def is_armed(self) -> bool:
        return self.enforcement_mode == "armed"

    async def load_enforcement(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/security/enforcement",
                                     headers=self._headers())
                r.raise_for_status()
                e = r.json().get("enforcement", {}) or {}
                self.enforcement_mode = e.get("mode", "learning")
                self.enforcement_by = e.get("updated_by", "")
        except Exception as ex:
            self._log(f"Enforcement state load failed: {ex}")
        yield

    async def set_enforcement(self, mode: str):
        """Arm or return to learning. Admin-only on the backend."""
        if not self.token:
            return
        self.status_msg = ("Arming enforcement…" if mode == "armed"
                           else "Switching to learning mode…")
        yield
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/security/enforcement",
                                      headers=self._headers(), json={"mode": mode})
                r.raise_for_status()
                e = r.json().get("enforcement", {}) or {}
                self.enforcement_mode = e.get("mode", mode)
                if mode == "armed":
                    self.status_msg = ("Enforcement ARMED — unrecognized devices "
                                       "will now be isolated automatically.")
                    self._log("Enforcement armed — kill-switch active")
                else:
                    self.status_msg = ("Learning mode — detection only, no ports "
                                       "will be shut.")
                    self._log("Enforcement set to learning")
        except httpx.HTTPStatusError as ex:
            if ex.response.status_code == 403:
                self.status_msg = "Only an admin can change enforcement mode."
            else:
                self.status_msg = f"Enforcement change failed: {ex}"
        except Exception as ex:
            self.status_msg = f"Enforcement change failed: {ex}"

    async def load_security_page(self):
        """Security page mount: threats + enforcement state together."""
        async for _ in self.load_security():
            pass
        async for _ in self.load_enforcement():
            pass
        yield

    # ── user management (admin) ──
    def set_nu_username(self, v: str):
        self.nu_username = v

    def set_nu_password(self, v: str):
        self.nu_password = v

    def set_nu_role(self, v: str):
        self.nu_role = v

    async def load_users(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/users", headers=self._headers())
                r.raise_for_status()
                self.users = r.json().get("users", [])
        except httpx.HTTPStatusError as ex:
            if ex.response.status_code == 403:
                self.users = []
            else:
                self._log(f"User list load failed: {ex}")
        except Exception as ex:
            self._log(f"User list load failed: {ex}")
        yield

    async def create_user(self):
        if not self.token:
            return
        if not self.nu_username.strip() or len(self.nu_password) < 6:
            self.status_msg = "Username required and password must be 6+ characters."
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/users", headers=self._headers(),
                                      json={"username": self.nu_username.strip(),
                                            "password": self.nu_password,
                                            "role": self.nu_role})
                r.raise_for_status()
                self.status_msg = f"User '{self.nu_username.strip()}' created ({self.nu_role})."
                self._log(f"Created user {self.nu_username.strip()} ({self.nu_role})")
                self.nu_username = ""
                self.nu_password = ""
                self.nu_role = "viewer"
        except httpx.HTTPStatusError as ex:
            if ex.response.status_code == 403:
                self.status_msg = "Only an admin can create users."
            elif ex.response.status_code == 400:
                self.status_msg = "That username already exists (or invalid input)."
            else:
                self.status_msg = f"Create user failed: {ex}"
        except Exception as ex:
            self.status_msg = f"Create user failed: {ex}"
        async for _ in self.load_users():
            pass

    def ask_delete_user(self, username: str):
        self.confirm_del_user = username

    def cancel_delete_user(self):
        self.confirm_del_user = ""

    async def delete_user(self, username: str):
        if not self.token:
            return
        self.confirm_del_user = ""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.delete(f"{API_BASE}/users/{username}",
                                        headers=self._headers())
                r.raise_for_status()
                self.status_msg = f"User '{username}' deleted."
                self._log(f"Deleted user {username}")
        except httpx.HTTPStatusError as ex:
            if ex.response.status_code == 400:
                self.status_msg = "Cannot delete the last remaining admin."
            elif ex.response.status_code == 403:
                self.status_msg = "Only an admin can delete users."
            else:
                self.status_msg = f"Delete failed: {ex}"
        except Exception as ex:
            self.status_msg = f"Delete failed: {ex}"
        async for _ in self.load_users():
            pass

    async def load_settings_page(self):
        """Settings mount: authorized devices + user accounts."""
        async for _ in self.load_authorized():
            pass
        async for _ in self.load_users():
            pass
        yield

    # ── authorized devices registry ──
    async def load_authorized(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/security/authorized", headers=self._headers())
                r.raise_for_status()
                self.authorized = r.json().get("authorized", [])
        except Exception as e:
            self._log(f"Authorized list load failed: {e}")
        yield

    def set_new_mac(self, v: str):
        self.new_mac = v

    def set_new_label(self, v: str):
        self.new_label = v

    # ── account: change own password (role/permissions preserved server-side) ──
    def set_old_pw(self, v: str):
        self.old_pw = v

    def set_new_pw(self, v: str):
        self.new_pw = v

    def set_confirm_pw(self, v: str):
        self.confirm_pw = v

    async def change_password(self):
        if not self.token:
            return
        if not self.old_pw or not self.new_pw:
            self.status_msg = "Enter your current and new password."
            return
        if self.new_pw != self.confirm_pw:
            self.status_msg = "New passwords don't match."
            return
        if len(self.new_pw) < 6:
            self.status_msg = "New password must be at least 6 characters."
            return
        self.status_msg = "Changing password…"
        yield
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/auth/change-password",
                                      headers=self._headers(),
                                      json={"old_password": self.old_pw,
                                            "new_password": self.new_pw})
                r.raise_for_status()
                self._log("Password changed (role unchanged)")
                self.status_msg = "Password changed ✓ — use it at next sign-in."
                self.old_pw = ""
                self.new_pw = ""
                self.confirm_pw = ""
        except httpx.HTTPStatusError as e:
            detail = ""
            try:
                detail = e.response.json().get("detail", "")
            except Exception:
                pass
            self.status_msg = f"Change failed: {detail or e}"
            self._log(f"Password change failed: {detail or e}")
        except Exception as e:
            self.status_msg = f"Change failed: {e}"
            self._log(f"Password change failed: {e}")
        yield

    async def add_authorized(self):
        if not self.token or not self.new_mac.strip():
            self.status_msg = "Enter a MAC address to authorize."
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/security/authorized", headers=self._headers(),
                                      json={"mac": self.new_mac, "label": self.new_label})
                r.raise_for_status()
                self._log(f"Authorized {self.new_mac} ({self.new_label or 'unnamed'})")
                self.status_msg = "Device authorized."
                self.new_mac = ""
                self.new_label = ""
        except Exception as e:
            self.status_msg = f"Add failed: {e}"
            self._log(f"Authorize failed: {e}")
        async for _ in self.load_authorized():
            pass

    def ask_remove_authorized(self, mac: str):
        """First click arms the confirm; the row button becomes 'Confirm?'."""
        self.confirm_remove_mac = mac

    def cancel_remove(self):
        self.confirm_remove_mac = ""

    async def remove_authorized(self, mac: str):
        if not self.token:
            return
        self.confirm_remove_mac = ""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.delete(f"{API_BASE}/security/authorized/{mac}",
                                        headers=self._headers())
                r.raise_for_status()
                self._log(f"Removed {mac} from authorized devices")
                self.status_msg = f"Removed {mac}."
        except Exception as e:
            self._log(f"Remove failed: {e}")
            self.status_msg = f"Remove failed: {e}"
        async for _ in self.load_authorized():
            pass

    async def trust_threat(self, mac: str):
        """One-click trust a flagged device from the Security page."""
        if not self.token:
            return
        self.status_msg = f"Trusting {mac}…"
        yield
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/security/authorized/trust-threat",
                                      headers=self._headers(),
                                      json={"mac": mac, "label": "Trusted from detection"})
                r.raise_for_status()
                self._log(f"Marked {mac} as trusted — will not flag on next scan")
                self.status_msg = f"{mac} trusted. Re-scanning to clear…"
        except Exception as e:
            self.status_msg = f"Trust failed: {e}"
            self._log(f"Trust failed: {e}")
            return
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                await client.post(f"{API_BASE}/security/clear-threats", headers=self._headers())
                await client.post(f"{API_BASE}/security/scan", headers=self._headers())
        except Exception:
            pass
        await asyncio.sleep(3)
        async for _ in self.load_security():
            pass

    # ── audit page ──
    async def load_audit(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/audit/logs?limit=100", headers=self._headers())
                r.raise_for_status()
                raw = r.json().get("logs", [])
                self.audit_logs = [{
                    "time": _fmt_ts(l.get("timestamp", "")),
                    "event": l.get("event_type", "EVENT"),
                    "sev": l.get("severity", "INFO"),
                    "user": l.get("username", "—") or "—",
                    "details": l.get("details", ""),
                } for l in reversed(raw)]
                self.status_msg = f"Loaded {len(self.audit_logs)} audit entries."
        except Exception as e:
            self._log(f"Audit load failed: {e}")
            self.status_msg = ("Audit log requires the admin role."
                               if "403" in str(e) else f"Audit load failed: {e}")
        yield

    # ── schedule page ──
    async def load_scheduler(self):
        if not self.token:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/scheduler/status", headers=self._headers())
                r.raise_for_status()
                data = r.json()
                self.scheduler_running = data.get("running", False)
                self.scheduler_jobs = data.get("jobs", [])
        except Exception as e:
            self._log(f"Scheduler status failed: {e}")
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(f"{API_BASE}/scheduler/policy", headers=self._headers())
                r.raise_for_status()
                p = r.json().get("policy", {})
                self.block_start = p.get("block_start_hour", 18)
                self.block_end = p.get("block_end_hour", 8)
                self.policy_enabled = p.get("enabled", True)
                sh12, sap = _to_12h(self.block_start)
                eh12, eap = _to_12h(self.block_end)
                self.start_hour12, self.start_ampm = str(sh12), sap
                self.end_hour12, self.end_ampm = str(eh12), eap
        except Exception as e:
            self._log(f"Policy load failed: {e}")
        yield

    def set_start_hour12(self, v: str):
        self.start_hour12 = v

    def set_start_ampm(self, v: str):
        self.start_ampm = v

    def set_end_hour12(self, v: str):
        self.end_hour12 = v

    def set_end_ampm(self, v: str):
        self.end_ampm = v

    def toggle_policy_enabled(self, v: bool):
        self.policy_enabled = v

    async def save_policy(self):
        if not self.token:
            self.status_msg = "Sign in first."
            return
        start24 = _to_24h(self.start_hour12, self.start_ampm)
        end24 = _to_24h(self.end_hour12, self.end_ampm)
        self.block_start = start24
        self.block_end = end24
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.post(f"{API_BASE}/scheduler/policy", headers=self._headers(),
                                      json={"block_start_hour": start24,
                                            "block_end_hour": end24,
                                            "enabled": self.policy_enabled})
                r.raise_for_status()
                self._log(f"Access policy saved: restrict {self.start_hour12} {self.start_ampm}"
                          f" – {self.end_hour12} {self.end_ampm} (enabled={self.policy_enabled})")
                self.status_msg = "Access policy saved ✓"
        except Exception as e:
            self.status_msg = f"Save failed: {e}"
            self._log(f"Policy save failed: {e}")

    # ── monitoring page ──
    async def load_monitor(self):
        """Pull /monitor/network-health and flatten it for table display."""
        if not self.token:
            return
        self.monitor_loading = True
        self.status_msg = "Collecting live metrics from all devices…"
        yield
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.get(f"{API_BASE}/monitor/network-health",
                                     headers=self._headers())
                r.raise_for_status()
                m = r.json().get("metrics", {}) or {}
                avail = m.get("network_availability", None)
                self.net_availability = (f"{avail}%" if avail is not None else "—")
                self.net_if_up = m.get("interfaces_up", 0)
                self.net_if_down = m.get("interfaces_down", 0)
                self.net_if_total = m.get("total_interfaces", 0)
                rows = []
                for d in (m.get("device_details", []) or []):
                    ifs = d.get("interfaces", {}) or {}
                    rows.append({
                        "name": d.get("device_name", ""),
                        "ip": d.get("device_ip", ""),
                        "platform": d.get("platform", ""),
                        "role": d.get("device_role", "") or "—",
                        "status": d.get("status", "unknown"),
                        "up": ifs.get("up", 0),
                        "down": ifs.get("down", 0),
                        "total": ifs.get("total", 0),
                        "checked": _fmt_ts(d.get("last_checked", "")),
                    })
                self.monitor_rows = rows
                self.status_msg = (f"Metrics: {m.get('devices_online', 0)}/"
                                   f"{m.get('total_devices', 0)} online, "
                                   f"{self.net_if_up}/{self.net_if_total} interfaces up")
                self._log("Network health metrics collected")
        except Exception as e:
            self.status_msg = f"Metrics load failed: {e}"
            self._log(f"Metrics load failed: {e}")
        self.monitor_loading = False
        yield

    # ── wireless networks (UniFi SSIDs) ──
    async def load_wlans(self):
        """List SSIDs from the first UniFi controller in inventory."""
        if not self.token:
            return
        if not self.devices:
            async for _ in self.load_devices():
                pass
        unifi = next((d for d in self.devices
                      if "unifi" in d.get("platform", "").lower()
                      or "ubiquiti" in d.get("platform", "").lower()), None)
        if not unifi:
            self.wlan_note = "No UniFi controller in inventory."
            self.wlans = []
            return
        self.wlan_device = unifi["name"]
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(f"{API_BASE}/devices/{unifi['name']}/wlans",
                                     headers=self._headers())
                r.raise_for_status()
                data = r.json()
                if data.get("status") == "unreachable":
                    self.wlans = []
                    self.wlan_note = (f"{unifi['name']} is offline — SSIDs will "
                                      "appear when the controller is reachable.")
                else:
                    self.wlans = [{"id": w.get("id", ""),
                                   "name": w.get("name", ""),
                                   "enabled": bool(w.get("enabled", False)),
                                   "vlan": str(w.get("vlan", "") or "—")}
                                  for w in data.get("wlans", [])]
                    self.wlan_note = ""
        except Exception as e:
            self.wlans = []
            self.wlan_note = f"WLAN load failed: {e}"
        yield

    async def load_schedule_page(self):
        """Schedule page mount: scheduler status + policy + UniFi SSIDs."""
        async for _ in self.load_scheduler():
            pass
        async for _ in self.load_wlans():
            pass
        yield

    # ── SSID edit / delete (full lifecycle from UAF, no controller GUI) ──
    def begin_edit_wlan(self, wlan_id: str, name: str, vlan: str):
        self.editing_wlan_id = wlan_id
        self.edit_ssid_name = name
        self.edit_ssid_pass = ""
        self.edit_ssid_vlan = "" if vlan in ("—", "") else vlan
        self.confirm_delete_wlan = ""

    def cancel_edit_wlan(self):
        self.editing_wlan_id = ""
        self.edit_ssid_name = ""
        self.edit_ssid_pass = ""
        self.edit_ssid_vlan = ""

    def set_edit_ssid_name(self, v: str):
        self.edit_ssid_name = v

    def set_edit_ssid_pass(self, v: str):
        self.edit_ssid_pass = v

    def set_edit_ssid_vlan(self, v: str):
        self.edit_ssid_vlan = v

    async def save_wlan_edit(self):
        if not self.token or not self.editing_wlan_id or not self.wlan_device:
            return
        payload: Dict[str, Any] = {}
        if self.edit_ssid_name.strip():
            payload["name"] = self.edit_ssid_name.strip()
        if self.edit_ssid_pass.strip():
            payload["passphrase"] = self.edit_ssid_pass.strip()
        v = self.edit_ssid_vlan.strip()
        if v:
            try:
                payload["vlan"] = int(v)
            except ValueError:
                self.status_msg = "VLAN must be a number."
                return
        else:
            payload["vlan"] = 0  # clear VLAN tagging
        self.status_msg = "Saving SSID changes…"
        yield
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.put(
                    f"{API_BASE}/devices/{self.wlan_device}/wlans/{self.editing_wlan_id}",
                    headers=self._headers(), json=payload)
                r.raise_for_status()
                self._log(f"SSID {self.editing_wlan_id} updated")
                self.status_msg = "SSID updated ✓"
        except Exception as e:
            self.status_msg = f"SSID update failed: {e}"
            self._log(f"SSID update failed: {e}")
        self.cancel_edit_wlan()
        async for _ in self.load_wlans():
            pass
        yield

    def ask_delete_wlan(self, wlan_id: str):
        """First click arms the confirm; the row button becomes 'Confirm?'."""
        self.confirm_delete_wlan = wlan_id
        self.editing_wlan_id = ""

    def cancel_delete_wlan(self):
        self.confirm_delete_wlan = ""

    async def remove_wlan(self, wlan_id: str):
        if not self.token or not self.wlan_device:
            return
        self.confirm_delete_wlan = ""
        self.status_msg = "Deleting SSID…"
        yield
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.delete(
                    f"{API_BASE}/devices/{self.wlan_device}/wlans/{wlan_id}",
                    headers=self._headers())
                r.raise_for_status()
                self._log(f"SSID {wlan_id} deleted")
                self.status_msg = "SSID deleted ✓"
        except Exception as e:
            self.status_msg = f"SSID delete failed: {e}"
            self._log(f"SSID delete failed: {e}")
        async for _ in self.load_wlans():
            pass
        yield

    # ── network provisioning (admin) ──
    def set_prov_name(self, v: str):
        self.prov_name = v

    def set_prov_vlan(self, v: str):
        self.prov_vlan = v

    def set_prov_subnet(self, v: str):
        self.prov_subnet = v

    def set_prov_gateway(self, v: str):
        self.prov_gateway = v

    def set_prov_ports(self, v: str):
        self.prov_ports = v

    def set_prov_ssid(self, v: str):
        self.prov_ssid = v

    def set_prov_psk(self, v: str):
        self.prov_psk = v

    def toggle_prov_dhcp(self, v: bool):
        self.prov_dhcp = v

    def toggle_prov_sec(self, v: bool):
        self.prov_sec = v

    async def run_provision(self):
        """One high-level intent -> vendor-specific config on every device."""
        if not self.token:
            return
        if not self.prov_name.strip() or not self.prov_subnet.strip():
            self.status_msg = "Network name and subnet are required."
            return
        try:
            vlan = int(self.prov_vlan)
            if not (2 <= vlan <= 4094):
                raise ValueError
        except ValueError:
            self.status_msg = "VLAN ID must be a number between 2 and 4094."
            return
        self.prov_running = True
        self.prov_results = []
        self.prov_summary = ""
        self.status_msg = f"Provisioning '{self.prov_name}' across all vendors…"
        self._log(f"Provisioning network '{self.prov_name}' (VLAN {vlan})")
        yield
        payload = {
            "network_name": self.prov_name.strip(),
            "vlan_id": vlan,
            "subnet": self.prov_subnet.strip(),
            "gateway": self.prov_gateway.strip(),
            "enable_dhcp": self.prov_dhcp,
            "enable_port_security": self.prov_sec,
            "switch_ports": [p.strip() for p in self.prov_ports.split(",") if p.strip()],
        }
        if self.prov_ssid.strip():
            payload["wifi_ssid"] = self.prov_ssid.strip()
            payload["wifi_password"] = self.prov_psk
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(f"{API_BASE}/provision/network",
                                      headers=self._headers(), json=payload)
                r.raise_for_status()
                data = r.json()
                # Backend nests the step lists under "details".
                detail = data.get("details", data) or {}
                done = detail.get("steps_completed", []) or []
                failed = detail.get("steps_failed", []) or []
                rows = []
                for st in done:
                    rows.append({"ok": True,
                                 "step": st.get("step", "step"),
                                 "device": st.get("device", ""),
                                 "info": str(st.get("port", "") or "")})
                for st in failed:
                    rows.append({"ok": False,
                                 "step": st.get("step", "step"),
                                 "device": st.get("device", ""),
                                 "info": str(st.get("error", ""))[:200]})
                self.prov_results = rows
                self.prov_summary = (f"{len(done)} step(s) completed, "
                                     f"{len(failed)} failed")
                self.status_msg = f"Provisioning finished — {self.prov_summary}."
                self._log(f"Provisioned '{self.prov_name}': {self.prov_summary}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                self.status_msg = "Provisioning requires the admin role."
            else:
                self.status_msg = f"Provisioning failed: {e}"
            self._log(f"Provisioning failed: {e}")
        except Exception as e:
            self.status_msg = f"Provisioning failed: {e}"
            self._log(f"Provisioning failed: {e}")
        self.prov_running = False
        yield

    # ── wake-on-lan ──
    def toggle_wol_device(self, name: str):
        if name in self.wol_selected:
            self.wol_selected = [n for n in self.wol_selected if n != name]
        else:
            self.wol_selected = self.wol_selected + [name]

    async def wake_selected(self):
        await self._wake([d["mac"] for d in self.devices
                          if d["name"] in self.wol_selected and d.get("mac")])

    def ask_wake_all(self):
        self.confirm_wake_all = True

    def cancel_wake_all(self):
        self.confirm_wake_all = False

    async def wake_all(self):
        self.confirm_wake_all = False
        await self._wake([d["mac"] for d in self.devices if d.get("mac")])

    async def _wake(self, macs: List[str]):
        if not self.token:
            self.status_msg = "Sign in first."
            return
        if not macs:
            self.status_msg = "No devices selected (or no MACs available)."
            return
        self.status_msg = f"Sending Wake-on-LAN to {len(macs)} device(s)…"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(f"{API_BASE}/power/wake-batch", headers=self._headers(),
                                      json={"macs": macs, "broadcast_ip": "255.255.255.255"})
                r.raise_for_status()
                data = r.json()
                self._log(f"Wake-on-LAN: {data.get('sent',0)}/{data.get('total',0)} packets sent")
                self.status_msg = f"Sent {data.get('sent',0)}/{data.get('total',0)} magic packets ✓"
        except Exception as e:
            self.status_msg = f"WoL failed: {e}"
            self._log(f"WoL failed: {e}")


# ── shared building blocks ───────────────────────────────────────────────────
def bg_layer() -> rx.Component:
    if USE_VIDEO_BG:
        media = rx.el.video(
            rx.el.source(src=f"/{VIDEO_FILE}", type="video/mp4"),
            auto_play=True, loop=True, muted=True, plays_inline=True,
            style={"position": "fixed", "inset": "0", "width": "100%",
                   "height": "100%", "object_fit": "cover", "z_index": "-2"},
        )
    else:
        media = rx.box(style={
            "position": "fixed", "inset": "0", "z_index": "-2",
            "background": (
                "radial-gradient(60% 80% at 15% 20%, rgba(52,211,153,0.18), transparent 60%),"
                "radial-gradient(50% 70% at 85% 15%, rgba(96,165,250,0.16), transparent 60%),"
                "radial-gradient(70% 90% at 70% 90%, rgba(139,92,246,0.14), transparent 60%),"
                f"linear-gradient(135deg, {INK}, #0d1422 55%, #0a1018)"
            ),
            "background_size": "200% 200%, 200% 200%, 200% 200%, 100% 100%",
            "animation": "auroraShift 22s ease-in-out infinite",
        })
    scrim = rx.box(style={"position": "fixed", "inset": "0", "z_index": "-1",
                          "background": "rgba(6, 9, 14, 0.62)", "backdrop_filter": "blur(3px)"})
    return rx.fragment(media, scrim)


def glass(*children, **props) -> rx.Component:
    style = {"background": PANEL, "backdrop_filter": "blur(20px) saturate(160%)",
             "border": f"1px solid {PANEL_BORDER}", "border_radius": "18px",
             "box_shadow": "0 8px 40px rgba(0,0,0,0.35)", "padding": "22px"}
    style.update(props.pop("style", {}))
    return rx.box(*children, style=style, **props)


def section_label(text: str, mb: str = "14px") -> rx.Component:
    return rx.text(text, style={"font_family": MONO, "font_size": "12px",
                                "letter_spacing": "0.15em", "color": MUTED,
                                "margin_bottom": mb})


def col_header(*cells) -> rx.Component:
    """Industry-style table header row: (label, width-or-None) pairs."""
    items = []
    for label, width in cells:
        st = {"font_family": MONO, "font_size": "10px", "letter_spacing": "0.12em",
              "color": MUTED, "text_transform": "uppercase"}
        if width:
            st["width"] = width
            st["flex_shrink"] = "0"
        else:
            st["flex"] = "1"
        items.append(rx.text(label, style=st))
    return rx.hstack(*items, width="100%", align="center", spacing="3",
                     style={"padding": "8px 4px",
                            "border_bottom": f"1px solid {PANEL_BORDER}"})


def pill(text, color, dim) -> rx.Component:
    return rx.box(
        rx.text(text, style={"font_family": MONO, "font_size": "10px",
                             "letter_spacing": "0.1em", "color": color}),
        style={"padding": "3px 9px", "border_radius": "6px", "background": dim,
               "flex_shrink": "0"},
    )


def btn(label, on_click, color=ACCENT, dim=ACCENT_DIM, border="rgba(52,211,153,0.35)",
        **props) -> rx.Component:
    style = {"font_family": MONO, "font_size": "12px", "cursor": "pointer",
             "padding": "8px 16px", "border_radius": "9px", "background": dim,
             "color": color, "border": f"1px solid {border}"}
    style.update(props.pop("style", {}))
    return rx.button(label, on_click=on_click, style=style, **props)


def nav_item(label: str, icon: str, route: str) -> rx.Component:
    active = State.router.page.path == route
    return rx.link(
        rx.hstack(
            rx.icon(icon, size=18, color=rx.cond(active, ACCENT, MUTED)),
            rx.text(label, style={"font_size": "14px", "font_weight": "500",
                                  "color": rx.cond(active, TEXT, MUTED)}),
            spacing="3", align="center",
            style={"padding": "10px 14px", "border_radius": "10px", "width": "100%",
                   "background": rx.cond(active, ACCENT_DIM, "transparent"),
                   "border": f"1px solid {rx.cond(active, 'rgba(52,211,153,0.25)', 'transparent')}",
                   "transition": "all 0.15s ease"},
        ),
        href=route, style={"text_decoration": "none", "width": "100%"},
    )


def sidebar() -> rx.Component:
    return rx.box(
        rx.vstack(
            rx.hstack(
                rx.box(style={"width": "10px", "height": "10px", "border_radius": "50%",
                              "background": ACCENT, "box_shadow": f"0 0 10px {ACCENT}"}),
                rx.heading("UAF", style={"font_family": MONO, "font_size": "22px",
                                         "font_weight": "800", "color": TEXT,
                                         "letter_spacing": "0.08em"}),
                spacing="2", align="center", margin_bottom="4px",
            ),
            rx.text("OPERATIONS CONSOLE", style={"font_family": MONO, "font_size": "9px",
                                                 "letter_spacing": "0.2em", "color": MUTED,
                                                 "margin_bottom": "22px"}),
            nav_item("Dashboard", "layout-dashboard", "/"),
            nav_item("Devices", "server", "/devices"),
            nav_item("Monitoring", "activity", "/monitor"),
            nav_item("Security", "shield-alert", "/security"),
            nav_item("Schedule", "clock", "/schedule"),
            nav_item("Provision", "network", "/provision"),
            nav_item("Audit", "scroll-text", "/audit"),
            nav_item("Settings", "settings", "/settings"),
            nav_item("How It Works", "circle-help", "/how"),
            rx.spacer(),
            # signed-in user chip + logout (industry standard)
            rx.box(
                rx.hstack(
                    rx.icon("user", size=15, color=ACCENT),
                    rx.vstack(
                        rx.text(State.current_user,
                                style={"font_size": "12px", "font_weight": "600", "color": TEXT}),
                        rx.text(State.current_role,
                                style={"font_family": MONO, "font_size": "9px",
                                       "letter_spacing": "0.12em", "color": ACCENT,
                                       "text_transform": "uppercase"}),
                        spacing="0", align="start",
                    ),
                    rx.spacer(),
                    rx.icon("log-out", size=15, color=MUTED, cursor="pointer",
                            on_click=State.logout),
                    spacing="2", align="center", width="100%",
                ),
                style={"padding": "10px 12px", "border_radius": "10px", "width": "100%",
                       "background": "rgba(255,255,255,0.03)",
                       "border": f"1px solid {PANEL_BORDER}", "margin_bottom": "10px"},
            ),
            rx.hstack(
                rx.box(style={"width": "8px", "height": "8px", "border_radius": "50%",
                              "background": rx.cond(State.connected, ACCENT, MUTED),
                              "box_shadow": rx.cond(State.connected, f"0 0 8px {ACCENT}", "none"),
                              "animation": rx.cond(State.connected, "pulse 2s infinite", "none")}),
                rx.text(rx.cond(State.connected, "CONTROL PLANE ONLINE", "OFFLINE"),
                        style={"font_family": MONO, "font_size": "9px",
                               "letter_spacing": "0.12em",
                               "color": rx.cond(State.connected, ACCENT, MUTED)}),
                spacing="2", align="center",
                style={"padding_left": "12px"},
            ),
            spacing="2", align="start", height="100%",
        ),
        style={"width": "230px", "min_width": "230px", "height": "100vh", "position": "sticky",
               "top": "0", "padding": "26px 18px",
               "background": "rgba(12, 18, 28, 0.6)", "backdrop_filter": "blur(24px)",
               "border_right": f"1px solid {PANEL_BORDER}"},
    )


def status_bar() -> rx.Component:
    """Always-visible feedback strip — every action's result shows here."""
    return rx.hstack(
        rx.icon("activity", size=14, color=ACCENT),
        rx.text(State.status_msg, style={"font_family": MONO, "font_size": "12px",
                                         "color": MUTED, "white_space": "nowrap",
                                         "overflow": "hidden", "text_overflow": "ellipsis",
                                         "flex": "1"}),
        rx.button(
            rx.cond(State.live_enabled, "● LIVE", "❚❚ PAUSED"),
            on_click=State.toggle_live,
            style={"font_family": MONO, "font_size": "10px", "cursor": "pointer",
                   "padding": "4px 12px", "border_radius": "999px",
                   "background": rx.cond(State.live_enabled, ACCENT_DIM, "rgba(0,0,0,0.25)"),
                   "color": rx.cond(State.live_enabled, ACCENT, MUTED),
                   "border": f"1px solid {rx.cond(State.live_enabled, 'rgba(52,211,153,0.35)', PANEL_BORDER)}"},
        ),
        rx.button(
            rx.hstack(rx.icon("refresh-cw", size=12), rx.text("Refresh"), spacing="1",
                      align="center"),
            on_click=State.refresh_all, loading=State.loading,
            style={"font_family": MONO, "font_size": "10px", "cursor": "pointer",
                   "padding": "4px 12px", "border_radius": "999px",
                   "background": "rgba(255,255,255,0.04)", "color": MUTED,
                   "border": f"1px solid {PANEL_BORDER}"},
        ),
        width="100%", align="center", spacing="3",
        style={"padding": "9px 14px", "border_radius": "12px", "margin_bottom": "20px",
               "background": "rgba(12,18,28,0.5)", "border": f"1px solid {PANEL_BORDER}",
               "backdrop_filter": "blur(16px)"},
    )


def page_shell(title: str, subtitle: str, *body, on_mount=None) -> rx.Component:
    content = rx.box(
        rx.hstack(
            rx.vstack(
                rx.heading(title, style={"font_size": "26px", "font_weight": "700", "color": TEXT}),
                rx.text(subtitle, style={"font_size": "13px", "color": MUTED}),
                spacing="1", align="start",
            ),
            rx.spacer(),
            width="100%", align="center", margin_bottom="16px",
        ),
        status_bar(),
        *body,
        style={"padding": "32px 40px", "width": "100%", "max_width": "1160px"},
    )
    box_props = {"style": {"display": "flex", "min_height": "100vh", "width": "100%",
                           "color": TEXT, "font_family": SANS}}
    if on_mount is not None:
        box_props["on_mount"] = on_mount
    return rx.box(bg_layer(), sidebar(), content, **box_props)


def stat_card(label: str, value, accent=TEXT) -> rx.Component:
    return glass(
        rx.vstack(
            rx.text(value, style={"font_family": MONO, "font_size": "30px", "font_weight": "700",
                                  "color": accent, "line_height": "1"}),
            rx.text(label, style={"font_size": "11px", "letter_spacing": "0.12em",
                                  "color": MUTED, "text_transform": "uppercase"}),
            spacing="2", align="start",
        ),
        style={"flex": "1", "padding": "20px 22px"},
    )


# ── PAGE: Login ──────────────────────────────────────────────────────────────
def login_page() -> rx.Component:
    return rx.box(
        bg_layer(),
        rx.center(
            glass(
                rx.vstack(
                    rx.hstack(
                        rx.box(style={"width": "12px", "height": "12px", "border_radius": "50%",
                                      "background": ACCENT, "box_shadow": f"0 0 12px {ACCENT}"}),
                        rx.heading("UAF", style={"font_family": MONO, "font_size": "30px",
                                                 "font_weight": "800", "color": TEXT,
                                                 "letter_spacing": "0.08em"}),
                        spacing="3", align="center",
                    ),
                    rx.text("UNIFIED AUTOMATION FRAMEWORK",
                            style={"font_family": MONO, "font_size": "10px",
                                   "letter_spacing": "0.25em", "color": MUTED,
                                   "margin_bottom": "26px"}),
                    rx.vstack(
                        rx.text("Username", style={"font_size": "11px", "color": MUTED}),
                        rx.input(
                            value=State.username_input, on_change=State.set_username_input,
                            placeholder="admin", width="100%",
                            style={"font_family": MONO, "font_size": "13px",
                                   "background": "rgba(0,0,0,0.3)", "color": TEXT,
                                   "border": f"1px solid {PANEL_BORDER}",
                                   "border_radius": "9px", "padding": "10px 13px"},
                        ),
                        spacing="1", align="start", width="100%",
                    ),
                    rx.vstack(
                        rx.text("Password", style={"font_size": "11px", "color": MUTED}),
                        rx.input(
                            value=State.password_input, on_change=State.set_password_input,
                            placeholder="••••••••", type="password", width="100%",
                            style={"font_family": MONO, "font_size": "13px",
                                   "background": "rgba(0,0,0,0.3)", "color": TEXT,
                                   "border": f"1px solid {PANEL_BORDER}",
                                   "border_radius": "9px", "padding": "10px 13px"},
                        ),
                        spacing="1", align="start", width="100%",
                    ),
                    rx.cond(
                        State.login_error != "",
                        rx.hstack(
                            rx.icon("circle-alert", size=14, color=DANGER),
                            rx.text(State.login_error,
                                    style={"font_size": "12px", "color": DANGER}),
                            spacing="2", align="center", width="100%",
                        ),
                        rx.box(),
                    ),
                    rx.button(
                        "Sign In",
                        on_click=State.login, loading=State.loading,
                        style={"font_family": MONO, "font_size": "13px", "font_weight": "600",
                               "cursor": "pointer", "width": "100%", "padding": "12px",
                               "border_radius": "10px", "background": ACCENT, "color": INK,
                               "border": "none", "margin_top": "6px"},
                    ),
                    rx.box(
                        rx.text("Roles: admin · operator · viewer",
                                style={"font_family": MONO, "font_size": "10px",
                                       "color": MUTED}),
                        rx.text("Accounts are provisioned by an administrator — there is "
                                "no self-service sign-up for this privileged console. "
                                "Need access? Ask an admin to create your account under "
                                "Settings → User Management. (Demo default: admin / admin123)",
                                style={"font_family": SANS, "font_size": "10px",
                                       "color": MUTED, "line_height": "1.6",
                                       "margin_top": "6px"}),
                        style={"margin_top": "10px"},
                    ),
                    spacing="3", align="start", width="100%",
                ),
                style={"width": "380px", "padding": "34px"},
            ),
            style={"min_height": "100vh", "width": "100%"},
        ),
        style={"font_family": SANS},
    )


# ── PAGE: Dashboard ──────────────────────────────────────────────────────────
def alert_row(a: Dict[str, Any]) -> rx.Component:
    color = rx.match(a["kind"],
                     ("threat", DANGER), ("port_control", WARN),
                     ("port_restored", ACCENT), ("provision_done", ACCENT), INFO)
    return rx.hstack(
        rx.box(style={"width": "7px", "height": "7px", "border_radius": "50%",
                      "background": color, "flex_shrink": "0",
                      "box_shadow": f"0 0 8px {color}"}),
        rx.text(a["ts"], style={"font_family": MONO, "font_size": "11px",
                                "color": MUTED, "width": "70px", "flex_shrink": "0"}),
        rx.text(a["label"], style={"font_family": MONO, "font_size": "12px",
                                   "color": TEXT, "width": "150px",
                                   "flex_shrink": "0"}),
        rx.text(a["detail"], style={"font_size": "12px", "color": MUTED, "flex": "1",
                                    "white_space": "nowrap", "overflow": "hidden",
                                    "text_overflow": "ellipsis"}),
        width="100%", align="center", spacing="3",
        style={"padding": "8px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def dashboard() -> rx.Component:
    return page_shell(
        "Dashboard", "Network control plane overview",
        rx.hstack(
            stat_card("Managed Devices", State.device_count),
            stat_card("Online", State.online_count, ACCENT),
            stat_card("Active Threats", State.threat_count,
                      rx.cond(State.threat_count > 0, DANGER, ACCENT)),
            stat_card("Scheduler", rx.cond(State.scheduler_running, "ACTIVE", "—"),
                      rx.cond(State.scheduler_running, ACCENT, MUTED)),
            width="100%", spacing="3", margin_bottom="20px",
        ),
        glass(
            rx.hstack(
                section_label("REAL-TIME ALERTS", mb="0px"),
                rx.spacer(),
                rx.hstack(
                    rx.box(style={"width": "8px", "height": "8px",
                                  "border_radius": "50%",
                                  "background": rx.cond(State.ws_connected, ACCENT, MUTED),
                                  "box_shadow": rx.cond(State.ws_connected,
                                                        f"0 0 8px {ACCENT}", "none"),
                                  "animation": rx.cond(State.ws_connected,
                                                       "pulse 2s infinite", "none")}),
                    rx.text(rx.cond(State.ws_connected, "WEBSOCKET LIVE", "CONNECTING…"),
                            style={"font_family": MONO, "font_size": "9px",
                                   "letter_spacing": "0.12em",
                                   "color": rx.cond(State.ws_connected, ACCENT, MUTED)}),
                    spacing="2", align="center",
                ),
                width="100%", align="center", margin_bottom="12px",
            ),
            rx.cond(
                State.alerts,
                rx.vstack(rx.foreach(State.alerts, alert_row),
                          spacing="0", width="100%"),
                rx.text("No live events yet. Security alerts, port actions, and "
                        "device-status changes are pushed here the instant they happen.",
                        style={"color": MUTED, "font_size": "13px"}),
            ),
            style={"width": "100%", "margin_bottom": "20px"},
        ),
        glass(
            section_label("SESSION ACTIVITY"),
            rx.cond(
                State.action_log,
                rx.vstack(rx.foreach(State.action_log,
                          lambda l: rx.text(l, style={"font_family": MONO, "font_size": "12px",
                                                      "color": MUTED, "line_height": "1.7"})),
                          spacing="0", align="start"),
                rx.text("No actions yet this session. Full history is on the Audit page.",
                        style={"color": MUTED, "font_size": "13px"}),
            ),
            style={"width": "100%"},
        ),
        on_mount=State.load_scheduler,
    )


# ── PAGE: Devices ─────────────────────────────────────────────────────────────
def device_row(d: Dict[str, Any]) -> rx.Component:
    is_sel = State.selected_device == d["name"]
    dot = rx.match(d["status"], ("online", ACCENT), ("offline", DANGER), MUTED)
    return rx.box(
        rx.hstack(
            rx.box(style={"width": "8px", "height": "8px", "border_radius": "50%",
                          "background": dot, "flex_shrink": "0",
                          "box_shadow": rx.match(d["status"], ("online", f"0 0 8px {ACCENT}"),
                                                 ("offline", f"0 0 8px {DANGER}"), "none")}),
            rx.vstack(
                rx.text(d["name"], style={"font_weight": "600", "color": TEXT,
                                          "font_size": "14px"}),
                rx.hstack(
                    rx.text(d["ip"], style={"font_family": MONO, "font_size": "11px",
                                            "color": MUTED}),
                    pill(d["platform"], INFO, INFO_DIM),
                    spacing="2", align="center",
                ),
                spacing="1", align="start",
            ),
            rx.spacer(),
            rx.button(rx.cond(is_sel, "Viewing", "Inspect"),
                      on_click=lambda: State.select_device(d["name"]),
                      style={"font_family": MONO, "font_size": "11px", "cursor": "pointer",
                             "padding": "5px 14px", "border_radius": "8px",
                             "background": rx.cond(is_sel, ACCENT_DIM, "rgba(255,255,255,0.04)"),
                             "color": rx.cond(is_sel, ACCENT, TEXT),
                             "border": f"1px solid {rx.cond(is_sel, ACCENT, PANEL_BORDER)}"}),
            width="100%", align="center",
        ),
        style={"padding": "13px 14px", "border_radius": "12px", "margin_bottom": "9px",
               "background": rx.cond(is_sel, "rgba(52,211,153,0.06)", "rgba(255,255,255,0.02)"),
               "border": f"1px solid {rx.cond(is_sel, 'rgba(52,211,153,0.3)', PANEL_BORDER)}"},
    )


def interface_row(itf: Dict[str, Any]) -> rx.Component:
    disabled = itf["disabled"]
    is_busy = State.busy_port == itf["name"]
    return rx.hstack(
        rx.box(style={"width": "9px", "height": "9px", "border_radius": "50%",
                      "background": rx.cond(disabled, DANGER, ACCENT),
                      "box_shadow": rx.cond(disabled, f"0 0 8px {DANGER}", f"0 0 8px {ACCENT}"),
                      "flex_shrink": "0"}),
        rx.text(itf["name"], style={"font_family": MONO, "font_size": "13px", "color": TEXT,
                                    "width": "120px", "font_weight": "500",
                                    "flex_shrink": "0"}),
        rx.box(pill(rx.cond(disabled, "DISABLED", "ENABLED"),
                    rx.cond(disabled, DANGER, ACCENT),
                    rx.cond(disabled, DANGER_DIM, ACCENT_DIM)),
               style={"width": "100px", "flex_shrink": "0"}),
        rx.text(itf["mac_address"], style={"font_family": MONO, "font_size": "11px",
                                           "color": MUTED, "flex": "1"}),
        rx.button(rx.cond(is_busy, "…", rx.cond(disabled, "Enable", "Disable")),
                  on_click=lambda: State.toggle_port(itf["name"], disabled), disabled=is_busy,
                  style={"font_family": MONO, "font_size": "11px", "cursor": "pointer",
                         "padding": "6px 16px", "border_radius": "8px", "min_width": "78px",
                         "flex_shrink": "0",
                         "background": rx.cond(disabled, ACCENT_DIM, DANGER_DIM),
                         "color": rx.cond(disabled, ACCENT, DANGER),
                         "border": f"1px solid {rx.cond(disabled, 'rgba(52,211,153,0.3)', 'rgba(248,113,113,0.3)')}"}),
        width="100%", align="center", spacing="3",
        style={"padding": "11px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def devices_page() -> rx.Component:
    return page_shell(
        "Devices", "Inventory and live interface control",
        rx.hstack(
            glass(
                rx.hstack(
                    section_label("INVENTORY", mb="0px"),
                    rx.spacer(),
                    width="100%", align="center", margin_bottom="12px",
                ),
                rx.input(
                    placeholder="Search name, IP, or vendor…",
                    value=State.device_search, on_change=State.set_device_search,
                    width="100%",
                    style={"font_family": MONO, "font_size": "12px",
                           "background": "rgba(0,0,0,0.25)", "color": TEXT,
                           "border": f"1px solid {PANEL_BORDER}", "border_radius": "9px",
                           "padding": "8px 12px", "margin_bottom": "14px"},
                ),
                rx.cond(State.filtered_devices,
                        rx.foreach(State.filtered_devices, device_row),
                        rx.text("No devices match.", style={"color": MUTED, "font_size": "13px"})),
                style={"width": "40%", "align_self": "stretch"},
            ),
            glass(
                rx.hstack(
                    section_label("INTERFACES", mb="0px"),
                    rx.cond(State.selected_device != "",
                            rx.text(State.selected_device,
                                    style={"font_family": MONO, "font_size": "12px",
                                           "color": ACCENT}),
                            rx.text("")),
                    spacing="2", margin_bottom="12px",
                ),
                rx.cond(
                    State.interfaces,
                    rx.vstack(
                        col_header(("", "9px"), ("Port", "120px"), ("Admin", "100px"),
                                   ("MAC Address", None), ("Action", "78px")),
                        rx.foreach(State.interfaces, interface_row),
                        spacing="0", width="100%",
                    ),
                    rx.cond(
                        (State.selected_device != "") & (State.selected_status == "offline"),
                        rx.vstack(
                            rx.box(style={"width": "12px", "height": "12px",
                                          "border_radius": "50%", "background": DANGER,
                                          "box_shadow": f"0 0 10px {DANGER}",
                                          "margin_bottom": "10px"}),
                            rx.text("Device offline", style={"font_family": MONO,
                                                             "color": DANGER,
                                                             "font_size": "14px"}),
                            rx.text("Not reachable. Provision or connect the device, "
                                    "then inspect again.",
                                    style={"color": MUTED, "font_size": "12px",
                                           "text_align": "center", "max_width": "320px"}),
                            spacing="2", align="center", style={"padding": "30px 0"},
                        ),
                        rx.text("Select a device to inspect live interfaces.",
                                style={"color": MUTED, "font_size": "13px"}),
                    ),
                ),
                style={"width": "60%", "align_self": "stretch"},
            ),
            width="100%", spacing="3", align="stretch",
        ),
    )


# ── PAGE: Security ────────────────────────────────────────────────────────────
def threat_row(t: Dict[str, Any]) -> rx.Component:
    mac = t["mac"]
    return rx.hstack(
        rx.icon("triangle-alert", size=15, color=DANGER),
        rx.text(mac, style={"font_family": MONO, "font_size": "13px", "color": TEXT,
                            "width": "180px", "flex_shrink": "0"}),
        rx.text(t["device_name"], style={"font_family": MONO, "font_size": "12px",
                                         "color": MUTED, "width": "170px",
                                         "flex_shrink": "0"}),
        rx.text(t["port_id"], style={"font_family": MONO, "font_size": "12px",
                                     "color": WARN, "flex": "1"}),
        pill("QUARANTINED", DANGER, DANGER_DIM),
        rx.button(
            "Trust",
            on_click=lambda: State.trust_threat(mac),
            style={"font_family": MONO, "font_size": "11px", "cursor": "pointer",
                   "padding": "5px 14px", "border_radius": "8px", "background": ACCENT_DIM,
                   "color": ACCENT, "border": "1px solid rgba(52,211,153,0.3)",
                   "flex_shrink": "0"},
        ),
        width="100%", align="center", spacing="3",
        style={"padding": "11px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def enforcement_banner() -> rx.Component:
    """Shows learning vs armed, and the control to switch — the first thing a
    new admin sees, so they build a trusted baseline before auto-blocking."""
    return glass(
        rx.hstack(
            rx.icon(rx.cond(State.is_armed, "shield-check", "eye"),
                    size=22, color=rx.cond(State.is_armed, ACCENT, WARN)),
            rx.vstack(
                rx.hstack(
                    rx.text(rx.cond(State.is_armed, "ENFORCEMENT ARMED",
                                    "LEARNING MODE"),
                            style={"font_family": MONO, "font_size": "13px",
                                   "font_weight": "700",
                                   "color": rx.cond(State.is_armed, ACCENT, WARN),
                                   "letter_spacing": "0.1em"}),
                    spacing="2", align="center",
                ),
                rx.text(rx.cond(
                    State.is_armed,
                    "Unrecognized devices are isolated automatically. Detected "
                    "devices not in your trusted list will have their port shut.",
                    "UAF is detecting and listing devices but NOT blocking any. "
                    "Review what is on the network, trust the legitimate devices "
                    "below, then arm enforcement."),
                    style={"color": MUTED, "font_size": "12px", "line_height": "1.6",
                           "max_width": "560px"}),
                spacing="1", align="start",
            ),
            rx.spacer(),
            rx.cond(
                State.is_armed,
                btn("Switch to Learning", lambda: State.set_enforcement("learning"),
                    color=WARN, dim=WARN_DIM, border="rgba(251,191,36,0.35)",
                    style={"padding": "10px 18px"}),
                btn("Activate Enforcement", lambda: State.set_enforcement("armed"),
                    style={"padding": "10px 18px"}),
            ),
            width="100%", align="center", spacing="4",
        ),
        style={"width": "100%", "margin_bottom": "20px",
               "border": f"1px solid {rx.cond(State.is_armed, 'rgba(52,211,153,0.3)', 'rgba(251,191,36,0.3)')}"},
    )


def security_page() -> rx.Component:
    return page_shell(
        "Security", "Rogue device detection and automated response",
        enforcement_banner(),
        rx.hstack(
            stat_card("Detected Devices", State.threat_count,
                      rx.cond(State.is_armed,
                              rx.cond(State.threat_count > 0, DANGER, ACCENT),
                              WARN)),
            glass(
                btn("Run Network Scan", State.run_scan, style={"width": "100%",
                                                               "padding": "10px 18px"}),
                rx.text("Reads every switch's MAC table and lists every connected "
                        "device. In armed mode, unrecognized devices are isolated.",
                        style={"color": MUTED, "font_size": "11px", "margin_top": "8px"}),
                style={"flex": "2"},
            ),
            width="100%", spacing="3", margin_bottom="20px",
        ),
        glass(
            section_label(rx.cond(State.is_armed, "DETECTED THREATS", "DEVICES ON NETWORK")),
            rx.cond(
                State.threats,
                rx.vstack(
                    col_header(("", "15px"), ("MAC Address", "180px"), ("Device", "170px"),
                               ("Port", None), ("State", "96px"), ("Action", "70px")),
                    rx.foreach(State.threats, threat_row),
                    spacing="0", width="100%",
                ),
                rx.hstack(
                    rx.icon("shield-check", size=18, color=ACCENT),
                    rx.text("No active threats. Network is clean.",
                            style={"color": MUTED, "font_size": "13px"}),
                    spacing="2", align="center",
                ),
            ),
            style={"width": "100%"},
        ),
        on_mount=State.load_security_page,
    )


# ── PAGE: Schedule ────────────────────────────────────────────────────────────
def wol_device_row(d: Dict[str, Any]) -> rx.Component:
    selected = State.wol_selected.contains(d["name"])
    return rx.hstack(
        rx.box(
            rx.cond(selected, rx.icon("check", size=13, color=INK), rx.text("")),
            style={"width": "18px", "height": "18px", "border_radius": "5px",
                   "flex_shrink": "0",
                   "background": rx.cond(selected, ACCENT, "transparent"),
                   "border": f"1px solid {rx.cond(selected, ACCENT, PANEL_BORDER)}",
                   "display": "flex", "align_items": "center",
                   "justify_content": "center"},
        ),
        rx.text(d["name"], style={"font_size": "13px", "color": TEXT, "width": "200px"}),
        rx.text(d["mac"], style={"font_family": MONO, "font_size": "11px", "color": MUTED}),
        on_click=lambda: State.toggle_wol_device(d["name"]),
        width="100%", align="center", spacing="3",
        style={"padding": "10px 4px", "cursor": "pointer",
               "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def wlan_row(w: Dict[str, Any]) -> rx.Component:
    armed = State.confirm_delete_wlan == w["id"]
    return rx.hstack(
        rx.icon("wifi", size=15, color=rx.cond(w["enabled"], ACCENT, MUTED)),
        rx.text(w["name"], style={"font_size": "13px", "color": TEXT,
                                  "width": "200px", "flex_shrink": "0"}),
        rx.text(w["vlan"], style={"font_family": MONO, "font_size": "12px",
                                  "color": MUTED, "width": "70px", "flex_shrink": "0"}),
        pill(rx.cond(w["enabled"], "ENABLED", "DISABLED"),
             rx.cond(w["enabled"], ACCENT, MUTED),
             rx.cond(w["enabled"], ACCENT_DIM, "rgba(255,255,255,0.05)")),
        rx.spacer(),
        rx.button("Edit",
                  on_click=lambda: State.begin_edit_wlan(w["id"], w["name"], w["vlan"]),
                  style={"font_family": MONO, "font_size": "11px", "cursor": "pointer",
                         "padding": "5px 12px", "border_radius": "8px",
                         "background": ACCENT_DIM, "color": ACCENT,
                         "border": "1px solid rgba(52,211,153,0.3)", "flex_shrink": "0"}),
        rx.cond(
            armed,
            rx.hstack(
                rx.button("Confirm?", on_click=lambda: State.remove_wlan(w["id"]),
                          style={"font_family": MONO, "font_size": "11px",
                                 "cursor": "pointer", "padding": "5px 12px",
                                 "border_radius": "8px", "background": DANGER,
                                 "color": INK, "border": "none"}),
                rx.button("✕", on_click=State.cancel_delete_wlan,
                          style={"font_family": MONO, "font_size": "11px",
                                 "cursor": "pointer", "padding": "5px 9px",
                                 "border_radius": "8px",
                                 "background": "rgba(255,255,255,0.04)", "color": MUTED,
                                 "border": f"1px solid {PANEL_BORDER}"}),
                spacing="1", flex_shrink="0",
            ),
            rx.button("Delete", on_click=lambda: State.ask_delete_wlan(w["id"]),
                      style={"font_family": MONO, "font_size": "11px", "cursor": "pointer",
                             "padding": "5px 12px", "border_radius": "8px",
                             "background": DANGER_DIM, "color": DANGER,
                             "border": "1px solid rgba(248,113,113,0.3)",
                             "flex_shrink": "0"}),
        ),
        width="100%", align="center", spacing="2",
        style={"padding": "10px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def schedule_page() -> rx.Component:
    return page_shell(
        "Schedule", "Time-based access policy and automation jobs",
        rx.hstack(
            stat_card("Scheduler", rx.cond(State.scheduler_running, "RUNNING", "STOPPED"),
                      rx.cond(State.scheduler_running, ACCENT, MUTED)),
            stat_card("Active Jobs", State.scheduler_jobs.length()),
            width="100%", spacing="3", margin_bottom="20px",
        ),
        glass(
            section_label("SCHEDULED JOBS"),
            rx.cond(
                State.scheduler_jobs,
                rx.vstack(
                    col_header(("", "15px"), ("Job", "280px"), ("Next Run", None)),
                    rx.foreach(State.scheduler_jobs, lambda j: rx.hstack(
                        rx.icon("clock", size=15, color=ACCENT),
                        rx.text(j["name"], style={"font_size": "13px", "color": TEXT,
                                                  "width": "280px", "flex_shrink": "0"}),
                        rx.text(j["next_run"], style={"font_family": MONO, "font_size": "11px",
                                                      "color": MUTED}),
                        width="100%", align="center", spacing="3",
                        style={"padding": "11px 4px",
                               "border_bottom": f"1px solid {PANEL_BORDER}"})),
                    spacing="0", width="100%",
                ),
                rx.text("Scheduler jobs load automatically.", style={"color": MUTED,
                                                                     "font_size": "13px"}),
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        glass(
            section_label("TIME-BASED ACCESS POLICY", mb="6px"),
            rx.text("Set the window during which internet access is restricted across all "
                    "vendors — Cisco ACLs, MikroTik firewall, and UniFi SSIDs. Applied "
                    "automatically by the scheduler (the window can run overnight, "
                    "e.g. 6 PM to 8 AM).",
                    style={"color": MUTED, "font_size": "12px", "margin_bottom": "16px",
                           "line_height": "1.6"}),
            rx.hstack(
                rx.vstack(
                    rx.text("Restrict FROM", style={"font_size": "11px", "color": MUTED}),
                    rx.hstack(
                        rx.select(HOURS_12, value=State.start_hour12,
                                  on_change=State.set_start_hour12, width="80px"),
                        rx.select(["AM", "PM"], value=State.start_ampm,
                                  on_change=State.set_start_ampm, width="80px"),
                        spacing="2",
                    ),
                    spacing="1", align="start",
                ),
                rx.vstack(
                    rx.text("Restrict UNTIL", style={"font_size": "11px", "color": MUTED}),
                    rx.hstack(
                        rx.select(HOURS_12, value=State.end_hour12,
                                  on_change=State.set_end_hour12, width="80px"),
                        rx.select(["AM", "PM"], value=State.end_ampm,
                                  on_change=State.set_end_ampm, width="80px"),
                        spacing="2",
                    ),
                    spacing="1", align="start",
                ),
                rx.vstack(
                    rx.text("Enabled", style={"font_size": "11px", "color": MUTED}),
                    rx.switch(checked=State.policy_enabled,
                              on_change=State.toggle_policy_enabled, color_scheme="green"),
                    spacing="1", align="start",
                ),
                rx.spacer(),
                btn("Save Policy", State.save_policy, style={"align_self": "end",
                                                             "padding": "10px 20px"}),
                width="100%", spacing="4", align="end",
            ),
            rx.box(
                rx.text(
                    "Current: restrict access from "
                    + State.start_hour12 + " " + State.start_ampm + " until "
                    + State.end_hour12 + " " + State.end_ampm + ".",
                    style={"font_family": MONO, "font_size": "12px", "color": WARN}),
                style={"margin_top": "14px", "padding": "10px 14px", "border_radius": "8px",
                       "background": "rgba(251,191,36,0.06)",
                       "border": "1px solid rgba(251,191,36,0.2)"},
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        glass(
            rx.hstack(
                section_label("WIRELESS NETWORKS", mb="0px"),
                rx.cond(State.wlan_device != "",
                        rx.text(State.wlan_device,
                                style={"font_family": MONO, "font_size": "12px",
                                       "color": ACCENT}),
                        rx.text("")),
                spacing="2", align="center", margin_bottom="6px",
            ),
            rx.text("SSIDs on the UniFi controller. The scheduler switches these off "
                    "during the restricted window and back on in work hours — "
                    "management SSIDs are never touched, so the admin can't be "
                    "locked out.",
                    style={"color": MUTED, "font_size": "12px", "margin_bottom": "14px",
                           "line_height": "1.6"}),
            rx.cond(
                State.wlans,
                rx.vstack(
                    col_header(("", "15px"), ("SSID", "200px"), ("VLAN", "70px"),
                               ("State", None), ("Action", "150px")),
                    rx.foreach(State.wlans, wlan_row),
                    spacing="0", width="100%",
                ),
                rx.hstack(
                    rx.icon("wifi-off", size=16, color=MUTED),
                    rx.text(rx.cond(State.wlan_note != "", State.wlan_note,
                                    "No wireless networks reported."),
                            style={"color": MUTED, "font_size": "12px"}),
                    spacing="2", align="center",
                ),
            ),
            rx.cond(
                State.editing_wlan_id != "",
                rx.vstack(
                    rx.text("EDIT SSID", style={"font_family": MONO, "font_size": "11px",
                                                "letter_spacing": "0.12em", "color": ACCENT,
                                                "margin_top": "14px"}),
                    rx.input(placeholder="SSID name", value=State.edit_ssid_name,
                             on_change=State.set_edit_ssid_name, width="100%",
                             style={"font_family": MONO, "font_size": "12px",
                                    "background": "rgba(0,0,0,0.25)", "color": TEXT,
                                    "border": f"1px solid {PANEL_BORDER}",
                                    "border_radius": "8px", "padding": "8px 12px"}),
                    rx.input(placeholder="New password (leave blank to keep current)",
                             value=State.edit_ssid_pass, type="password", width="100%",
                             on_change=State.set_edit_ssid_pass,
                             style={"font_family": MONO, "font_size": "12px",
                                    "background": "rgba(0,0,0,0.25)", "color": TEXT,
                                    "border": f"1px solid {PANEL_BORDER}",
                                    "border_radius": "8px", "padding": "8px 12px"}),
                    rx.input(placeholder="VLAN id (blank = untagged)",
                             value=State.edit_ssid_vlan, width="100%",
                             on_change=State.set_edit_ssid_vlan,
                             style={"font_family": MONO, "font_size": "12px",
                                    "background": "rgba(0,0,0,0.25)", "color": TEXT,
                                    "border": f"1px solid {PANEL_BORDER}",
                                    "border_radius": "8px", "padding": "8px 12px"}),
                    rx.hstack(
                        btn("Save Changes", State.save_wlan_edit),
                        btn("Cancel", State.cancel_edit_wlan, color=MUTED,
                            dim="rgba(255,255,255,0.04)", border=PANEL_BORDER),
                        spacing="3",
                    ),
                    spacing="2", width="100%", align="start",
                    style={"margin_top": "10px", "padding": "14px",
                           "border_radius": "10px", "background": "rgba(255,255,255,0.02)",
                           "border": f"1px solid {PANEL_BORDER}"}),
                rx.box(),
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        glass(
            section_label("WAKE-ON-LAN", mb="6px"),
            rx.text("Select devices to power on with a magic packet, or wake all managed "
                    "devices at once.",
                    style={"color": MUTED, "font_size": "12px", "margin_bottom": "14px"}),
            rx.cond(
                State.devices,
                rx.vstack(rx.foreach(State.devices, wol_device_row), spacing="0",
                          width="100%"),
                rx.text("Devices load automatically.", style={"color": MUTED,
                                                              "font_size": "13px"}),
            ),
            rx.hstack(
                btn("Wake Selected", State.wake_selected),
                rx.cond(
                    State.confirm_wake_all,
                    rx.hstack(
                        btn("Confirm: wake ALL", State.wake_all, color=WARN, dim=WARN_DIM,
                            border="rgba(251,191,36,0.35)"),
                        btn("Cancel", State.cancel_wake_all, color=MUTED,
                            dim="rgba(255,255,255,0.04)", border=PANEL_BORDER),
                        spacing="2",
                    ),
                    btn("Wake All", State.ask_wake_all, color=INFO, dim=INFO_DIM,
                        border="rgba(96,165,250,0.35)"),
                ),
                spacing="3", margin_top="16px",
            ),
            style={"width": "100%"},
        ),
        on_mount=State.load_schedule_page,
    )


# ── PAGE: Audit ───────────────────────────────────────────────────────────────
def audit_row(l: Dict[str, Any]) -> rx.Component:
    sev_color = rx.match(l["sev"], ("CRITICAL", DANGER), ("ERROR", DANGER),
                         ("WARNING", WARN), INFO)
    sev_dim = rx.match(l["sev"], ("CRITICAL", DANGER_DIM), ("ERROR", DANGER_DIM),
                       ("WARNING", WARN_DIM), INFO_DIM)
    return rx.hstack(
        rx.text(l["time"], style={"font_family": MONO, "font_size": "11px", "color": MUTED,
                                  "width": "150px", "flex_shrink": "0"}),
        rx.box(pill(l["sev"], sev_color, sev_dim), style={"width": "92px",
                                                          "flex_shrink": "0"}),
        rx.text(l["event"], style={"font_family": MONO, "font_size": "11px", "color": TEXT,
                                   "width": "200px", "flex_shrink": "0",
                                   "white_space": "nowrap", "overflow": "hidden",
                                   "text_overflow": "ellipsis"}),
        rx.text(l["user"], style={"font_family": MONO, "font_size": "11px", "color": ACCENT,
                                  "width": "80px", "flex_shrink": "0"}),
        rx.text(l["details"], style={"font_size": "12px", "color": MUTED, "flex": "1",
                                     "white_space": "nowrap", "overflow": "hidden",
                                     "text_overflow": "ellipsis"}),
        width="100%", align="center", spacing="3",
        style={"padding": "9px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def audit_page() -> rx.Component:
    return page_shell(
        "Audit", "Server-side audit trail — every authenticated action, recorded",
        glass(
            rx.hstack(
                section_label("AUDIT LOG (LAST 100)", mb="0px"),
                rx.spacer(),
                btn("Reload", State.load_audit, color=MUTED, dim="rgba(255,255,255,0.04)",
                    border=PANEL_BORDER, style={"padding": "5px 14px",
                                                "font_size": "10px"}),
                width="100%", align="center", margin_bottom="12px",
            ),
            rx.cond(
                State.audit_logs,
                rx.vstack(
                    col_header(("Timestamp", "150px"), ("Severity", "92px"),
                               ("Event", "200px"), ("User", "80px"), ("Details", None)),
                    rx.foreach(State.audit_logs, audit_row),
                    spacing="0", width="100%",
                ),
                rx.text("No audit entries loaded. (The audit log requires the admin role.)",
                        style={"color": MUTED, "font_size": "13px"}),
            ),
            style={"width": "100%"},
        ),
        on_mount=State.load_audit,
    )


# ── PAGE: Settings ────────────────────────────────────────────────────────────
def authorized_row(a: Dict[str, Any]) -> rx.Component:
    mac = a["mac"]
    armed = State.confirm_remove_mac == mac
    return rx.hstack(
        rx.icon("shield-check", size=15, color=ACCENT),
        rx.text(mac, style={"font_family": MONO, "font_size": "13px", "color": TEXT,
                            "width": "200px", "flex_shrink": "0"}),
        rx.text(a["label"], style={"font_size": "12px", "color": MUTED, "flex": "1"}),
        rx.cond(
            armed,
            rx.hstack(
                rx.button("Confirm?", on_click=lambda: State.remove_authorized(mac),
                          style={"font_family": MONO, "font_size": "10px",
                                 "cursor": "pointer", "padding": "4px 12px",
                                 "border_radius": "7px", "background": DANGER,
                                 "color": INK, "border": "none"}),
                rx.button("✕", on_click=State.cancel_remove,
                          style={"font_family": MONO, "font_size": "10px",
                                 "cursor": "pointer", "padding": "4px 9px",
                                 "border_radius": "7px",
                                 "background": "rgba(255,255,255,0.04)", "color": MUTED,
                                 "border": f"1px solid {PANEL_BORDER}"}),
                spacing="1",
            ),
            rx.button("Remove", on_click=lambda: State.ask_remove_authorized(mac),
                      style={"font_family": MONO, "font_size": "10px", "cursor": "pointer",
                             "padding": "4px 12px", "border_radius": "7px",
                             "background": DANGER_DIM, "color": DANGER,
                             "border": "1px solid rgba(248,113,113,0.3)"}),
        ),
        width="100%", align="center", spacing="3",
        style={"padding": "10px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def user_row(u: Dict[str, Any]) -> rx.Component:
    uname = u["username"]
    role = u["role"]
    armed = State.confirm_del_user == uname
    role_color = rx.match(role, ("admin", ACCENT), ("operator", INFO), MUTED)
    role_dim = rx.match(role, ("admin", ACCENT_DIM), ("operator", INFO_DIM),
                        "rgba(255,255,255,0.05)")
    return rx.hstack(
        rx.icon("user", size=15, color=role_color),
        rx.text(uname, style={"font_family": MONO, "font_size": "13px", "color": TEXT,
                              "width": "200px", "flex_shrink": "0"}),
        rx.box(pill(role, role_color, role_dim),
               style={"width": "140px", "flex_shrink": "0"}),
        rx.spacer(),
        rx.cond(
            armed,
            rx.hstack(
                rx.button("Confirm?", on_click=lambda: State.delete_user(uname),
                          style={"font_family": MONO, "font_size": "10px",
                                 "cursor": "pointer", "padding": "4px 12px",
                                 "border_radius": "7px", "background": DANGER,
                                 "color": INK, "border": "none"}),
                rx.button("✕", on_click=State.cancel_delete_user,
                          style={"font_family": MONO, "font_size": "10px",
                                 "cursor": "pointer", "padding": "4px 9px",
                                 "border_radius": "7px",
                                 "background": "rgba(255,255,255,0.04)", "color": MUTED,
                                 "border": f"1px solid {PANEL_BORDER}"}),
                spacing="1",
            ),
            rx.button("Remove", on_click=lambda: State.ask_delete_user(uname),
                      style={"font_family": MONO, "font_size": "10px", "cursor": "pointer",
                             "padding": "4px 12px", "border_radius": "7px",
                             "background": DANGER_DIM, "color": DANGER,
                             "border": "1px solid rgba(248,113,113,0.3)"}),
        ),
        width="100%", align="center", spacing="3",
        style={"padding": "10px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def settings_page() -> rx.Component:
    return page_shell(
        "Settings", "Connection and source-of-truth configuration",
        glass(
            section_label("SESSION"),
            rx.hstack(
                rx.text("API endpoint:", style={"color": MUTED, "font_size": "13px"}),
                rx.text(API_BASE, style={"font_family": MONO, "font_size": "13px",
                                         "color": TEXT}),
                spacing="2",
            ),
            rx.hstack(
                rx.text("Signed in as:", style={"color": MUTED, "font_size": "13px"}),
                rx.text(State.current_user, style={"font_family": MONO, "font_size": "13px",
                                                   "color": TEXT}),
                pill(State.current_role, ACCENT, ACCENT_DIM),
                spacing="2", align="center",
            ),
            rx.hstack(
                rx.text("Status:", style={"color": MUTED, "font_size": "13px"}),
                rx.text(rx.cond(State.connected, "Connected", "Disconnected"),
                        style={"font_family": MONO, "font_size": "13px",
                               "color": rx.cond(State.connected, ACCENT, MUTED)}),
                spacing="2",
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        glass(
            section_label("ACCOUNT SECURITY", mb="6px"),
            rx.hstack(
                rx.text("Change your sign-in password. Your role stays the same — ",
                        style={"color": MUTED, "font_size": "12px"}),
                pill(State.current_role, ACCENT, ACCENT_DIM),
                rx.text(" is preserved.", style={"color": MUTED, "font_size": "12px"}),
                spacing="1", align="center", margin_bottom="14px",
            ),
            rx.vstack(
                rx.input(placeholder="Current password", value=State.old_pw,
                         on_change=State.set_old_pw, type="password", width="100%",
                         style={"font_family": MONO, "font_size": "12px",
                                "background": "rgba(0,0,0,0.25)", "color": TEXT,
                                "border": f"1px solid {PANEL_BORDER}",
                                "border_radius": "8px", "padding": "8px 12px"}),
                rx.input(placeholder="New password (min 6 characters)", value=State.new_pw,
                         on_change=State.set_new_pw, type="password", width="100%",
                         style={"font_family": MONO, "font_size": "12px",
                                "background": "rgba(0,0,0,0.25)", "color": TEXT,
                                "border": f"1px solid {PANEL_BORDER}",
                                "border_radius": "8px", "padding": "8px 12px"}),
                rx.input(placeholder="Confirm new password", value=State.confirm_pw,
                         on_change=State.set_confirm_pw, type="password", width="100%",
                         style={"font_family": MONO, "font_size": "12px",
                                "background": "rgba(0,0,0,0.25)", "color": TEXT,
                                "border": f"1px solid {PANEL_BORDER}",
                                "border_radius": "8px", "padding": "8px 12px"}),
                btn("Change Password", State.change_password,
                    style={"align_self": "start", "padding": "9px 18px"}),
                spacing="2", width="100%", align="start",
                style={"max_width": "420px"},
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        glass(
            section_label("AUTHORIZED DEVICES", mb="6px"),
            rx.text("The source of truth for the rogue scanner. Any device on the network "
                    "whose MAC is not listed here (and isn't a managed device) is flagged "
                    "as a potential rogue.",
                    style={"color": MUTED, "font_size": "12px", "margin_bottom": "16px",
                           "line_height": "1.6"}),
            rx.hstack(
                rx.input(placeholder="MAC address (e.g. AA:BB:CC:DD:EE:FF)",
                         value=State.new_mac, on_change=State.set_new_mac,
                         style={"font_family": MONO, "font_size": "12px", "flex": "2",
                                "background": "rgba(0,0,0,0.25)",
                                "border": f"1px solid {PANEL_BORDER}",
                                "color": TEXT, "border_radius": "8px",
                                "padding": "8px 12px"}),
                rx.input(placeholder="Label (e.g. Reception PC)",
                         value=State.new_label, on_change=State.set_new_label,
                         style={"font_size": "12px", "flex": "2",
                                "background": "rgba(0,0,0,0.25)",
                                "border": f"1px solid {PANEL_BORDER}",
                                "color": TEXT, "border_radius": "8px",
                                "padding": "8px 12px"}),
                btn("Authorize", State.add_authorized, style={"flex": "1",
                                                              "padding": "8px 18px"}),
                width="100%", spacing="2", margin_bottom="16px",
            ),
            rx.cond(
                State.authorized,
                rx.vstack(
                    col_header(("", "15px"), ("MAC Address", "200px"), ("Label", None),
                               ("Action", "90px")),
                    rx.foreach(State.authorized, authorized_row),
                    spacing="0", width="100%",
                ),
                rx.text("No authorized devices yet. Add one above, or click 'Trust' on a "
                        "detected device.",
                        style={"color": MUTED, "font_size": "13px"}),
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        glass(
            section_label("USER MANAGEMENT", mb="6px"),
            rx.text("Provision accounts for staff. Accounts are admin-created with a "
                    "role — there is no public sign-up for this privileged console. "
                    "(Admin-only; visible and editable only by administrators.)",
                    style={"color": MUTED, "font_size": "12px", "margin_bottom": "16px",
                           "line_height": "1.6"}),
            rx.cond(
                State.role_is_admin,
                rx.vstack(
                    rx.hstack(
                        rx.input(placeholder="Username", value=State.nu_username,
                                 on_change=State.set_nu_username,
                                 style={"font_family": MONO, "font_size": "12px", "flex": "2",
                                        "background": "rgba(0,0,0,0.25)",
                                        "border": f"1px solid {PANEL_BORDER}",
                                        "color": TEXT, "border_radius": "8px",
                                        "padding": "8px 12px"}),
                        rx.input(placeholder="Initial password (6+ chars)",
                                 value=State.nu_password, type="password",
                                 on_change=State.set_nu_password,
                                 style={"font_family": MONO, "font_size": "12px", "flex": "2",
                                        "background": "rgba(0,0,0,0.25)",
                                        "border": f"1px solid {PANEL_BORDER}",
                                        "color": TEXT, "border_radius": "8px",
                                        "padding": "8px 12px"}),
                        rx.select(["admin", "operator", "viewer"], value=State.nu_role,
                                  on_change=State.set_nu_role, width="130px"),
                        btn("Create User", State.create_user,
                            style={"flex": "1", "padding": "8px 16px"}),
                        width="100%", spacing="2", margin_bottom="16px",
                    ),
                    rx.vstack(
                        col_header(("", "15px"), ("Username", "200px"), ("Role", "140px"),
                                   ("Action", None)),
                        rx.foreach(State.users, user_row),
                        spacing="0", width="100%",
                    ),
                    spacing="0", width="100%",
                ),
                pill("ADMIN ROLE REQUIRED TO MANAGE USERS", WARN, WARN_DIM),
            ),
            style={"width": "100%"},
        ),
        on_mount=State.load_settings_page,
    )


# ── PAGE: How It Works ────────────────────────────────────────────────────────
def how_step(num: str, title: str, body: str) -> rx.Component:
    return rx.hstack(
        rx.box(rx.text(num, style={"font_family": MONO, "font_size": "16px",
                                   "font_weight": "700", "color": ACCENT}),
               style={"width": "40px", "height": "40px", "border_radius": "10px",
                      "background": ACCENT_DIM, "display": "flex",
                      "align_items": "center", "justify_content": "center",
                      "flex_shrink": "0"}),
        rx.vstack(
            rx.text(title, style={"font_weight": "600", "color": TEXT, "font_size": "15px"}),
            rx.text(body, style={"color": MUTED, "font_size": "13px", "line_height": "1.6"}),
            spacing="1", align="start",
        ),
        spacing="4", align="start", width="100%",
        style={"padding": "14px 0", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def how_page() -> rx.Component:
    return page_shell(
        "How It Works", "Plain-language overview of the framework",
        glass(
            how_step("1", "Unified Control",
                     "UAF talks to Cisco (CLI/SSH), MikroTik (API) and Ubiquiti (REST) through "
                     "one common driver layer. One action — like disabling a port — is "
                     "translated into each vendor's own commands automatically."),
            how_step("2", "Source of Truth",
                     "An authoritative inventory records every device and its authorized MAC "
                     "addresses. Anything seen on the network that isn't registered is treated "
                     "as a potential rogue device."),
            how_step("3", "Automated Kill-Switch",
                     "A background scan reads each switch's MAC table. If an unregistered "
                     "device appears, the matching driver shuts its port down automatically — "
                     "in under a second, with no human needed."),
            how_step("4", "Time-Based Access",
                     "The scheduler enforces internet-access windows across all vendors — "
                     "Cisco ACLs, MikroTik firewall rules, and UniFi SSID schedules — and can "
                     "wake machines before business hours with Wake-on-LAN."),
            how_step("5", "Secure by Design",
                     "Every action goes through a JWT-authenticated REST API with role-based "
                     "access control (Viewer / Operator / Admin), and every action is recorded "
                     "in a server-side audit trail — Zero-Trust principles throughout."),
            style={"width": "100%"},
        ),
    )


# ── PAGE: Monitoring ──────────────────────────────────────────────────────────
def monitor_row(d: Dict[str, Any]) -> rx.Component:
    dot = rx.match(d["status"], ("online", ACCENT), ("offline", DANGER), MUTED)
    return rx.hstack(
        rx.box(style={"width": "8px", "height": "8px", "border_radius": "50%",
                      "background": dot, "flex_shrink": "0"}),
        rx.text(d["name"], style={"font_size": "13px", "font_weight": "500",
                                  "color": TEXT, "width": "170px", "flex_shrink": "0",
                                  "white_space": "nowrap", "overflow": "hidden",
                                  "text_overflow": "ellipsis"}),
        rx.text(d["ip"], style={"font_family": MONO, "font_size": "11px",
                                "color": MUTED, "width": "110px", "flex_shrink": "0"}),
        rx.box(pill(d["platform"], INFO, INFO_DIM),
               style={"width": "130px", "flex_shrink": "0"}),
        rx.box(pill(rx.cond(d["status"] == "online", "ONLINE", "OFFLINE"),
                    rx.cond(d["status"] == "online", ACCENT, DANGER),
                    rx.cond(d["status"] == "online", ACCENT_DIM, DANGER_DIM)),
               style={"width": "90px", "flex_shrink": "0"}),
        rx.text(d["up"].to_string() + " / " + d["total"].to_string(),
                style={"font_family": MONO, "font_size": "12px", "color": TEXT,
                       "width": "80px", "flex_shrink": "0"}),
        rx.text(d["checked"], style={"font_family": MONO, "font_size": "11px",
                                     "color": MUTED, "flex": "1"}),
        width="100%", align="center", spacing="3",
        style={"padding": "10px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def monitoring_page() -> rx.Component:
    return page_shell(
        "Monitoring", "Live health metrics across the whole network",
        rx.hstack(
            stat_card("Network Availability", State.net_availability, ACCENT),
            stat_card("Interfaces Up", State.net_if_up, ACCENT),
            stat_card("Interfaces Down", State.net_if_down,
                      rx.cond(State.net_if_down > 0, DANGER, MUTED)),
            stat_card("Total Interfaces", State.net_if_total),
            width="100%", spacing="3", margin_bottom="20px",
        ),
        glass(
            rx.hstack(
                section_label("PER-DEVICE METRICS", mb="0px"),
                rx.spacer(),
                rx.button(
                    rx.hstack(rx.icon("refresh-cw", size=12), rx.text("Collect Metrics"),
                              spacing="1", align="center"),
                    on_click=State.load_monitor, loading=State.monitor_loading,
                    style={"font_family": MONO, "font_size": "10px",
                           "cursor": "pointer", "padding": "5px 14px",
                           "border_radius": "7px", "background": ACCENT_DIM,
                           "color": ACCENT,
                           "border": "1px solid rgba(52,211,153,0.3)"},
                ),
                width="100%", align="center", margin_bottom="12px",
            ),
            rx.cond(
                State.monitor_rows,
                rx.vstack(
                    col_header(("", "8px"), ("Device", "170px"), ("IP", "110px"),
                               ("Vendor", "130px"), ("Status", "90px"),
                               ("If Up", "80px"), ("Last Checked", None)),
                    rx.foreach(State.monitor_rows, monitor_row),
                    spacing="0", width="100%",
                ),
                rx.cond(
                    State.monitor_loading,
                    rx.hstack(rx.icon("loader", size=16, color=MUTED),
                              rx.text("Connecting to every device — this can take "
                                      "up to half a minute if some are offline…",
                                      style={"color": MUTED, "font_size": "12px"}),
                              spacing="2", align="center"),
                    rx.text("Click 'Collect Metrics' to poll every device.",
                            style={"color": MUTED, "font_size": "13px"}),
                ),
            ),
            style={"width": "100%"},
        ),
        on_mount=State.load_monitor,
    )


# ── PAGE: Provision (admin) ───────────────────────────────────────────────────
def prov_input(label: str, value, on_change, placeholder: str,
               password: bool = False) -> rx.Component:
    return rx.vstack(
        rx.text(label, style={"font_size": "11px", "color": MUTED}),
        rx.input(value=value, on_change=on_change, placeholder=placeholder,
                 type="password" if password else "text", width="100%",
                 style={"font_family": MONO, "font_size": "12px",
                        "background": "rgba(0,0,0,0.25)", "color": TEXT,
                        "border": f"1px solid {PANEL_BORDER}",
                        "border_radius": "8px", "padding": "8px 12px"}),
        spacing="1", align="start", style={"flex": "1"},
    )


def prov_result_row(r: Dict[str, Any]) -> rx.Component:
    return rx.hstack(
        rx.icon(rx.cond(r["ok"], "circle-check", "circle-x"), size=15,
                color=rx.cond(r["ok"], ACCENT, DANGER)),
        rx.text(r["step"], style={"font_family": MONO, "font_size": "12px",
                                  "color": TEXT, "width": "220px",
                                  "flex_shrink": "0"}),
        rx.text(r["device"], style={"font_family": MONO, "font_size": "12px",
                                    "color": MUTED, "width": "170px",
                                    "flex_shrink": "0"}),
        rx.text(r["info"], style={"font_size": "12px", "color": MUTED, "flex": "1",
                                  "white_space": "nowrap", "overflow": "hidden",
                                  "text_overflow": "ellipsis"}),
        width="100%", align="center", spacing="3",
        style={"padding": "9px 4px", "border_bottom": f"1px solid {PANEL_BORDER}"},
    )


def provision_page() -> rx.Component:
    return page_shell(
        "Provision", "One intent — every vendor configured automatically",
        glass(
            section_label("NEW NETWORK SEGMENT", mb="6px"),
            rx.text("Describe WHAT you want; UAF works out HOW on each vendor: "
                    "VLAN + port assignment (+ optional port security) on Cisco, "
                    "DHCP pool on MikroTik, and an optional Wi-Fi SSID on UniFi.",
                    style={"color": MUTED, "font_size": "12px",
                           "margin_bottom": "16px", "line_height": "1.6"}),
            rx.hstack(
                prov_input("Network Name *", State.prov_name, State.set_prov_name,
                           "e.g. Student-Lab"),
                prov_input("VLAN ID * (2–4094)", State.prov_vlan, State.set_prov_vlan,
                           "20"),
                width="100%", spacing="3", margin_bottom="12px",
            ),
            rx.hstack(
                prov_input("Subnet (CIDR) *", State.prov_subnet, State.set_prov_subnet,
                           "192.168.20.0/24"),
                prov_input("Gateway", State.prov_gateway, State.set_prov_gateway,
                           "192.168.20.1"),
                width="100%", spacing="3", margin_bottom="12px",
            ),
            prov_input("Cisco Switch Ports (comma-separated)", State.prov_ports,
                       State.set_prov_ports,
                       "GigabitEthernet0/1, GigabitEthernet0/2"),
            rx.hstack(
                prov_input("Wi-Fi SSID (optional)", State.prov_ssid,
                           State.set_prov_ssid, "Student-WiFi"),
                prov_input("Wi-Fi Password", State.prov_psk, State.set_prov_psk,
                           "min 8 characters", password=True),
                width="100%", spacing="3", margin_top="12px",
                margin_bottom="14px",
            ),
            rx.hstack(
                rx.hstack(
                    rx.switch(checked=State.prov_dhcp,
                              on_change=State.toggle_prov_dhcp, color_scheme="green"),
                    rx.text("DHCP pool (MikroTik)", style={"font_size": "12px",
                                                           "color": MUTED}),
                    spacing="2", align="center",
                ),
                rx.hstack(
                    rx.switch(checked=State.prov_sec,
                              on_change=State.toggle_prov_sec, color_scheme="green"),
                    rx.text("Port security (Cisco)", style={"font_size": "12px",
                                                            "color": MUTED}),
                    spacing="2", align="center",
                ),
                rx.spacer(),
                rx.cond(
                    State.role_is_admin,
                    rx.button("Provision Network", on_click=State.run_provision,
                              loading=State.prov_running,
                              style={"font_family": MONO, "font_size": "12px",
                                     "font_weight": "600", "cursor": "pointer",
                                     "padding": "10px 22px", "border_radius": "9px",
                                     "background": ACCENT, "color": INK,
                                     "border": "none"}),
                    pill("ADMIN ROLE REQUIRED", WARN, WARN_DIM),
                ),
                width="100%", spacing="4", align="center",
            ),
            style={"width": "100%", "margin_bottom": "18px"},
        ),
        rx.cond(
            State.prov_summary != "",
            glass(
                rx.hstack(
                    section_label("PROVISIONING RESULT", mb="0px"),
                    rx.spacer(),
                    rx.text(State.prov_summary,
                            style={"font_family": MONO, "font_size": "12px",
                                   "color": WARN}),
                    width="100%", align="center", margin_bottom="12px",
                ),
                rx.vstack(
                    col_header(("", "15px"), ("Step", "220px"), ("Device", "170px"),
                               ("Detail", None)),
                    rx.foreach(State.prov_results, prov_result_row),
                    spacing="0", width="100%",
                ),
                style={"width": "100%"},
            ),
            rx.box(),
        ),
    )


# ── App registration ─────────────────────────────────────────────────────────
app = rx.App(
    head_components=[
        rx.el.link(rel="preconnect", href="https://fonts.googleapis.com"),
        rx.el.link(
            href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap",
            rel="stylesheet",
        ),
        rx.el.style(
            "@keyframes auroraShift{0%,100%{background-position:0% 50%,100% 50%,50% 100%,0 0}"
            "50%{background-position:100% 50%,0% 50%,50% 0%,0 0}}"
            "@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}"
            "input,textarea,select{color:#e6edf3 !important;}"
            "input::placeholder,textarea::placeholder{color:#9fb0c3 !important;opacity:1 !important;}"
            "select option{color:#0a0e14 !important;background:#e6edf3 !important;}"
            "::-webkit-input-placeholder{color:#9fb0c3 !important;opacity:1 !important;}"
            "input:-internal-autofill-selected{-webkit-text-fill-color:#e6edf3 !important;}"
        ),
    ],
)
app.add_page(login_page, route="/login", title="Sign In · UAF", on_load=State.guard_login)
app.add_page(dashboard, route="/", title="Dashboard · UAF", on_load=State.guard)
app.add_page(devices_page, route="/devices", title="Devices · UAF", on_load=State.guard)
app.add_page(security_page, route="/security", title="Security · UAF", on_load=State.guard)
app.add_page(monitoring_page, route="/monitor", title="Monitoring · UAF", on_load=State.guard)
app.add_page(provision_page, route="/provision", title="Provision · UAF", on_load=State.guard)
app.add_page(schedule_page, route="/schedule", title="Schedule · UAF", on_load=State.guard)
app.add_page(audit_page, route="/audit", title="Audit · UAF", on_load=State.guard)
app.add_page(settings_page, route="/settings", title="Settings · UAF", on_load=State.guard)
app.add_page(how_page, route="/how", title="How It Works · UAF", on_load=State.guard)