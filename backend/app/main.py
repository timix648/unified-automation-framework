"""
UAF Backend - Main Application Entry Point
===========================================
This is the core FastAPI application that orchestrates all services.

FIXES APPLIED:
- CRITICAL (CORS): allow_origins=["*"] + allow_credentials=True is rejected by
  browsers per the CORS spec. Credentials require an explicit origin list.
  Now uses a configurable ALLOWED_ORIGINS list that defaults to common dev URLs.
- ADDED: Rate limiting middleware to protect security-critical endpoints
  (kill-switch, port-control, auth) from abuse.
- ADDED: Request audit logging middleware for API access tracking.
- ADDED: Auth router properly mounted (was already fixed previously).
"""

from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
import time
import logging
from collections import defaultdict

import os
from app.core.config import settings
from app.api.endpoints import router
from app.api.auth import router as auth_router
from app.services.scheduler import start_scheduler, scheduler
from app.services.metrics import metrics_exporter
try:
    from app.core.snmp_trap_listener import TrapToKillSwitchBridge
except Exception:
    # Legacy asyncore-based pysnmp cannot import on Python 3.12+ (asyncore
    # was removed). We degrade gracefully rather than crash.
    TrapToKillSwitchBridge = None

# SNMP traps are an OPTIONAL real-time detection source, OFF by default.
# Automated response always runs via the scheduled rogue-MAC scan.
SNMP_AVAILABLE = TrapToKillSwitchBridge is not None
ENABLE_SNMP_TRAPS = os.getenv("ENABLE_SNMP_TRAPS", "false").lower() == "true"
from app.services.kill_switch import KillSwitchService
from app.services.device_manager import DeviceFactory

logger = logging.getLogger(__name__)

# ============================================================================
# RATE LIMITING
# ============================================================================

class RateLimitMiddleware:
    """
    Simple in-memory rate limiter using a sliding window approach.
    
    Critical for a security-focused project to prevent:
    - Brute-force login attempts
    - Kill-switch endpoint abuse
    - Port-control spam
    """

    def __init__(self, app, default_rpm: int = 120, strict_rpm: int = 20):
        """
        Args:
            app: ASGI application
            default_rpm: Requests per minute for normal endpoints
            strict_rpm: Requests per minute for security-critical endpoints
        """
        self.app = app
        self.default_rpm = default_rpm
        self.strict_rpm = strict_rpm
        self.request_log: dict = defaultdict(list)

        # Endpoints with stricter rate limits
        self.strict_endpoints = {
            "/api/auth/login",
            "/api/devices/port-control",
            "/api/security/alert",
            "/api/security/scan",
            "/api/security/restore",
            "/api/power/wake",
        }

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract client IP
        client_ip = (scope.get("client") or ("unknown", 0))[0]
        path = scope.get("path", "")
        now = time.time()

        # Determine rate limit for this endpoint
        rpm_limit = self.strict_rpm if path in self.strict_endpoints else self.default_rpm

        # Clean old entries (older than 60 seconds)
        key = f"{client_ip}:{path}" if path in self.strict_endpoints else client_ip
        self.request_log[key] = [t for t in self.request_log[key] if now - t < 60]

        if len(self.request_log[key]) >= rpm_limit:
            # Rate limit exceeded — return 429
            response = Response(
                content='{"detail":"Rate limit exceeded. Please slow down."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"}
            )
            await response(scope, receive, send)
            return

        self.request_log[key].append(now)
        await self.app(scope, receive, send)


# ============================================================================
# LIFESPAN (Startup/Shutdown)
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager - runs on startup and shutdown.
    This is where we initialize background services.
    """
    # STARTUP LOGIC
    print("=" * 60)
    print(f"🚀 {settings.PROJECT_NAME} v{settings.VERSION}")
    print("=" * 60)
    print(f"🔧 Mock Mode: {'ENABLED' if settings.MOCK_MODE else 'DISABLED'}")
    print(f"🌐 NetBox URL: {settings.NETBOX_URL}")
    print("=" * 60)

    # Start the background scheduler for automation tasks
    start_scheduler()
    print("✅ Background scheduler started")

    # Bind the real-time event bus to this running loop so publishers in
    # worker threads (scheduler jobs, SNMP trap bridge, kill-switch) can reach
    # WebSocket subscribers safely (Report 4.7 real-time alerts).
    try:
        import asyncio as _asyncio
        from app.services.event_bus import event_bus
        event_bus.bind_loop(_asyncio.get_running_loop())
        print("✅ Real-time event bus bound to loop")
    except Exception as _e:
        print(f"⚠️  Event bus loop binding failed: {_e}")

    # Automated kill-switch detection runs via the scheduled rogue-MAC scan
    # (auto_scan_for_rogues, every 5 min) — always on, needs no trap source.
    # The SNMP trap listener is an OPTIONAL additional real-time source. It is
    # off by default and requires: an asyncio-capable pysnmp build (legacy
    # asyncore pysnmp 4.x cannot run on Python 3.12+), a device configured to
    # emit traps, and privileges to bind UDP 162.
    trap_bridge = None
    if not ENABLE_SNMP_TRAPS:
        print("ℹ️  SNMP trap listener disabled (set ENABLE_SNMP_TRAPS=true to enable).")
        print("   Automated response is active via the scheduled rogue-device scan.")
    elif not SNMP_AVAILABLE:
        print("⚠️  SNMP traps requested, but the listener module could not load on this")
        print("   Python/pysnmp build — continuing without it. Rogue scan still active.")
    elif settings.MOCK_MODE:
        print("ℹ️  SNMP trap listener skipped (MOCK_MODE enabled).")
    else:
        try:
            ks = KillSwitchService()
            trap_bridge = TrapToKillSwitchBridge(ks, DeviceFactory)
            trap_bridge.start()
            print("✅ SNMP trap listener started")
        except Exception as e:
            logger.warning(f"⚠️  SNMP trap listener failed to start: {e}")
            trap_bridge = None

    yield  # Server runs here

    # SHUTDOWN LOGIC
    print("\n🛑 Shutting down UAF Backend...")
    if trap_bridge:
        trap_bridge.stop()
        print("✅ SNMP trap listener stopped")
    scheduler.shutdown()
    print("✅ Scheduler stopped gracefully")

# Initialize FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Unified Automation Framework for CLI and API Network Ecosystems",
    lifespan=lifespan
)

# ============================================================================
# MIDDLEWARE STACK (order matters — last added runs first)
# ============================================================================

# 1. CORS Middleware
# FIX: allow_origins=["*"] combined with allow_credentials=True is actually
# rejected by browsers per the CORS spec. Credentials require an explicit
# origin list. We now use sensible defaults for development that can be
# overridden via the ALLOWED_ORIGINS env var.
ALLOWED_ORIGINS = [
    "http://localhost:3000",      # Reflex frontend (dev)
    "http://localhost:3001",      # Reflex frontend (alt)
    "http://localhost:8000",      # Backend self-reference
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:8000",
]

# Allow custom origins from environment (comma-separated)
import os
extra_origins = os.getenv("ALLOWED_ORIGINS", "")
if extra_origins:
    ALLOWED_ORIGINS.extend([o.strip() for o in extra_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Rate Limiting Middleware
# default_rpm=120 for general endpoints, strict_rpm=20 for security-critical ones
app.add_middleware(
    RateLimitMiddleware,
    default_rpm=120,
    strict_rpm=20,
)

# ============================================================================
# REQUEST AUDIT LOGGING MIDDLEWARE
# ============================================================================

@app.middleware("http")
async def audit_logging_middleware(request: Request, call_next):
    """Log all API requests for audit trail and metrics."""
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time
    path = request.url.path

    # Record API metrics for Prometheus
    metrics_exporter.record_api_request(
        endpoint=path,
        method=request.method,
        status=response.status_code,
        latency=duration,
    )

    return response

# ============================================================================
# ROUTES
# ============================================================================

# Include API routes
app.include_router(router, prefix="/api")
app.include_router(auth_router, prefix="/api")

# Root endpoint (health check)
@app.get("/")
async def root():
    """
    Health check endpoint - confirms the backend is running.
    """
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mock_mode": settings.MOCK_MODE
    }

# Prometheus metrics endpoint
@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint for monitoring.
    """
    return Response(
        content=metrics_exporter.get_metrics(),
        media_type="text/plain"
    )

if __name__ == "__main__":
    # In production, use: uvicorn app.main:app --host 0.0.0.0 --port 8000
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True  # Auto-reload on code changes
    )