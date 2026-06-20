"""
Real-Time Event Bus
====================
In-process async pub/sub that backs the WebSocket push channel (Report 4.7:
"real-time WebSocket updates for security alerts and device status").

Subsystems publish events — a rogue device detected, a port shut/restored, a
provisioning run finishing — and every connected WebSocket subscriber receives
them the instant they happen, instead of waiting for the next poll cycle.

Publishers can run either inside the FastAPI event loop (request handlers) or
in worker threads (APScheduler jobs, the SNMP trap bridge, the kill-switch).
publish() is therefore thread-safe: when called off the loop it hands the event
to the bus's bound loop via call_soon_threadsafe.
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, Optional, Set


class EventBus:
    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Record the running loop so thread publishers can reach subscribers."""
        self._loop = loop

    async def subscribe(self) -> asyncio.Queue:
        """Register a new subscriber queue (one per WebSocket connection)."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _fan_out(self, event: Dict[str, Any]) -> None:
        """Deliver one event to every subscriber (runs on the bus loop)."""
        dead = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Slow consumer: drop its oldest event and push the newest.
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
        for q in dead:
            self._subscribers.discard(q)

    def publish(self, event_type: str, **data: Any) -> None:
        """Publish an event from anywhere (event loop or worker thread)."""
        event = {
            "type": event_type,
            "ts": datetime.now().isoformat(timespec="seconds"),
            **data,
        }
        loop = self._loop
        if loop is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(self._fan_out, event)
                return
            except RuntimeError:
                pass
        # Fallback for environments without a bound running loop.
        self._fan_out(event)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Module-level singleton shared across the app.
event_bus = EventBus()
