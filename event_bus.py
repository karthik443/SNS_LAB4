"""
event_bus.py - Thread-safe shared event bus used by all components.
Sensors publish events; the Correlation Engine subscribes to them.
"""

import queue
import threading
import logging
from schema import Event, Alert

logger = logging.getLogger("ids.event_bus")


class EventBus:
    """
    Simple publish-subscribe bus backed by thread-safe queues.
    Multiple consumers can subscribe; each gets its own queue copy.
    """

    def __init__(self):
        self._lock       = threading.Lock()
        self._event_subs: list[queue.Queue] = []
        self._alert_subs: list[queue.Queue] = []

    # ── Subscription ──────────────────────────
    def subscribe_events(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._event_subs.append(q)
        return q

    def subscribe_alerts(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._alert_subs.append(q)
        return q

    # ── Publishing ────────────────────────────
    def publish_event(self, event: Event):
        with self._lock:
            for q in self._event_subs:
                q.put(event)

    def publish_alert(self, alert: Alert):
        with self._lock:
            for q in self._alert_subs:
                q.put(alert)


# Global singleton
bus = EventBus()