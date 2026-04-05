"""
network_sensor.py - Network Sensor component.

Listens on a raw socket (or generates synthetic flows) and publishes
normalized Event objects to the event bus.
"""

import socket
import threading
import time
import logging
import random
from schema import Event, EventType
from event_bus import bus

logger = logging.getLogger("ids.network_sensor")

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _make_net_event(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                    protocol: str = "TCP", event_type: str = EventType.NET_CONNECTION,
                    metadata: dict = None) -> Event:
    return Event(
        source="network",
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        metadata=metadata or {},
    )


# ──────────────────────────────────────────────
# Passive TCP listener (real traffic)
# ──────────────────────────────────────────────

class TCPListener(threading.Thread):
    """
    Binds a raw server socket and observes incoming connections.
    Each accepted connection becomes a NET_CONNECTION event.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9999,
                 active: threading.Event = None):
        super().__init__(daemon=True, name="TCPListener")
        self.host   = host
        self.port   = port
        self.active = active or threading.Event()
        self.active.set()

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(50)
            srv.settimeout(1.0)
            logger.info(f"TCPListener bound on {self.host}:{self.port}")
            while self.active.is_set():
                try:
                    conn, addr = srv.accept()
                    evt = _make_net_event(
                        src_ip=addr[0], dst_ip=self.host,
                        src_port=addr[1], dst_port=self.port,
                        protocol="TCP", event_type=EventType.NET_CONNECTION,
                    )
                    bus.publish_event(evt)
                    conn.close()
                except socket.timeout:
                    pass
        except Exception as e:
            logger.warning(f"TCPListener error: {e}")

    def stop(self):
        self.active.clear()


# ──────────────────────────────────────────────
# Synthetic flow generator (for testing)
# ──────────────────────────────────────────────

class SyntheticNetworkSensor(threading.Thread):
    """
    Generates synthetic benign network flows at a configurable rate.
    Used as baseline traffic to calibrate anomaly detectors.
    """
    BENIGN_PORTS = [80, 443, 22, 53, 8080, 3306]

    def __init__(self, rate_hz: float = 2.0, active: threading.Event = None):
        super().__init__(daemon=True, name="SyntheticNetSensor")
        self.interval = 1.0 / max(rate_hz, 0.01)
        self.active   = active or threading.Event()
        self.active.set()

    def run(self):
        logger.info("SyntheticNetworkSensor started")
        while self.active.is_set():
            src_ip   = f"192.168.1.{random.randint(2, 20)}"
            dst_port = random.choice(self.BENIGN_PORTS)
            evt = _make_net_event(
                src_ip=src_ip, dst_ip="127.0.0.1",
                src_port=random.randint(1024, 65535),
                dst_port=dst_port,
                protocol="TCP",
                event_type=EventType.NET_CONNECTION,
                metadata={"benign": True, "pkt_count": random.randint(3, 50)},
            )
            bus.publish_event(evt)
            time.sleep(self.interval)

    def stop(self):
        self.active.clear()


# ──────────────────────────────────────────────
# Flow tracker (aggregates raw events → flows)
# ──────────────────────────────────────────────

class FlowTracker:
    """
    Maintains short-lived connection records per (src_ip, dst_port).
    Detects port-scan patterns: one src hitting many ports rapidly.
    """

    def __init__(self, window: float = 10.0, threshold: int = 15):
        self.window    = window
        self.threshold = threshold
        self._lock     = threading.Lock()
        self._flows: dict[str, list[tuple[float, int]]] = {}   # src_ip → [(ts, dst_port)]

    def record(self, event: Event):
        if event.src_ip is None or event.dst_port is None:
            return
        key = event.src_ip
        now = event.timestamp
        with self._lock:
            if key not in self._flows:
                self._flows[key] = []
            self._flows[key].append((now, event.dst_port))
            # prune old
            self._flows[key] = [(t, p) for t, p in self._flows[key] if now - t <= self.window]
            # detect scan
            ports = {p for _, p in self._flows[key]}
            if len(ports) >= self.threshold:
                scan_evt = _make_net_event(
                    src_ip=event.src_ip, dst_ip=event.dst_ip or "127.0.0.1",
                    src_port=0, dst_port=0,
                    event_type=EventType.NET_PORT_SCAN,
                    metadata={"ports_accessed": sorted(ports), "window_s": self.window},
                )
                bus.publish_event(scan_evt)
                # clear to avoid repeated firing
                self._flows[key] = []


# Module-level singletons
flow_tracker = FlowTracker()