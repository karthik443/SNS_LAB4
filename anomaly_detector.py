"""
anomaly_detector.py - Lightweight statistical anomaly detection.

Tracks rolling mean/std for various features per-entity (IP or username)
and raises an anomaly signal when observed value deviates significantly (|z| > threshold).
"""

import math
import threading
import time
import logging
from collections import defaultdict, deque
from schema import Event, EventType

logger = logging.getLogger("ids.anomaly")

EPSILON = 1e-6  # prevent division by zero


class RollingStats:
    """Welford's online algorithm for mean and variance."""

    def __init__(self, window: int = 100):
        self._values: deque = deque(maxlen=window)
        self._lock   = threading.Lock()

    def add(self, value: float):
        with self._lock:
            self._values.append(value)

    def mean(self) -> float:
        with self._lock:
            if not self._values:
                return 0.0
            return sum(self._values) / len(self._values)

    def std(self) -> float:
        with self._lock:
            n = len(self._values)
            if n < 2:
                return 0.0
            mu = sum(self._values) / n
            variance = sum((x - mu) ** 2 for x in self._values) / n
            return math.sqrt(variance)

    def z_score(self, value: float) -> float:
        return (value - self.mean()) / (self.std() + EPSILON)

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)


class AnomalyDetector:
    """
    Maintains per-IP and per-user feature statistics.
    Detects anomalies using z-score thresholding.

    Features tracked:
      - login_fail_rate per IP (events per minute bucket)
      - port_count per IP (unique ports per 60s window)
      - request_rate per IP (connections per 10s bucket)
      - proc_exec_rate per user
    """

    def __init__(self, z_threshold: float = 3.0, bucket_seconds: float = 60.0):
        self.z_threshold     = z_threshold
        self.bucket_seconds  = bucket_seconds

        # Rolling stats keyed by (entity_type, entity_id, feature)
        self._stats: dict[tuple, RollingStats] = defaultdict(RollingStats)

        # Counters within current time bucket
        self._lock       = threading.Lock()
        self._buckets:   dict[tuple, float] = defaultdict(float)
        self._bucket_ts: dict[tuple, float] = defaultdict(float)

        # Anomaly callback
        self._callbacks = []

    def register_callback(self, fn):
        self._callbacks.append(fn)

    def _flush_bucket(self, key: tuple, now: float):
        """Commit current bucket value to rolling stats and reset."""
        with self._lock:
            value = self._buckets.get(key, 0.0)
            self._stats[key].add(value)
            self._buckets[key] = 0.0
            self._bucket_ts[key] = now

    def _increment(self, key: tuple, amount: float = 1.0) -> float:
        """Increment counter, flush bucket if window expired. Return z-score."""
        now = time.time()
        with self._lock:
            if now - self._bucket_ts.get(key, 0) >= self.bucket_seconds:
                # Flush old bucket
                old_val = self._buckets.get(key, 0.0)
                self._stats[key].add(old_val)
                self._buckets[key] = amount
                self._bucket_ts[key] = now
            else:
                self._buckets[key] = self._buckets.get(key, 0.0) + amount

            current = self._buckets[key]

        # z-score using historical stats (excludes current open bucket)
        z = self._stats[key].z_score(current)
        return z

    def observe_event(self, event: Event) -> list[dict]:
        """
        Process a single event. Returns list of anomaly signals (may be empty).
        Each signal: {"entity": ..., "feature": ..., "z_score": ..., "value": ...}
        """
        signals = []

        if event.event_type == EventType.HOST_LOGIN_FAIL and event.src_ip:
            key = ("ip", event.src_ip, "login_fail_rate")
            z   = self._increment(key)
            if abs(z) > self.z_threshold and len(self._stats[key]) >= 3:
                signals.append({"entity": event.src_ip, "feature": "login_fail_rate",
                                 "z_score": round(z, 2),
                                 "value": self._buckets[key]})

        if event.event_type == EventType.NET_CONNECTION and event.src_ip:
            key = ("ip", event.src_ip, "request_rate")
            z   = self._increment(key)
            if abs(z) > self.z_threshold and len(self._stats[key]) >= 3:
                signals.append({"entity": event.src_ip, "feature": "request_rate",
                                 "z_score": round(z, 2),
                                 "value": self._buckets[key]})

        if event.event_type == EventType.NET_PORT_SCAN and event.src_ip:
            ports = event.metadata.get("ports_accessed", [])
            key   = ("ip", event.src_ip, "port_count")
            z     = self._increment(key, len(ports))
            if abs(z) > self.z_threshold and len(self._stats[key]) >= 2:
                signals.append({"entity": event.src_ip, "feature": "port_count",
                                 "z_score": round(z, 2),
                                 "value": len(ports)})

        if event.event_type == EventType.HOST_PROC_EXEC and event.username:
            key = ("user", event.username, "proc_exec_rate")
            z   = self._increment(key)
            if abs(z) > self.z_threshold and len(self._stats[key]) >= 3:
                signals.append({"entity": event.username, "feature": "proc_exec_rate",
                                 "z_score": round(z, 2),
                                 "value": self._buckets[key]})

        for sig in signals:
            sig["source_event_id"] = event.event_id
            for cb in self._callbacks:
                cb(sig)

        return signals


# Module-level singleton
anomaly_detector = AnomalyDetector(z_threshold=3.0, bucket_seconds=30.0)