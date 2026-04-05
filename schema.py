"""
schema.py - Unified JSON-based event schema for the IDS system.
All modules must use this schema for interoperability.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
import json


# ──────────────────────────────────────────────
# Event Types
# ──────────────────────────────────────────────
class EventType:
    # Network events
    NET_CONNECTION   = "net.connection"
    NET_PORT_SCAN    = "net.port_scan"
    NET_FLOOD        = "net.flood"
    NET_REPLAY       = "net.replay"

    # Host events
    HOST_LOGIN_FAIL  = "host.login_fail"
    HOST_LOGIN_OK    = "host.login_ok"
    HOST_PROC_EXEC   = "host.process_exec"
    HOST_FILE_ACCESS = "host.file_access"
    HOST_PRIV_ESC    = "host.privilege_escalation"

    # Sensor meta
    SENSOR_FAILURE   = "sensor.failure"
    SENSOR_NOISE     = "sensor.noise"


# ──────────────────────────────────────────────
# Severity Levels (ordered)
# ──────────────────────────────────────────────
class Severity:
    INFO     = "Info"
    LOW      = "Low"
    MEDIUM   = "Medium"
    HIGH     = "High"
    CRITICAL = "Critical"

    ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

    @classmethod
    def max(cls, a: str, b: str) -> str:
        return a if cls.ORDER.get(a, 0) >= cls.ORDER.get(b, 0) else b

    @classmethod
    def cap(cls, severity: str, cap_at: str) -> str:
        if cls.ORDER.get(severity, 0) > cls.ORDER.get(cap_at, 0):
            return cap_at
        return severity


# ──────────────────────────────────────────────
# Unified Event
# ──────────────────────────────────────────────
@dataclass
class Event:
    event_id:    str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   float          = field(default_factory=time.time)
    source:      str            = "unknown"        # "network" | "host" | "system"
    event_type:  str            = EventType.NET_CONNECTION
    src_ip:      Optional[str]  = None
    dst_ip:      Optional[str]  = None
    src_port:    Optional[int]  = None
    dst_port:    Optional[int]  = None
    protocol:    Optional[str]  = None
    username:    Optional[str]  = None
    process:     Optional[str]  = None
    filepath:    Optional[str]  = None
    payload:     Optional[str]  = None             # small text payload / command
    metadata:    Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_json(cls, s: str) -> "Event":
        return cls.from_dict(json.loads(s))


# ──────────────────────────────────────────────
# Alert
# ──────────────────────────────────────────────
@dataclass
class Alert:
    alert_id:       str   = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:      float = field(default_factory=time.time)
    rule_name:      str   = ""
    severity:       str   = Severity.INFO
    score:          float = 0.0
    description:    str   = ""
    sources:        list  = field(default_factory=list)   # list of source names that contributed
    related_events: list  = field(default_factory=list)   # event_ids
    src_ip:         Optional[str] = None
    username:       Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})