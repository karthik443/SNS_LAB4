"""
host_sensor.py - Host Sensor component.

Generates and monitors host-level events (login attempts, process execution,
file access, privilege escalation) and publishes them to the event bus.
Reads from a synthetic log queue or real /var/log/auth.log if available.
"""

import threading
import time
import logging
import random
import os
import re
from schema import Event, EventType
from event_bus import bus

logger = logging.getLogger("ids.host_sensor")

# ──────────────────────────────────────────────
# Synthetic Host Log Generator
# ──────────────────────────────────────────────

BENIGN_USERS    = ["alice", "bob", "charlie", "dave"]
BENIGN_PROCS    = ["bash", "python3", "vim", "ls", "cat", "ssh", "curl"]
SENSITIVE_FILES = ["/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys"]
SUSPICIOUS_PROCS = ["nc", "nmap", "tcpdump", "wireshark", "metasploit", "hydra"]


class SyntheticHostSensor(threading.Thread):
    """
    Generates synthetic host events representing normal user activity.
    Used to establish a baseline and emit benign events.
    """

    def __init__(self, rate_hz: float = 1.0, active: threading.Event = None):
        super().__init__(daemon=True, name="SyntheticHostSensor")
        self.interval = 1.0 / max(rate_hz, 0.01)
        self.active   = active or threading.Event()
        self.active.set()

    def run(self):
        logger.info("SyntheticHostSensor started")
        while self.active.is_set():
            username = random.choice(BENIGN_USERS)
            process  = random.choice(BENIGN_PROCS)
            src_ip   = f"192.168.1.{random.randint(2, 20)}"

            choice = random.random()
            if choice < 0.60:
                # Normal login
                evt = Event(
                    source="host",
                    event_type=EventType.HOST_LOGIN_OK,
                    src_ip=src_ip,
                    username=username,
                    metadata={"attempt": 1},
                )
            elif choice < 0.80:
                # Process execution
                evt = Event(
                    source="host",
                    event_type=EventType.HOST_PROC_EXEC,
                    username=username,
                    process=process,
                    metadata={"pid": random.randint(1000, 9999)},
                )
            else:
                # File access
                evt = Event(
                    source="host",
                    event_type=EventType.HOST_FILE_ACCESS,
                    username=username,
                    filepath=f"/home/{username}/documents/file{random.randint(1,10)}.txt",
                    metadata={"mode": "read"},
                )
            bus.publish_event(evt)
            time.sleep(self.interval)

    def stop(self):
        self.active.clear()


# ──────────────────────────────────────────────
# Auth Log Tail Reader (real system logs)
# ──────────────────────────────────────────────

_AUTH_LOG = "/var/log/auth.log"

_FAIL_RE  = re.compile(r"Failed password for (\S+) from ([\d.]+)")
_OK_RE    = re.compile(r"Accepted password for (\S+) from ([\d.]+)")
_SU_RE    = re.compile(r"session opened for user root by (\S+)")


class AuthLogSensor(threading.Thread):
    """
    Tails /var/log/auth.log in real time and converts sshd entries
    into host Events. Falls back gracefully if the file is absent.
    """

    def __init__(self, active: threading.Event = None):
        super().__init__(daemon=True, name="AuthLogSensor")
        self.active = active or threading.Event()
        self.active.set()

    def run(self):
        if not os.path.exists(_AUTH_LOG):
            logger.info(f"AuthLogSensor: {_AUTH_LOG} not found, skipping real log tail.")
            return
        logger.info(f"AuthLogSensor: tailing {_AUTH_LOG}")
        with open(_AUTH_LOG, "r") as f:
            f.seek(0, 2)  # seek to end
            while self.active.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                self._parse(line.strip())

    def _parse(self, line: str):
        m = _FAIL_RE.search(line)
        if m:
            bus.publish_event(Event(
                source="host", event_type=EventType.HOST_LOGIN_FAIL,
                username=m.group(1), src_ip=m.group(2),
            ))
            return
        m = _OK_RE.search(line)
        if m:
            bus.publish_event(Event(
                source="host", event_type=EventType.HOST_LOGIN_OK,
                username=m.group(1), src_ip=m.group(2),
            ))
            return
        m = _SU_RE.search(line)
        if m:
            bus.publish_event(Event(
                source="host", event_type=EventType.HOST_PRIV_ESC,
                username=m.group(1),
                metadata={"method": "su/sudo"},
            ))

    def stop(self):
        self.active.clear()


# ──────────────────────────────────────────────
# Host Log Injector (used by Attack Simulator)
# ──────────────────────────────────────────────

def inject_login_failure(username: str, src_ip: str):
    bus.publish_event(Event(
        source="host", event_type=EventType.HOST_LOGIN_FAIL,
        username=username, src_ip=src_ip,
    ))

def inject_login_success(username: str, src_ip: str):
    bus.publish_event(Event(
        source="host", event_type=EventType.HOST_LOGIN_OK,
        username=username, src_ip=src_ip,
    ))

def inject_suspicious_process(username: str, process: str):
    bus.publish_event(Event(
        source="host", event_type=EventType.HOST_PROC_EXEC,
        username=username, process=process,
        metadata={"suspicious": True},
    ))

def inject_sensitive_file_access(username: str, filepath: str):
    bus.publish_event(Event(
        source="host", event_type=EventType.HOST_FILE_ACCESS,
        username=username, filepath=filepath,
        metadata={"mode": "read", "sensitive": True},
    ))

def inject_privilege_escalation(username: str):
    bus.publish_event(Event(
        source="host", event_type=EventType.HOST_PRIV_ESC,
        username=username, metadata={"method": "sudo su"},
    ))