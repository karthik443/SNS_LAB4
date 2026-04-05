"""
attack_simulator.py - Generates both benign and malicious activity for IDS evaluation.

Implements all required attack scenarios:
  1. Brute-force login attempts
  2. Port scanning (fast + slow)
  3. Noise injection
  4. Replay attacks
  5. Sensor failure simulation

Each scenario is reproducible and can be run independently.
"""

import socket
import threading
import time
import random
import logging
from schema import Event, EventType
from event_bus import bus
import host_sensor as hs

logger = logging.getLogger("ids.simulator")

ATTACKER_IP  = "10.0.0.99"   # simulated attacker
VICTIM_IP    = "127.0.0.1"


# ──────────────────────────────────────────────
# Helper: publish net event directly
# ──────────────────────────────────────────────

def _net(src_ip, dst_ip, src_port, dst_port, etype, meta=None):
    bus.publish_event(Event(
        source="network", event_type=etype,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol="TCP", metadata=meta or {},
    ))


# ──────────────────────────────────────────────
# Scenario 1: Brute-Force Login
# ──────────────────────────────────────────────

def scenario_brute_force(username: str = "root",
                          attacker_ip: str = ATTACKER_IP,
                          n_attempts: int = 20,
                          delay: float = 0.1):
    """
    Simulates a brute-force SSH login attack:
      - Emits repeated HOST_LOGIN_FAIL events from attacker_ip
      - After N attempts, simulates a successful login (attacker got in)
      - Also emits network connection events to trigger multi-source correlation
    """
    logger.info(f"[Scenario] Brute-force: {n_attempts} attempts on user '{username}' "
                f"from {attacker_ip}")
    for i in range(n_attempts):
        hs.inject_login_failure(username=username, src_ip=attacker_ip)
        _net(attacker_ip, VICTIM_IP, random.randint(1024, 65535), 22,
             EventType.NET_CONNECTION)
        time.sleep(delay)

    # Attacker succeeds
    logger.info(f"[Scenario] Brute-force: attacker logged in as '{username}'!")
    hs.inject_login_success(username=username, src_ip=attacker_ip)
    _net(attacker_ip, VICTIM_IP, random.randint(1024, 65535), 22,
         EventType.NET_CONNECTION, {"result": "success"})


# ──────────────────────────────────────────────
# Scenario 2: Port Scan (fast and slow)
# ──────────────────────────────────────────────

def scenario_port_scan_fast(attacker_ip: str = ATTACKER_IP,
                             target_ip:   str = VICTIM_IP,
                             ports: list  = None,
                             delay: float = 0.02):
    """Fast port scan hitting many ports rapidly."""
    ports = ports or list(range(20, 1024, 5))
    logger.info(f"[Scenario] Fast port scan: {len(ports)} ports from {attacker_ip}")
    for p in ports:
        _net(attacker_ip, target_ip, random.randint(1024, 65535), p,
             EventType.NET_CONNECTION)
        time.sleep(delay)
    # Explicit scan event summary
    bus.publish_event(Event(
        source="network", event_type=EventType.NET_PORT_SCAN,
        src_ip=attacker_ip, dst_ip=target_ip,
        src_port=0, dst_port=0,
        metadata={"ports_accessed": ports, "scan_type": "fast"},
    ))


def scenario_port_scan_slow(attacker_ip: str = ATTACKER_IP,
                             target_ip:   str = VICTIM_IP,
                             ports: list  = None,
                             delay: float = 0.5):
    """Slow/stealthy port scan — mimics evasion attempt."""
    ports = ports or [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]
    logger.info(f"[Scenario] Slow port scan: {len(ports)} ports from {attacker_ip}")
    for p in ports:
        _net(attacker_ip, target_ip, random.randint(1024, 65535), p,
             EventType.NET_CONNECTION)
        time.sleep(delay)
    bus.publish_event(Event(
        source="network", event_type=EventType.NET_PORT_SCAN,
        src_ip=attacker_ip, dst_ip=target_ip,
        src_port=0, dst_port=0,
        metadata={"ports_accessed": ports, "scan_type": "slow_stealth"},
    ))


# ──────────────────────────────────────────────
# Scenario 3: Noise Injection
# ──────────────────────────────────────────────

def scenario_noise_injection(duration: float = 10.0,
                              n_ips: int = 50):
    """
    Injects random noise from many IPs to confuse the IDS.
    Verifies that the IDS does NOT generate false Critical alerts.
    """
    logger.info(f"[Scenario] Noise injection: {n_ips} random IPs for {duration}s")
    end = time.time() + duration
    while time.time() < end:
        ip   = f"172.16.{random.randint(0,255)}.{random.randint(1,254)}"
        port = random.randint(1, 65535)
        _net(ip, VICTIM_IP, random.randint(1024, 65535), port,
             EventType.NET_CONNECTION)
        bus.publish_event(Event(
            source="network", event_type=EventType.SENSOR_NOISE,
            src_ip=ip, metadata={"noise": True},
        ))
        time.sleep(random.uniform(0.01, 0.1))


# ──────────────────────────────────────────────
# Scenario 4: Replay Attack
# ──────────────────────────────────────────────

_REPLAY_STORE: list[Event] = []

def scenario_record_benign(n: int = 10):
    """Record benign traffic to replay later."""
    _REPLAY_STORE.clear()
    for _ in range(n):
        ip   = f"192.168.1.{random.randint(2, 20)}"
        port = random.choice([80, 443, 22])
        e = Event(
            source="network", event_type=EventType.NET_CONNECTION,
            src_ip=ip, dst_ip=VICTIM_IP,
            src_port=random.randint(1024, 65535), dst_port=port,
            protocol="TCP",
        )
        _REPLAY_STORE.append(e)
        bus.publish_event(e)
        time.sleep(0.05)
    logger.info(f"[Scenario] Recorded {len(_REPLAY_STORE)} benign events for replay.")


def scenario_replay_attack(attacker_ip: str = ATTACKER_IP,
                            modification: str = "slight"):
    """
    Replays previously observed benign traffic with slight modifications.
    Uses NET_REPLAY event type to signal replay to the IDS.
    """
    if not _REPLAY_STORE:
        scenario_record_benign()

    logger.info(f"[Scenario] Replay attack: replaying {len(_REPLAY_STORE)} events "
                f"with modification='{modification}'")
    for original in _REPLAY_STORE:
        replay = Event(
            source="network", event_type=EventType.NET_REPLAY,
            src_ip=attacker_ip, dst_ip=original.dst_ip,
            src_port=original.src_port + random.randint(1, 10),
            dst_port=original.dst_port,
            protocol=original.protocol,
            metadata={"original_src": original.src_ip,
                      "modification": modification,
                      "replay": True},
        )
        bus.publish_event(replay)
        time.sleep(0.05)


# ──────────────────────────────────────────────
# Scenario 5: Sensor Failure Simulation
# ──────────────────────────────────────────────

class SensorFailureSimulator:
    """
    Temporarily disables a sensor to test IDS robustness
    when one data source is unavailable.
    Verifies that Critical alerts are NOT raised from single source.
    """

    def __init__(self, sensor_name: str, sensor_stop_fn, sensor_start_fn):
        self.sensor_name   = sensor_name
        self._stop_fn      = sensor_stop_fn
        self._start_fn     = sensor_start_fn
        self._failure_flag = threading.Event()

    def simulate_failure(self, duration: float = 15.0):
        logger.info(f"[Scenario] Sensor failure: disabling '{self.sensor_name}' "
                    f"for {duration}s")
        bus.publish_event(Event(
            source="system", event_type=EventType.SENSOR_FAILURE,
            metadata={"sensor": self.sensor_name, "reason": "simulated_failure"},
        ))
        self._stop_fn()
        self._failure_flag.set()
        time.sleep(duration)
        self._failure_flag.clear()
        self._start_fn()
        logger.info(f"[Scenario] Sensor '{self.sensor_name}' restored.")


# ──────────────────────────────────────────────
# Scenario 6: Coordinated Multi-Vector Attack
# ──────────────────────────────────────────────

def scenario_coordinated_attack(attacker_ip: str = ATTACKER_IP,
                                 username: str = "admin"):
    """
    Combines brute force + port scan + privilege escalation.
    Designed to trigger coordinated_attack and privilege_escalation rules.
    """
    logger.info(f"[Scenario] Coordinated attack from {attacker_ip} targeting {username}")

    # Step 1: Port scan reconnaissance
    scenario_port_scan_fast(attacker_ip=attacker_ip, ports=list(range(20, 200, 3)),
                             delay=0.01)
    time.sleep(0.5)

    # Step 2: Brute force
    for _ in range(15):
        hs.inject_login_failure(username=username, src_ip=attacker_ip)
        _net(attacker_ip, VICTIM_IP, random.randint(1024, 65535), 22,
             EventType.NET_CONNECTION)
        time.sleep(0.05)

    # Step 3: Attacker gets in
    hs.inject_login_success(username=username, src_ip=attacker_ip)

    # Step 4: Suspicious process + sensitive file
    hs.inject_suspicious_process(username=username, process="nc")
    hs.inject_sensitive_file_access(username=username, filepath="/etc/shadow")

    # Step 5: Privilege escalation
    hs.inject_privilege_escalation(username=username)