"""
correlation_engine.py - Core detection and correlation logic.

Implements:
  - Sliding time-window event buffer per entity
  - 6 rule-based detectors (+ anomaly integration)
  - Multi-source correlation (Critical only when ≥2 sources agree)
  - Scoring model: score(u,t) = Σ w(e)
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Optional
from schema import Event, EventType, Severity, Alert
from event_bus import bus
from anomaly_detector import anomaly_detector

logger = logging.getLogger("ids.correlation")


def _looks_like_ip(s: str) -> bool:
    """Rudimentary check whether a string is an IPv4-like key."""
    if not isinstance(s, str):
        return False
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

WINDOW_SECONDS = 60.0   # sliding window duration
SCORE_WEIGHTS  = {
    EventType.HOST_LOGIN_FAIL:   2.0,
    EventType.HOST_LOGIN_OK:     0.5,
    EventType.HOST_PROC_EXEC:    1.0,
    EventType.HOST_FILE_ACCESS:  1.5,
    EventType.HOST_PRIV_ESC:     5.0,
    EventType.NET_CONNECTION:    0.3,
    EventType.NET_PORT_SCAN:     4.0,
    EventType.NET_FLOOD:         3.0,
    EventType.NET_REPLAY:        3.5,
}


# ──────────────────────────────────────────────
# Per-entity sliding window
# ──────────────────────────────────────────────

class SlidingWindow:
    """Stores recent events per entity within WINDOW_SECONDS."""

    def __init__(self, window: float = WINDOW_SECONDS):
        self.window = window
        self._events: deque[Event] = deque()
        self._lock = threading.Lock()

    def add(self, event: Event):
        with self._lock:
            self._events.append(event)
            self._prune()

    def _prune(self):
        now = time.time()
        while self._events and now - self._events[0].timestamp > self.window:
            self._events.popleft()

    def all(self) -> list[Event]:
        with self._lock:
            self._prune()
            return list(self._events)

    def count_by_type(self, etype: str) -> int:
        return sum(1 for e in self.all() if e.event_type == etype)

    def count_by_source(self, source: str) -> int:
        return sum(1 for e in self.all() if e.source == source)

    def unique_sources(self) -> set[str]:
        return {e.source for e in self.all()}

    def score(self) -> float:
        return sum(SCORE_WEIGHTS.get(e.event_type, 0.5) for e in self.all())

    def event_ids(self) -> list[str]:
        return [e.event_id for e in self.all()]


# ──────────────────────────────────────────────
# Rule definitions (6 non-trivial rules)
# ──────────────────────────────────────────────

class RuleResult:
    def __init__(self, triggered: bool, rule_name: str,
                 severity: str, description: str,
                 score: float, sources: list[str],
                 multi_source: bool = False):
        self.triggered    = triggered
        self.rule_name    = rule_name
        self.severity     = severity
        self.description  = description
        self.score        = score
        self.sources      = sources
        self.multi_source = multi_source


def rule_brute_force(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 1 – Brute-Force Login Detection
    Trigger: ≥5 failed logins within window from same IP/entity.
    Multi-source: if host AND network both show evidence → Critical.
    """
    fails = window.count_by_type(EventType.HOST_LOGIN_FAIL)
    if fails < 5:
        return RuleResult(False, "brute_force", Severity.INFO, "", 0.0, [])

    sources     = list(window.unique_sources())
    multi       = len(sources) >= 2
    score       = window.score()
    description = (f"Brute-force detected: {fails} failed logins for entity '{entity}' "
                   f"in {WINDOW_SECONDS}s window. Score={score:.1f}.")

    if multi and fails >= 10:
        severity = Severity.CRITICAL
    elif multi or fails >= 10:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    # Core security requirement: cap single-source at HIGH
    if not multi:
        severity = Severity.cap(severity, Severity.HIGH)

    return RuleResult(True, "brute_force", severity, description, score, sources, multi)


def rule_port_scan(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 2 – Port Scan Detection
    Trigger: ≥1 NET_PORT_SCAN event from entity.
    """
    scans = window.count_by_type(EventType.NET_PORT_SCAN)
    conns = window.count_by_type(EventType.NET_CONNECTION)
    # Require stronger evidence: either multiple explicit scan summaries, or
    # at least one summary plus a significant number of connection attempts.
    if scans < 1 or (scans == 1 and conns < 10 and window.score() < 10.0):
        return RuleResult(False, "port_scan", Severity.INFO, "", 0.0, [])

    sources = list(window.unique_sources())
    multi   = len(sources) >= 2
    score   = window.score()
    desc    = f"Port scan detected from '{entity}': {scans} scan events. Score={score:.1f}."
    severity = Severity.CRITICAL if multi else Severity.HIGH
    if not multi:
        severity = Severity.cap(severity, Severity.HIGH)
    return RuleResult(True, "port_scan", severity, desc, score, sources, multi)


def rule_privilege_escalation(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 3 – Privilege Escalation after suspicious activity
    Trigger: HOST_PRIV_ESC preceded by ≥2 failed logins or suspicious process.
    Multi-step pattern → can reach Critical even from single source.
    """
    privesc = window.count_by_type(EventType.HOST_PRIV_ESC)
    if privesc < 1:
        return RuleResult(False, "privilege_escalation", Severity.INFO, "", 0.0, [])

    fails    = window.count_by_type(EventType.HOST_LOGIN_FAIL)
    procs    = window.count_by_type(EventType.HOST_PROC_EXEC)
    sources  = list(window.unique_sources())
    multi    = len(sources) >= 2
    score    = window.score()
    desc     = (f"Privilege escalation by '{entity}': {privesc} priv-esc events, "
                f"{fails} prior failures, {procs} process execs. Score={score:.1f}.")

    # Deterministic multi-step pattern → Critical even from single source
    if fails >= 2 or procs >= 3:
        severity = Severity.CRITICAL
    elif multi:
        severity = Severity.CRITICAL
    else:
        severity = Severity.HIGH
    return RuleResult(True, "privilege_escalation", severity, desc, score, sources, multi)


def rule_sensitive_file_access(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 4 – Sensitive File Access
    Trigger: file access events on sensitive paths.
    """
    SENSITIVE = {"/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys",
                 "/etc/sudoers", "/proc/keys"}
    events  = window.all()
    matches = [e for e in events
               if e.event_type == EventType.HOST_FILE_ACCESS
               and e.filepath in SENSITIVE]
    if not matches:
        return RuleResult(False, "sensitive_file_access", Severity.INFO, "", 0.0, [])

    sources  = list(window.unique_sources())
    multi    = len(sources) >= 2
    score    = window.score()
    files    = list({e.filepath for e in matches})
    desc     = f"Sensitive file access by '{entity}': {files}. Score={score:.1f}."
    severity = Severity.HIGH if multi else Severity.MEDIUM
    if not multi:
        severity = Severity.cap(severity, Severity.HIGH)
    return RuleResult(True, "sensitive_file_access", severity, desc, score, sources, multi)


def rule_suspicious_process(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 5 – Suspicious Process Execution
    Trigger: execution of known attack tools (nc, nmap, hydra, etc.)
    """
    SUSPICIOUS = {"nc", "ncat", "netcat", "nmap", "masscan", "hydra",
                  "tcpdump", "wireshark", "metasploit", "msfconsole",
                  "sqlmap", "nikto", "john", "hashcat"}
    events = window.all()
    hits   = [e for e in events
              if e.event_type == EventType.HOST_PROC_EXEC
              and e.process in SUSPICIOUS]
    if not hits:
        return RuleResult(False, "suspicious_process", Severity.INFO, "", 0.0, [])

    sources  = list(window.unique_sources())
    multi    = len(sources) >= 2
    score    = window.score()
    procs    = [e.process for e in hits]
    desc     = f"Suspicious process(es) executed by '{entity}': {procs}. Score={score:.1f}."
    severity = Severity.HIGH if multi else Severity.MEDIUM
    if not multi:
        severity = Severity.cap(severity, Severity.HIGH)
    return RuleResult(True, "suspicious_process", severity, desc, score, sources, multi)


def rule_replay_attack(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 6 – Replay Attack Detection
    Trigger: NET_REPLAY events seen from entity.
    """
    replays = window.count_by_type(EventType.NET_REPLAY)
    if replays < 1:
        return RuleResult(False, "replay_attack", Severity.INFO, "", 0.0, [])

    sources  = list(window.unique_sources())
    multi    = len(sources) >= 2
    score    = window.score()
    desc     = f"Replay attack from '{entity}': {replays} replay events. Score={score:.1f}."
    severity = Severity.HIGH if multi else Severity.MEDIUM
    if not multi:
        severity = Severity.cap(severity, Severity.HIGH)
    return RuleResult(True, "replay_attack", severity, desc, score, sources, multi)


def rule_coordinated_attack(window: SlidingWindow, entity: str) -> RuleResult:
    """
    Rule 7 (bonus) – Coordinated Multi-Vector Attack
    Trigger: brute force + port scan seen together in window from same IP.
    Both are network-level but combined they indicate coordinated attack.
    """
    fails  = window.count_by_type(EventType.HOST_LOGIN_FAIL)
    scans  = window.count_by_type(EventType.NET_PORT_SCAN)
    replay = window.count_by_type(EventType.NET_REPLAY)
    logger.debug(f"coordinated_check: entity={entity} fails={fails} scans={scans} replay={replay}")
    if not (fails >= 3 and scans >= 1):
        return RuleResult(False, "coordinated_attack", Severity.INFO, "", 0.0, [])

    sources  = list(window.unique_sources())
    multi    = len(sources) >= 2
    score    = window.score()
    desc     = (f"Coordinated attack from '{entity}': {fails} login fails + "
                f"{scans} port scans + {replay} replays. Score={score:.1f}.")
    # multi-step deterministic pattern → Critical
    severity = Severity.CRITICAL
    return RuleResult(True, "coordinated_attack", severity, desc, score, sources, multi)


ALL_RULES = [
    rule_brute_force,
    rule_port_scan,
    rule_privilege_escalation,
    rule_sensitive_file_access,
    rule_suspicious_process,
    rule_replay_attack,
    rule_coordinated_attack,
]


# ──────────────────────────────────────────────
# Correlation Engine
# ──────────────────────────────────────────────

class CorrelationEngine(threading.Thread):
    """
    Consumes events from the bus, maintains per-entity sliding windows,
    runs all rules every time a new event arrives, and publishes Alerts.
    """

    def __init__(self, active: threading.Event = None):
        super().__init__(daemon=True, name="CorrelationEngine")
        self.active     = active or threading.Event()
        self.active.set()
        self._eq        = bus.subscribe_events()
        self._windows:  dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._lock      = threading.Lock()

        # Register anomaly callback
        anomaly_detector.register_callback(self._on_anomaly)

    def _entity_key(self, event: Event) -> str:
        """Determine primary entity identifier for grouping."""
        # Prefer src_ip when present so network+host events can share window
        if event.src_ip:
            return event.src_ip
        # If host event carries a username and *also* includes src_ip in metadata,
        # prefer that src_ip so the host event joins the IP-based window.
        if event.username and event.metadata.get("src_ip"):
            return event.metadata.get("src_ip")
        if event.username:
            return event.username
        return "global"

    def _on_anomaly(self, signal: dict):
        """Called by anomaly detector when a statistical anomaly is found."""
        entity  = signal["entity"]
        feature = signal["feature"]
        z       = signal["z_score"]
        desc    = (f"Statistical anomaly: entity='{entity}' feature='{feature}' "
                   f"z={z:.2f} (threshold={anomaly_detector.z_threshold}).")
        # Treat anomaly as a Medium signal — only becomes High/Critical via correlation
        alert = Alert(
            rule_name    = "anomaly_detection",
            severity     = Severity.MEDIUM,
            score        = abs(z) * 2,
            description  = desc,
            sources      = ["anomaly"],
        )
        bus.publish_alert(alert)

    def run(self):
        logger.info("CorrelationEngine started")
        while self.active.is_set():
            try:
                event = self._eq.get(timeout=1.0)
            except Exception:
                continue

            # Feed anomaly detector
            anomaly_detector.observe_event(event)

            # Update sliding window
            key = self._entity_key(event)
            with self._lock:
                self._windows[key].add(event)
                window = self._windows[key]

            # Cross-post host-only events into IP window when possible
            # Some host events (priv-esc, proc-exec) may not have src_ip but are
            # part of a chain starting from an IP. If event.metadata contains
            # 'related_ip', mirror the event into that IP window as well so
            # coordinated rules can see both kinds of evidence together. We'll
            # evaluate rules for both the primary key and any related_ip so the
            # fused detectors can observe mixed evidence.
            related_ip = event.metadata.get("related_ip") if hasattr(event, 'metadata') else None
            if related_ip:
                with self._lock:
                    self._windows[related_ip].add(event)

            # Evaluate rules on the primary window and any mirrored related_ip
            # If we mirrored this event into an IP window, prefer publishing
            # alerts for the IP window only (to avoid duplicate username-keyed
            # alerts). We'll still evaluate both windows but only emit alerts
            # for the IP-keyed window when present.
            windows_to_check = [key]
            if related_ip and related_ip != key:
                windows_to_check.append(related_ip)

            published = set()  # avoid duplicate (rule,entity) alerts per event
            for wkey in windows_to_check:
                with self._lock:
                    w = self._windows[wkey]

                for rule_fn in ALL_RULES:
                    result = rule_fn(w, wkey)
                    if not result.triggered:
                        continue
                    ident = (result.rule_name, wkey)
                    if ident in published:
                        continue
                    published.add(ident)
                    logger.debug(f"rule_triggered: {result.rule_name} entity={wkey} severity={result.severity}")
                    # Ensure the alert uses the evaluated window entity as src_ip
                    # so downstream components and evaluation see a consistent key.
                    # If we have both a username-keyed window and an IP-keyed
                    # window for the same underlying attack, prefer emitting
                    # only the IP-keyed alert (when wkey looks like an IP).
                    emit_ip_only = any(_looks_like_ip(k) for k in windows_to_check)
                    if emit_ip_only and not _looks_like_ip(wkey):
                        # Skip emitting username-keyed alert to avoid duplicates.
                        continue
                    alert = Alert(
                        rule_name     = result.rule_name,
                        severity      = result.severity,
                        score         = result.score,
                        description   = result.description,
                        sources       = result.sources,
                        related_events = w.event_ids(),
                        src_ip        = wkey if _looks_like_ip(wkey) else event.src_ip,
                        username      = event.username,
                    )
                    bus.publish_alert(alert)


    def stop(self):
        self.active.clear()