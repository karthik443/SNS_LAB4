"""
alert_manager.py - Alert Manager component.

Responsibilities:
  - Receive alerts from the bus
  - Deduplicate alerts (same rule + entity within cooldown window)
  - Enforce the core security requirement:
      Critical ONLY if ≥2 independent sources agree (or multi-step pattern)
  - Assign final severity and log/display alerts
  - Maintain metrics counters
"""

import time
import threading
import logging
from collections import defaultdict
from schema import Alert, Severity
from event_bus import bus

logger = logging.getLogger("ids.alert_manager")


# Pretty severity colours (ANSI)
_COLORS = {
    Severity.INFO:     "\033[37m",      # white
    Severity.LOW:      "\033[36m",      # cyan
    Severity.MEDIUM:   "\033[33m",      # yellow
    Severity.HIGH:     "\033[91m",      # light red
    Severity.CRITICAL: "\033[1;31m",    # bold red
}
_RESET = "\033[0m"


class AlertManager(threading.Thread):
    """
    Consumes alerts from the bus, applies deduplication + cooldown,
    enforces multi-source requirement, and records metrics.
    """

    COOLDOWN: dict[str, float] = {
        # rule_name → cooldown seconds (don't re-alert for same rule+entity)
        "brute_force":           30.0,
        "port_scan":             20.0,
        "privilege_escalation":  60.0,
        "sensitive_file_access": 30.0,
        "suspicious_process":    20.0,
        "replay_attack":         25.0,
        "coordinated_attack":    45.0,
        "anomaly_detection":     30.0,
        "default":               15.0,
    }

    def __init__(self, active: threading.Event = None, log_file: str = "alerts.log"):
        super().__init__(daemon=True, name="AlertManager")
        self.active   = active or threading.Event()
        self.active.set()
        self._aq      = bus.subscribe_alerts()

        # last alert timestamp per (rule_name, entity)
        self._last_alert: dict[tuple, float] = {}
        self._lock = threading.Lock()

        # Metrics
        self.counters: dict[str, int] = defaultdict(int)
        self.alert_log: list[Alert]   = []

        # File logging
        self._fh = logging.FileHandler(log_file)
        self._fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
        self._fh.setFormatter(fmt)
        logger.addHandler(self._fh)

    def run(self):
        logger.info("AlertManager started")
        while self.active.is_set():
            try:
                alert: Alert = self._aq.get(timeout=1.0)
            except Exception:
                continue
            self._process(alert)

    def _process(self, alert: Alert):
        entity = alert.src_ip or alert.username or "unknown"
        key    = (alert.rule_name, entity)
        now    = time.time()

        # ── Core Security Requirement ─────────────────
        # Critical is only allowed when:
        # 1. ≥2 independent sources are in alert.sources, OR
        # 2. rule is a known multi-step deterministic pattern
        MULTI_STEP_RULES = {"privilege_escalation", "coordinated_attack"}
        if alert.severity == Severity.CRITICAL:
            source_set = set(alert.sources)
            # Remove internal tags
            real_sources = source_set - {"anomaly"}
            if len(real_sources) < 2 and alert.rule_name not in MULTI_STEP_RULES:
                logger.debug(f"Downgrading CRITICAL→HIGH: single source for rule "
                             f"'{alert.rule_name}' entity '{entity}'")
                alert.severity = Severity.HIGH

        # ── Deduplication / Cooldown ──────────────────
        cooldown = self.COOLDOWN.get(alert.rule_name, self.COOLDOWN["default"])
        with self._lock:
            last = self._last_alert.get(key, 0.0)
            if now - last < cooldown:
                self.counters["suppressed"] += 1
                return
            self._last_alert[key] = now

        # ── Record & Display ──────────────────────────
        self.counters["total"] += 1
        self.counters[alert.severity] += 1
        self.alert_log.append(alert)

        color   = _COLORS.get(alert.severity, "")
        sources = ", ".join(alert.sources) if alert.sources else "n/a"
        line    = (f"{color}[{alert.severity}] {alert.rule_name} | "
                   f"entity={entity} | score={alert.score:.1f} | "
                   f"sources=[{sources}] | {alert.description}{_RESET}")
        print(line, flush=True)
        logger.info(f"ALERT [{alert.severity}] rule={alert.rule_name} "
                    f"entity={entity} score={alert.score:.1f} sources=[{sources}] "
                    f"desc={alert.description}")

    def stop(self):
        self.active.clear()

    def get_metrics(self) -> dict:
        return dict(self.counters)

    def get_alert_log(self) -> list[Alert]:
        return list(self.alert_log)