"""
metrics.py - Evaluation metrics for the IDS.

Computes:
  - Precision, Recall, F1-score
  - False Positive Rate, False Negative Rate
  - Alert latency statistics
  - CPU and memory usage
"""

import time
import threading
import logging
import psutil
import os
from dataclasses import dataclass, field
from schema import Alert, Severity

logger = logging.getLogger("ids.metrics")


@dataclass
class ExperimentRecord:
    """Tracks ground truth for a single experiment run."""
    name:             str
    start_time:       float = field(default_factory=time.time)
    end_time:         float = 0.0
    injected_attacks: int   = 0      # total malicious events injected
    injected_benign:  int   = 0      # total benign events injected

    # Filled after experiment ends
    true_positives:  int   = 0
    false_positives: int   = 0
    true_negatives:  int   = 0
    false_negatives: int   = 0

    alert_latencies: list  = field(default_factory=list)  # seconds

    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def fpr(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    def fnr(self) -> float:
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom else 0.0

    def avg_latency(self) -> float:
        return sum(self.alert_latencies) / len(self.alert_latencies) \
               if self.alert_latencies else 0.0

    def report(self) -> str:
        duration = (self.end_time or time.time()) - self.start_time
        lines = [
            f"\n{'='*60}",
            f"  Experiment: {self.name}",
            f"  Duration  : {duration:.1f}s",
            f"{'='*60}",
            f"  True Positives  : {self.true_positives}",
            f"  False Positives : {self.false_positives}",
            f"  True Negatives  : {self.true_negatives}",
            f"  False Negatives : {self.false_negatives}",
            f"  Precision       : {self.precision():.3f}",
            f"  Recall          : {self.recall():.3f}",
            f"  F1-score        : {self.f1():.3f}",
            f"  FP Rate         : {self.fpr():.3f}",
            f"  FN Rate         : {self.fnr():.3f}",
            f"  Avg Latency     : {self.avg_latency()*1000:.1f} ms",
            f"{'='*60}",
        ]
        return "\n".join(lines)


class ResourceMonitor(threading.Thread):
    """Samples CPU and memory usage of the current process periodically."""

    def __init__(self, interval: float = 1.0, active: threading.Event = None):
        super().__init__(daemon=True, name="ResourceMonitor")
        self.interval   = interval
        self.active     = active or threading.Event()
        self.active.set()
        self._proc      = psutil.Process(os.getpid())
        self.cpu_samples:  list[float] = []
        self.mem_samples:  list[float] = []

    def run(self):
        while self.active.is_set():
            try:
                self.cpu_samples.append(self._proc.cpu_percent(interval=None))
                self.mem_samples.append(self._proc.memory_info().rss / 1024 / 1024)  # MB
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self):
        self.active.clear()

    def report(self) -> str:
        if not self.cpu_samples:
            return "  No resource data collected."
        avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples)
        max_cpu = max(self.cpu_samples)
        avg_mem = sum(self.mem_samples) / len(self.mem_samples)
        max_mem = max(self.mem_samples)
        return (f"  CPU avg={avg_cpu:.1f}% max={max_cpu:.1f}% | "
                f"MEM avg={avg_mem:.1f}MB max={max_mem:.1f}MB")


def evaluate_alerts(alerts: list[Alert],
                    attack_windows: list[tuple],
                    benign_count: int,
                    record: ExperimentRecord):
    """
    Matches alerts against known attack windows to compute TP/FP/FN/TN.

    attack_windows: list of (start_ts, end_ts, rule_name) tuples
    benign_count:   number of benign events that should NOT trigger alerts
    """
    ATTACK_RULES = {
        "brute_force", "port_scan", "privilege_escalation",
        "sensitive_file_access", "suspicious_process",
        "replay_attack", "coordinated_attack"
    }

    matched_windows = set()
    # Larger grace to account for propagation delays between components
    GRACE = 8.0
    for alert in alerts:
        if alert.rule_name not in ATTACK_RULES:
            continue
        matched = False
        for i, (ws, we, wname) in enumerate(attack_windows):
            # For coordinated attacks, accept any contributing attack rule as TP
            window_match = False
            if wname == "coordinated_attack":
                # Accept the fused coordinated_alert itself, or any contributing
                # attack rule that indicates the coordinated event.
                if alert.rule_name == "coordinated_attack" or \
                   alert.rule_name in {"brute_force", "port_scan", "replay_attack", "privilege_escalation"}:
                    window_match = (ws <= alert.timestamp <= we + GRACE)
            else:
                # Allow the fused coordinated alert to satisfy individual attack
                # windows (e.g., a coordinated detection proves a port_scan).
                window_match = (ws <= alert.timestamp <= we + GRACE and
                                (alert.rule_name == wname or alert.rule_name == "coordinated_attack"))

            if window_match:
                if i not in matched_windows:
                    record.true_positives += 1
                    matched_windows.add(i)
                    if record.start_time:
                        record.alert_latencies.append(alert.timestamp - ws)
                matched = True
                break
        if not matched:
            record.false_positives += 1

    record.false_negatives = len(attack_windows) - len(matched_windows)
    record.true_negatives  = max(0, benign_count - record.false_positives)