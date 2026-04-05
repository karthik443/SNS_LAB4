"""
ids_main.py - Main entry point for the Multi-Source IDS.

Usage:
    python ids_main.py [--scenario SCENARIO] [--duration DURATION]

Scenarios:
    all             Run all scenarios sequentially (default)
    brute_force     Brute-force login attack
    port_scan       Fast + slow port scan
    noise           Noise injection robustness test
    replay          Replay attack
    sensor_failure  Sensor failure simulation
    coordinated     Multi-vector coordinated attack
    baseline        Benign baseline only (no attacks)
"""

import argparse
import logging
import threading
import time
import sys

# ── Configure logging first ──────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
# Suppress noisy internal loggers
logging.getLogger("ids.event_bus").setLevel(logging.WARNING)

# ── Import IDS components ────────────────────
from schema import Severity
from event_bus import bus
from network_sensor import SyntheticNetworkSensor, flow_tracker
from host_sensor import SyntheticHostSensor, AuthLogSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from anomaly_detector import anomaly_detector
from metrics import ExperimentRecord, ResourceMonitor, evaluate_alerts
import attack_simulator as sim

logger = logging.getLogger("ids.main")


# ─────────────────────────────────────────────
# IDS System Context
# ─────────────────────────────────────────────

class IDSSystem:
    """
    Manages lifecycle of all IDS components.
    Call start() to bring up the system, stop() to tear it down.
    """

    def __init__(self):
        self._active      = threading.Event()
        self._active.set()

        # Component instances
        self.net_sensor   = SyntheticNetworkSensor(rate_hz=3.0, active=self._active)
        self.host_sensor  = SyntheticHostSensor(rate_hz=2.0, active=self._active)
        self.auth_sensor  = AuthLogSensor(active=self._active)
        self.correlation  = CorrelationEngine(active=self._active)
        self.alert_mgr    = AlertManager(active=self._active, log_file="alerts.log")
        self.resource_mon = ResourceMonitor(interval=1.0, active=self._active)

        # Wire flow tracker into net event bus
        net_queue = bus.subscribe_events()
        def _flow_feeder():
            while self._active.is_set():
                try:
                    evt = net_queue.get(timeout=1.0)
                    flow_tracker.record(evt)
                except Exception:
                    pass
        self._flow_thread = threading.Thread(target=_flow_feeder,
                                             daemon=True, name="FlowFeeder")

    def start(self):
        logger.info("=" * 60)
        logger.info("  Multi-Source IDS Starting...")
        logger.info("=" * 60)
        self.net_sensor.start()
        self.host_sensor.start()
        self.auth_sensor.start()
        self.correlation.start()
        self.alert_mgr.start()
        self.resource_mon.start()
        self._flow_thread.start()
        logger.info("All IDS components running.")

    def stop(self):
        logger.info("Stopping IDS...")
        self._active.clear()
        # Give threads a moment to finish
        time.sleep(1.5)

    def alerts(self):
        return self.alert_mgr.get_alert_log()

    def metrics(self) -> dict:
        return self.alert_mgr.get_metrics()

    def resource_report(self) -> str:
        return self.resource_mon.report()


# ─────────────────────────────────────────────
# Experiment runners
# ─────────────────────────────────────────────

def _banner(title: str):
    print(f"\n\033[1;34m{'─'*60}\n  🔍  {title}\n{'─'*60}\033[0m", flush=True)


def run_baseline(ids: IDSSystem, duration: float = 10.0) -> ExperimentRecord:
    _banner("Baseline: Benign Traffic Only")
    rec = ExperimentRecord("baseline")
    time.sleep(duration)
    rec.end_time = time.time()
    rec.injected_benign = int(duration * 5)   # ~5 events/s synthetic
    evaluate_alerts(ids.alerts(), [], rec.injected_benign, rec)
    return rec


def run_brute_force(ids: IDSSystem) -> ExperimentRecord:
    _banner("Scenario 1: Brute-Force Login")
    rec = ExperimentRecord("brute_force")
    attack_start = time.time()
    sim.scenario_brute_force(username="root", n_attempts=20, delay=0.08)
    attack_end = time.time()
    time.sleep(3)  # let alerts propagate
    rec.end_time = time.time()
    rec.injected_attacks = 1
    evaluate_alerts(ids.alerts(), [(attack_start, attack_end, "brute_force")],
                    benign_count=30, record=rec)
    return rec


def run_port_scan(ids: IDSSystem) -> ExperimentRecord:
    _banner("Scenario 2: Port Scan (Fast + Slow)")
    rec = ExperimentRecord("port_scan")
    t0 = time.time()
    sim.scenario_port_scan_fast()
    t1 = time.time()
    time.sleep(1)
    sim.scenario_port_scan_slow()
    t2 = time.time()
    time.sleep(3)
    rec.end_time = time.time()
    rec.injected_attacks = 2
    evaluate_alerts(ids.alerts(),
                    [(t0, t1, "port_scan"), (t1+1, t2, "port_scan")],
                    benign_count=20, record=rec)
    return rec


def run_noise(ids: IDSSystem) -> ExperimentRecord:
    _banner("Scenario 3: Noise Injection (no true attacks)")
    rec = ExperimentRecord("noise_injection")
    sim.scenario_noise_injection(duration=8.0, n_ips=40)
    time.sleep(2)
    rec.end_time = time.time()
    rec.injected_benign = 200
    rec.injected_attacks = 0
    # All alerts during noise are false positives
    noise_alerts = [a for a in ids.alerts() if a.severity in (Severity.HIGH, Severity.CRITICAL)]
    rec.false_positives = len(noise_alerts)
    rec.true_negatives  = max(0, 200 - rec.false_positives)
    return rec


def run_replay(ids: IDSSystem) -> ExperimentRecord:
    _banner("Scenario 4: Replay Attack")
    rec = ExperimentRecord("replay_attack")
    sim.scenario_record_benign(n=10)
    time.sleep(1)
    t0 = time.time()
    sim.scenario_replay_attack()
    t1 = time.time()
    time.sleep(3)
    rec.end_time = time.time()
    rec.injected_attacks = 1
    evaluate_alerts(ids.alerts(), [(t0, t1, "replay_attack")],
                    benign_count=10, record=rec)
    return rec


def run_sensor_failure(ids: IDSSystem) -> ExperimentRecord:
    _banner("Scenario 5: Sensor Failure Simulation")
    rec = ExperimentRecord("sensor_failure")

    active_ref = ids.host_sensor.active
    def _stop_host():
        active_ref.clear()
    def _start_host():
        active_ref.set()
        # Re-use same thread since it's daemon; spawn new one
        new_hs = SyntheticHostSensor(rate_hz=2.0, active=active_ref)
        new_hs.start()

    from host_sensor import SyntheticHostSensor
    fsim = sim.SensorFailureSimulator("host_sensor", _stop_host, _start_host)

    t0 = time.time()
    # During sensor failure, run a brute-force attack from network side only
    fail_thread = threading.Thread(target=fsim.simulate_failure, args=(10.0,), daemon=True)
    fail_thread.start()
    time.sleep(1)  # let failure take effect
    sim.scenario_brute_force(username="root", n_attempts=10, delay=0.1)
    fail_thread.join()
    time.sleep(2)
    rec.end_time = time.time()

    # Verify: with only network source, no CRITICAL alerts should exist
    critical = [a for a in ids.alerts()
                if a.severity == Severity.CRITICAL and t0 <= a.timestamp <= rec.end_time]
    print(f"  Critical alerts during sensor failure: {len(critical)} "
          f"(should be 0 per security requirement)")
    rec.true_negatives = 1 if len(critical) == 0 else 0
    rec.false_positives = len(critical)
    return rec


def run_coordinated(ids: IDSSystem) -> ExperimentRecord:
    _banner("Scenario 6: Coordinated Multi-Vector Attack")
    rec = ExperimentRecord("coordinated_attack")
    t0 = time.time()
    sim.scenario_coordinated_attack(username="admin")
    t1 = time.time()
    time.sleep(4)
    rec.end_time = time.time()
    rec.injected_attacks = 1
    evaluate_alerts(ids.alerts(), [(t0, t1, "coordinated_attack")],
                    benign_count=20, record=rec)
    return rec


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

SCENARIO_MAP = {
    "baseline":       run_baseline,
    "brute_force":    run_brute_force,
    "port_scan":      run_port_scan,
    "noise":          run_noise,
    "replay":         run_replay,
    "sensor_failure": run_sensor_failure,
    "coordinated":    run_coordinated,
}


def main():
    parser = argparse.ArgumentParser(description="Multi-Source IDS")
    parser.add_argument("--scenario", default="all",
                        choices=list(SCENARIO_MAP.keys()) + ["all"],
                        help="Which scenario to run (default: all)")
    parser.add_argument("--baseline-duration", type=float, default=8.0,
                        help="Seconds for baseline phase (default: 8)")
    args = parser.parse_args()

    ids = IDSSystem()
    ids.start()

    print("\n\033[1;33m⚡ Warming up (establishing baseline)...\033[0m")
    time.sleep(args.baseline_duration)

    records = []

    if args.scenario == "all":
        scenarios = list(SCENARIO_MAP.keys())
    else:
        scenarios = [args.scenario]

    for name in scenarios:
        fn = SCENARIO_MAP[name]
        try:
            if name == "baseline":
                rec = fn(ids, args.baseline_duration)
            else:
                rec = fn(ids)
            records.append(rec)
            print(rec.report())
        except Exception as e:
            logger.error(f"Scenario '{name}' failed: {e}", exc_info=True)
        time.sleep(2)  # gap between scenarios

    # Final summary
    print(f"\n\033[1;32m{'='*60}")
    print("  IDS Alert Manager Summary")
    print(f"{'='*60}\033[0m")
    m = ids.metrics()
    for k, v in m.items():
        print(f"  {k:20s}: {v}")
    print(f"\n  Resource Usage:\n{ids.resource_report()}")

    print(f"\n  Alerts log saved to: alerts.log")
    print(f"  Total experiments  : {len(records)}")

    ids.stop()
    print("\n\033[1;32m✅ IDS stopped cleanly.\033[0m\n")


if __name__ == "__main__":
    main()