# Multi-Source Intrusion Detection System (IDS)
## CS8.403 Lab Assignment 4 — IIIT Hyderabad

---

## Overview

A lightweight, modular IDS that correlates evidence from **network** and **host** sensors
to detect attacks while minimising false positives.

### Architecture

```
┌───────────────┐    ┌───────────────┐
│ Network Sensor│    │  Host Sensor  │
│  (flows/TCP)  │    │ (logins/procs)│
└──────┬────────┘    └──────┬────────┘
       │  Events (JSON)     │
       └─────────┬──────────┘
          ┌──────▼──────┐
          │  Event Bus  │  (thread-safe pub/sub)
          └──────┬──────┘
     ┌───────────┼──────────────┐
     │           │              │
┌────▼────┐ ┌────▼────┐ ┌──────▼──────┐
│Anomaly  │ │Correl.  │ │Flow Tracker │
│Detector │ │Engine   │ │(port scan)  │
└────┬────┘ └────┬────┘ └─────────────┘
     └─────┬─────┘
     ┌─────▼──────┐
     │Alert Manager│
     │(dedup/score)│
     └─────────────┘
```

---

## Requirements

- Python 3.9+
- pip packages: `psutil`

```bash
pip install psutil
```

> No other external libraries required.  
> Scapy / Snort / Suricata are NOT used.

---

## File Structure

```
ids/
├── schema.py              # Unified Event + Alert data model
├── event_bus.py           # Thread-safe publish-subscribe bus
├── network_sensor.py      # Network flow capture + synthetic generator
├── host_sensor.py         # Host log monitor + synthetic generator
├── anomaly_detector.py    # Statistical z-score anomaly detection
├── correlation_engine.py  # Sliding window + 7 rule-based detectors
├── alert_manager.py       # Deduplication, cooldown, severity enforcement
├── attack_simulator.py    # All 6 attack scenarios
├── metrics.py             # Precision, Recall, F1, latency, CPU/memory
├── ids_main.py            # Main orchestrator + experiment runner
├── README.md
└── SECURITY.md
```

---

## How to Run

### 1. Run All Scenarios (recommended)

```bash
cd ids/
python ids_main.py
```

This runs:
1. Benign baseline phase
2. Brute-force attack
3. Fast + slow port scan
4. Noise injection (false-positive test)
5. Replay attack
6. Sensor failure simulation
7. Coordinated multi-vector attack

### 2. Run a Specific Scenario

```bash
python ids_main.py --scenario brute_force
python ids_main.py --scenario port_scan
python ids_main.py --scenario noise
python ids_main.py --scenario replay
python ids_main.py --scenario sensor_failure
python ids_main.py --scenario coordinated
python ids_main.py --scenario baseline
```

### 3. Adjust Baseline Duration

```bash
python ids_main.py --baseline-duration 15
```

---

## Output

- **Console**: Color-coded alerts with severity, rule, entity, score
- **alerts.log**: Persistent log of all generated alerts

### Alert Severity Colours

| Colour  | Severity  |
|---------|-----------|
| White   | Info      |
| Cyan    | Low       |
| Yellow  | Medium    |
| Red     | High      |
| Bold Red| Critical  |

---

## Core Security Requirement

> A **Critical** alert is only raised when:
> 1. Evidence from ≥2 independent sources agrees within the time window, **OR**
> 2. A deterministic multi-step pattern is detected (e.g., privilege escalation, coordinated attack)

This is enforced in `alert_manager.py` → `_process()`.

---

## Detection Rules

| Rule                    | Trigger                                     | Min Severity |
|-------------------------|---------------------------------------------|-------------|
| `brute_force`           | ≥5 failed logins in 60s                     | Medium       |
| `port_scan`             | ≥15 unique ports accessed in 10s            | High         |
| `privilege_escalation`  | priv-esc after ≥2 failures (multi-step)     | High→Critical|
| `sensitive_file_access` | Access to /etc/shadow, /etc/passwd etc.     | Medium       |
| `suspicious_process`    | Execution of nc, nmap, hydra, etc.          | Medium       |
| `replay_attack`         | NET_REPLAY event detected                   | Medium       |
| `coordinated_attack`    | Brute force + port scan combined            | Critical     |
| `anomaly_detection`     | z-score > 3.0 for any tracked feature       | Medium       |

---

## Metrics Reported

For each experiment:

- True Positives / False Positives / True Negatives / False Negatives
- Precision, Recall, F1-score
- False Positive Rate, False Negative Rate
- Average Alert Latency (ms)
- CPU % and Memory (MB) usage