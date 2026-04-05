# SECURITY.md — Security Design for Multi-Source IDS

## 1. Threat Model

The IDS assumes an adversary with the following capabilities:

- Can perform brute-force login attempts via SSH or other services
- Can conduct port scans (fast sequential or slow stealthy)
- Can replay previously observed benign traffic with slight modifications
- Can inject random noise to hide malicious activity among false signals
- Can temporarily disable one sensor (partial system compromise)

The adversary **cannot**:
- Completely compromise both network and host sensors simultaneously
- Modify the correlation engine or alert manager
- Forge events with verified internal source identifiers

---

## 2. Multi-Source Correlation Requirement

### Rationale

Single-source detection is vulnerable to:
- **Spoofed logs** (attacker modifies host logs)
- **Encrypted traffic** (network sensor blind to content)
- **Steganographic channels** (low-signal evasion)

By requiring agreement from ≥2 independent sources, the IDS forces an attacker to compromise **multiple orthogonal subsystems** simultaneously, which is significantly harder.

### Implementation

In `alert_manager.py`:

```python
if alert.severity == Severity.CRITICAL:
    real_sources = set(alert.sources) - {"anomaly"}
    if len(real_sources) < 2 and rule_name not in MULTI_STEP_RULES:
        alert.severity = Severity.HIGH   # downgrade to High
```

Multi-step deterministic rules (`privilege_escalation`, `coordinated_attack`) are exempt because the attack chain itself constitutes strong evidence even from a single sensor.

---

## 3. False Positive Control

### Mechanism 1 — Cooldown / Deduplication

Each rule has a cooldown period. Re-triggering the same rule for the same entity within the cooldown window is suppressed. This prevents **alert flooding** from repeated benign anomalies.

### Mechanism 2 — Severity Scoring

Alerts carry a `score` field computed as `Σ w(e)` (sum of event weights). Low-weight events cannot accumulate into high-severity alerts without volume.

### Mechanism 3 — Statistical Thresholding

The anomaly detector uses a z-score with a threshold of 3.0 (3 standard deviations). New entities must accumulate ≥3 historical data points before anomaly signals are generated, preventing early false alarms.

---

## 4. Sliding Time Window

All rule evaluations operate on a **60-second sliding window** per entity. Events older than 60 seconds are discarded. This ensures:

- Slow/stealthy attacks across many minutes are NOT accumulated indefinitely
- Short-burst attacks within 60s trigger appropriate alerts
- Memory usage is bounded (deque with automatic pruning)

The window can be tuned in `correlation_engine.py → WINDOW_SECONDS`.

---

## 5. Event Schema Integrity

All components use a single `Event` dataclass from `schema.py`. The `source` field
(`"network"` or `"host"`) is set by the originating sensor and is used by the
correlation engine to determine multi-source status.

Inconsistent schema usage is a common error source — the unified dataclass with
type hints prevents this at development time.

---

## 6. Graceful Sensor Failure

If one sensor fails (simulated in `attack_simulator.py`), the IDS continues operating with degraded detection quality. Specifically:

- Rules continue to fire from the remaining sensor
- Severity is **capped at High** (not Critical) while only one source is active
- A `SENSOR_FAILURE` event is emitted to the bus for observability

This matches real-world resilience requirements where sensor availability is not guaranteed.

---

## 7. Identified Limitations

| Limitation | Mitigation |
|---|---|
| No cryptographic source verification | Assumed trusted internal bus |
| Synthetic logs (not real syslog) | AuthLogSensor supports real /var/log/auth.log |
| No persistence between restarts | alerts.log provides audit trail |
| Single-machine deployment | Architecture supports distributed extension |
| No ML-based detection | z-score anomaly module is extensible to ML |