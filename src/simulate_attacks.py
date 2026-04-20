"""
Generate synthetic benign and attack traffic windows for the P4-DVPF replication.

This script creates a CSV file that the analysis script later uses to generate
comparison plots. The logic is intentionally simple and transparent so the
replication is easy to understand and modify.
"""

from __future__ import annotations
import random
from pathlib import Path
from statistics import mean

from utils import Event, ensure_dir, write_events_csv, write_json

# Fixed seed so results are reproducible every time the script runs.
random.seed(574)


def classify_window(traffic_rate: int, unique_flows: int, path_mismatch: int) -> tuple[int, float]:
    """
    Simulate a data-plane detector.

    Returns:
        detected: 1 if an alert is raised, otherwise 0
        delay_ms: simulated detection delay in milliseconds
    """
    # Flooding-like behavior: unusually high traffic and too many distinct flows.
    flooding = traffic_rate > 850 and unique_flows > 70

    # Hijacking-like behavior: path verification says the packet path is inconsistent.
    hijacking = path_mismatch == 1

    detected = int(flooding or hijacking)

    # Data-plane detection is modeled as faster than controller-centric handling.
    if hijacking:
        delay_ms = round(random.uniform(3.1, 4.3), 2)
    elif flooding:
        delay_ms = round(random.uniform(3.5, 4.8), 2)
    else:
        delay_ms = round(random.uniform(5.0, 7.5), 2)

    return detected, delay_ms


def generate_events() -> list[Event]:
    """Create benign, flooding, and hijacking observation windows."""
    events: list[Event] = []
    time_index = 0

    # Benign traffic windows.
    for _ in range(120):
        traffic_rate = random.randint(280, 620)
        unique_flows = random.randint(8, 38)
        path_mismatch = 1 if random.random() < 0.02 else 0
        detected, delay_ms = classify_window(traffic_rate, unique_flows, path_mismatch)
        events.append(
            Event(
                time_index=time_index,
                traffic_rate=traffic_rate,
                unique_flows=unique_flows,
                path_mismatch=path_mismatch,
                attack_type="benign",
                detected=detected,
                detection_delay_ms=delay_ms,
            )
        )
        time_index += 1

    # Flooding attack windows.
    for _ in range(40):
        traffic_rate = random.randint(880, 1250)
        unique_flows = random.randint(72, 120)
        path_mismatch = 0
        detected, delay_ms = classify_window(traffic_rate, unique_flows, path_mismatch)
        events.append(
            Event(
                time_index=time_index,
                traffic_rate=traffic_rate,
                unique_flows=unique_flows,
                path_mismatch=path_mismatch,
                attack_type="flooding",
                detected=detected,
                detection_delay_ms=delay_ms,
            )
        )
        time_index += 1

    # Hijacking attack windows.
    for _ in range(35):
        traffic_rate = random.randint(300, 540)
        unique_flows = random.randint(10, 30)
        path_mismatch = 1
        detected, delay_ms = classify_window(traffic_rate, unique_flows, path_mismatch)
        events.append(
            Event(
                time_index=time_index,
                traffic_rate=traffic_rate,
                unique_flows=unique_flows,
                path_mismatch=path_mismatch,
                attack_type="hijacking",
                detected=detected,
                detection_delay_ms=delay_ms,
            )
        )
        time_index += 1

    return events


def main() -> None:
    """Run the simulation and write CSV + summary JSON."""
    project_root = Path(__file__).resolve().parents[1]
    data_dir = ensure_dir(project_root / "data")
    results_dir = ensure_dir(project_root / "results")

    events = generate_events()
    write_events_csv(events, data_dir / "sample_events.csv")

    total = len(events)
    benign = [e for e in events if e.attack_type == "benign"]
    flooding = [e for e in events if e.attack_type == "flooding"]
    hijacking = [e for e in events if e.attack_type == "hijacking"]

    summary = {
        "total_windows": total,
        "benign_windows": len(benign),
        "flooding_windows": len(flooding),
        "hijacking_windows": len(hijacking),
        "avg_delay_benign_ms": round(mean(e.detection_delay_ms for e in benign), 2),
        "avg_delay_flooding_ms": round(mean(e.detection_delay_ms for e in flooding), 2),
        "avg_delay_hijacking_ms": round(mean(e.detection_delay_ms for e in hijacking), 2),
    }
    write_json(summary, results_dir / "summary.json")
    print("Generated synthetic events at:", data_dir / "sample_events.csv")
    print("Wrote summary metrics to:", results_dir / "summary.json")


if __name__ == "__main__":
    main()
