"""
Generate synthetic benign and attack traffic windows for the P4-DVPF replication.

This script creates a CSV file that the analysis script later uses to generate
comparison plots. The logic is intentionally simple and transparent so the
replication is easy to understand and modify.
"""

from __future__ import annotations  # Enables forward type hints (Python 3.7+ feature)
import random  # Used to generate synthetic/random traffic data
from pathlib import Path  # Used for platform-independent file paths
from statistics import mean  # Used to compute average detection delay

# Import custom helper functions and data structure from utils.py
from utils import Event, ensure_dir, write_events_csv, write_json

# Fixed seed so results are reproducible every time the script runs
random.seed(574)


def classify_window(traffic_rate: int, unique_flows: int, path_mismatch: int) -> tuple[int, float]:
    """
    Simulate a data-plane detector.

    Returns:
        detected: 1 if an alert is raised, otherwise 0
        delay_ms: simulated detection delay in milliseconds
    """

    # Detect flooding attack: high traffic rate + high number of unique flows
    flooding = traffic_rate > 850 and unique_flows > 70

    # Detect hijacking attack: path mismatch indicates incorrect forwarding path
    hijacking = path_mismatch == 1

    # If either condition is true, mark as detected attack
    detected = int(flooding or hijacking)

    # Simulate detection delay (data plane is faster than controller)
    if hijacking:
        delay_ms = round(random.uniform(3.1, 4.3), 2)  # Fast detection for hijacking
    elif flooding:
        delay_ms = round(random.uniform(3.5, 4.8), 2)  # Slightly slower than hijacking
    else:
        delay_ms = round(random.uniform(5.0, 7.5), 2)  # Normal traffic takes longer

    return detected, delay_ms  # Return detection result and delay


def generate_events() -> list[Event]:
    """Create benign, flooding, and hijacking observation windows."""

    events: list[Event] = []  # List to store all generated events
    time_index = 0  # Acts like a timestamp or sequence counter

    # -------------------------
    # Generate BENIGN traffic
    # -------------------------
    for _ in range(120):  # Create 120 benign samples
        traffic_rate = random.randint(280, 620)  # Normal traffic range
        unique_flows = random.randint(8, 38)  # Typical number of flows

        # Small probability of mismatch (noise / false anomaly)
        path_mismatch = 1 if random.random() < 0.02 else 0

        # Classify this window using detection logic
        detected, delay_ms = classify_window(traffic_rate, unique_flows, path_mismatch)

        # Store event data
        events.append(
            Event(
                time_index=time_index,  # Time index
                traffic_rate=traffic_rate,  # Packets/sec or similar metric
                unique_flows=unique_flows,  # Number of distinct flows
                path_mismatch=path_mismatch,  # Path correctness flag
                attack_type="benign",  # Label as benign
                detected=detected,  # Detection result
                detection_delay_ms=delay_ms,  # Detection delay
            )
        )
        time_index += 1  # Increment time index

    # -------------------------
    # Generate FLOODING attacks
    # -------------------------
    for _ in range(40):  # Create 40 flooding samples
        traffic_rate = random.randint(880, 1250)  # High traffic (attack)
        unique_flows = random.randint(72, 120)  # Large number of flows
        path_mismatch = 0  # Flooding doesn't affect path consistency

        detected, delay_ms = classify_window(traffic_rate, unique_flows, path_mismatch)

        events.append(
            Event(
                time_index=time_index,
                traffic_rate=traffic_rate,
                unique_flows=unique_flows,
                path_mismatch=path_mismatch,
                attack_type="flooding",  # Label as flooding attack
                detected=detected,
                detection_delay_ms=delay_ms,
            )
        )
        time_index += 1

    # -------------------------
    # Generate HIJACKING attacks
    # -------------------------
    for _ in range(35):  # Create 35 hijacking samples
        traffic_rate = random.randint(300, 540)  # Normal traffic rate
        unique_flows = random.randint(10, 30)  # Normal flow count
        path_mismatch = 1  # Key indicator of hijacking

        detected, delay_ms = classify_window(traffic_rate, unique_flows, path_mismatch)

        events.append(
            Event(
                time_index=time_index,
                traffic_rate=traffic_rate,
                unique_flows=unique_flows,
                path_mismatch=path_mismatch,
                attack_type="hijacking",  # Label as hijacking attack
                detected=detected,
                detection_delay_ms=delay_ms,
            )
        )
        time_index += 1

    return events  # Return all generated events


def main() -> None:
    """Run the simulation and write CSV + summary JSON."""

    # Get project root directory (two levels up from this file)
    project_root = Path(__file__).resolve().parents[1]

    # Ensure data and results directories exist
    data_dir = ensure_dir(project_root / "data")
    results_dir = ensure_dir(project_root / "results")

    # Generate synthetic dataset
    events = generate_events()

    # Save all events to CSV file
    write_events_csv(events, data_dir / "sample_events.csv")

    # Total number of events
    total = len(events)

    # Split dataset by type
    benign = [e for e in events if e.attack_type == "benign"]
    flooding = [e for e in events if e.attack_type == "flooding"]
    hijacking = [e for e in events if e.attack_type == "hijacking"]

    # Create summary metrics
    summary = {
        "total_windows": total,  # Total samples
        "benign_windows": len(benign),  # Count benign
        "flooding_windows": len(flooding),  # Count flooding attacks
        "hijacking_windows": len(hijacking),  # Count hijacking attacks

        # Average detection delays
        "avg_delay_benign_ms": round(mean(e.detection_delay_ms for e in benign), 2),
        "avg_delay_flooding_ms": round(mean(e.detection_delay_ms for e in flooding), 2),
        "avg_delay_hijacking_ms": round(mean(e.detection_delay_ms for e in hijacking), 2),
    }

    # Save summary to JSON file
    write_json(summary, results_dir / "summary.json")

    # Print output file locations
    print("Generated synthetic events at:", data_dir / "sample_events.csv")
    print("Wrote summary metrics to:", results_dir / "summary.json")


# Entry point of the script
if __name__ == "__main__":
    main()  # Execute main function
