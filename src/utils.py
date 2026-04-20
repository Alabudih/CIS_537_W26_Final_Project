"""
Utility helpers for the P4-DVPF replication project.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import csv
from typing import Iterable, List


@dataclass
class Event:
    """
    Represents one traffic observation window.

    Attributes:
        time_index: Integer index of the observation window.
        traffic_rate: Number of packets observed in the window.
        unique_flows: Number of distinct flows seen in the window.
        path_mismatch: Whether forwarding-path verification failed.
        attack_type: Label used for ground truth.
        detected: Whether the replication detector raised an alert.
        detection_delay_ms: Simulated detection delay in milliseconds.
    """
    time_index: int
    traffic_rate: int
    unique_flows: int
    path_mismatch: int
    attack_type: str
    detected: int
    detection_delay_ms: float


def ensure_dir(path: str | Path) -> Path:
    """Create a directory if needed and return it as a Path object."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_events_csv(events: Iterable[Event], csv_path: str | Path) -> None:
    """Write a list of Event objects to a CSV file."""
    csv_path = Path(csv_path)
    rows = [asdict(event) for event in events]
    if not rows:
        return
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_json(data: dict, json_path: str | Path) -> None:
    """Write JSON with pretty indentation for readability."""
    json_path = Path(json_path)
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
