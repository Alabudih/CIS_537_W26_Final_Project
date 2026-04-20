"""
Mock controller for a simplified P4-DVPF style experiment.

This file does not require a live P4Runtime switch. It demonstrates the sort of
control-plane rule loading and event collection that a full implementation would use.
"""

from __future__ import annotations
from pathlib import Path
import json
import time


def load_topology(topology_path: str | Path) -> dict:
    """Read the topology JSON file."""
    with open(topology_path, "r", encoding="utf-8") as f:
        return json.load(f)


def install_rules() -> list[dict]:
    """Return a list of example forwarding and verification rules."""
    return [
        {"table": "MyIngress.ipv4_lpm", "match": "10.0.1.1/32", "action": "ipv4_forward", "params": {"port": 1}},
        {"table": "MyIngress.ipv4_lpm", "match": "10.0.2.2/32", "action": "ipv4_forward", "params": {"port": 2}},
        {"table": "MyIngress.verify_table", "match": "verif_header.valid == 1", "action": "mark_checked", "params": {}},
    ]


def main() -> None:
    """Simulate startup actions of a controller."""
    project_root = Path(__file__).resolve().parents[1]
    topology = load_topology(project_root / "topology" / "topology.json")
    rules = install_rules()

    print("Loaded topology with", len(topology["hosts"]), "hosts and", len(topology["switches"]), "switch(es).")
    print("Installing", len(rules), "example rules...")
    time.sleep(1)
    for rule in rules:
        print("Installed:", rule)
    print("Controller initialization complete.")


if __name__ == "__main__":
    main()
