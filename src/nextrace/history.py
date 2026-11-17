
import json
from pathlib import Path


HISTORY_DIR = Path("history")


def save_snapshot(target, data, filename):
    HISTORY_DIR.mkdir(exist_ok=True)
    filepath = HISTORY_DIR / filename

    snapshot = {
        "target": target,
        **data,
    }

    with filepath.open("w", encoding="utf-8") as file:
        json.dump(snapshot, file, indent=4)

    return filepath


def load_previous_snapshot(target, filename):
    if not HISTORY_DIR.exists():
        return None

    snapshots = sorted(
        HISTORY_DIR.glob(f"{filename}_*.json"),
        reverse=True,
    )

    for filepath in snapshots:
        try:
            with filepath.open("r", encoding="utf-8") as file:
                snapshot = json.load(file)

            if snapshot.get("target") == target:
                return snapshot

        except (OSError, json.JSONDecodeError):
            continue

    return None


def compare_scans(previous, current):
    """Compare two scan snapshots without assuming missing ports are closed."""
    old_ports = {
        (item["host"], item["protocol"], item["port"]): item
        for item in previous.get("ports", [])
    }

    new_ports = {
        (item["host"], item["protocol"], item["port"]): item
        for item in current.get("ports", [])
    }

    changes = {
        "newly_opened": [],
        "closed": [],
        "service_changed": [],
        "no_longer_observed": [],
    }

    for key, new_item in new_ports.items():
        old_item = old_ports.get(key)

        if new_item.get("state") == "open":
            if old_item is None or old_item.get("state") != "open":
                changes["newly_opened"].append(new_item)

            elif any(
                old_item.get(field) != new_item.get(field)
                for field in ("service", "product", "version")
            ):
                changes["service_changed"].append({
                    "previous": old_item,
                    "current": new_item,
                })

        elif old_item and old_item.get("state") == "open":
            if new_item.get("state") == "closed":
                changes["closed"].append(new_item)

    for key, old_item in old_ports.items():
        if key not in new_ports and old_item.get("state") == "open":
            changes["no_longer_observed"].append(old_item)

    return changes
