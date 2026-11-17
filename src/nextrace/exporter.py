
import csv
import json
from pathlib import Path


OUTPUT_DIR = Path("output")


def export_json(results, filename):
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / filename

    with filepath.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    return filepath


def export_csv(results, filename):
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / filename

    fields = [
        "host", "host_status", "protocol", "port",
        "state", "service", "product", "version"
    ]

    with filepath.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    return filepath
