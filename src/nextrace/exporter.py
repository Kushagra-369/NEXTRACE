
import csv
import json
from pathlib import Path

OUTPUT_DIR = Path("output")

FIELDS = [
    "host", "hostname", "mac_address", "os_guess",
    "host_status", "protocol", "port", "state",
    "service", "product", "version", "extra_info",
    "tunnel", "service_method", "service_confidence", "cpe"
]



def export_json(results, filename, host_info=None, findings=None):
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / filename

    data = {
        "hosts": host_info or [],
        "ports": results,
        "findings": findings or [],
        "summary": {
            "total_ports": len(results),
            "open_ports": sum(
                1 for item in results if item.get("state") == "open"
            ),
            "total_findings": len(findings or []),
        },
    }

    with filepath.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return filepath



def export_csv(results, filename):
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / filename

    with filepath.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file, fieldnames=FIELDS, extrasaction="ignore"
        )
        writer.writeheader()

        for item in results:
            row = item.copy()
            if isinstance(row.get("cpe"), list):
                row["cpe"] = "; ".join(row["cpe"])
            writer.writerow(row)

    return filepath
