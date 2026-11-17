
from datetime import datetime, timezone
from pathlib import Path


REPORT_DIR = Path("reports")


def generate_report(target, results, filename):
    REPORT_DIR.mkdir(exist_ok=True)
    filepath = REPORT_DIR / filename

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    open_ports = [item for item in results if item["state"] == "open"]

    lines = [
        "# NEXTRACE Reconnaissance Report",
        "",
        f"- Target: `{target}`",
        f"- Generated: {timestamp}",
        "- Authorization: User-confirmed",
        "",
        "## Summary",
        f"- Total port records: {len(results)}",
        f"- Open ports: {len(open_ports)}",
        "",
        "## Scan Results",
        "| Host | Port | Protocol | State | Service | Product | Version |",
        "|---|---:|---|---|---|---|---|"
    ]

    for item in results:
        lines.append(
            f"| {item['host']} | {item['port']} | {item['protocol']} | "
            f"{item['state']} | {item['service']} | "
            f"{item['product']} | {item['version']} |"
        )

    lines.extend([
        "",
        "## Limitations",
        "- Results represent observations at scan time.",
        "- Unknown versions do not prove outdated software.",
        "- This report does not establish vulnerability or exploitability.",
        ""
    ])

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
