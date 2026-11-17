
from datetime import datetime, timezone
from pathlib import Path

REPORT_DIR = Path("reports")



def generate_report(target, results, filename, host_info=None, findings=None):
    REPORT_DIR.mkdir(exist_ok=True)
    filepath = REPORT_DIR / filename

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    findings = findings or []
    open_ports = [
        item for item in results if item.get("state") == "open"
    ]

    severity_order = ["high", "medium", "low", "informational"]

    lines = [
        "# NEXTRACE Reconnaissance Report",
        "",
        f"- Target: `{target}`",
        f"- Generated: {timestamp}",
        "- Authorization confirmation: provided by operator",
        "",
        "## Host Information",
    ]

    for index, host in enumerate(host_info or [], start=1):
        lines.extend([
            f"### Host {index}",
            f"- Status: {host['status']}",
            f"- Hostnames: {', '.join(host['hostnames']) or 'Unknown'}",
        ])

        for address in host["addresses"]:
            lines.append(
                f"- Address: {address['address']} "
                f"({address['type']}, vendor: {address['vendor']})"
            )

        if host["os_guesses"]:
            for guess in host["os_guesses"]:
                lines.append(
                    f"- OS guess: {guess['name']} "
                    f"(accuracy: {guess['accuracy']}%)"
                )
        else:
            lines.append("- OS guess: Unknown")

    lines.extend([
        "",
        "## Enumeration Summary",
        f"- Total port records: {len(results)}",
        f"- Open ports: {len(open_ports)}",
        f"- Total findings: {len(findings)}",
        "",
        "## Risk Summary",
    ])

    for severity in severity_order:
        count = sum(
            1 for finding in findings
            if finding["severity"] == severity
        )
        lines.append(f"- {severity.title()}: {count}")

    lines.extend([
        "",
        "## Security Findings",
    ])

    if not findings:
        lines.append("No findings generated.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"### {index}. {finding['title']}",
                f"- Severity: {finding['severity'].upper()}",
                f"- Finding ID: `{finding['id']}`",
                f"- Host: {finding['host']}",
                f"- Port: {finding['port']}",
                f"- Service: {finding['service']}",
                f"- Evidence: {finding['description']}",
                f"- Recommendation: {finding['recommendation']}",
                "",
            ])

    lines.extend([
        "",
        "## Scan Results",
        "| Host | Port | Protocol | State | Service | Product | Version |",
        "|---|---:|---|---|---|---|---|",
    ])

    for item in results:
        lines.append(
            f"| {item['host']} | {item['port']} | "
            f"{item['protocol']} | {item['state']} | "
            f"{item['service']} | {item['product']} | "
            f"{item['version']} |"
        )

    lines.extend([
        "",
        "## Limitations",
        "- Results represent observations at scan time.",
        "- Findings are rule-based observations, not confirmed vulnerabilities.",
        "- Service identification may be incomplete.",
        "- OS guesses may be unavailable or inaccurate.",
        "- Open ports do not automatically indicate vulnerabilities.",
        "- Manual validation is required before remediation decisions.",
        "",
    ])

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
