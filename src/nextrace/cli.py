
import argparse
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from nextrace.discovery import validate_target
from nextrace.scanner import (
    run_scan,
    discover_host,
    parse_scan_results,
    parse_host_info,
    validate_ports,
)
from nextrace.exporter import export_json, export_csv
from nextrace.reporter import generate_report
from nextrace.findings import generate_findings
from nextrace.history import (
    save_snapshot,
    load_previous_snapshot,
    compare_scans,
)
from nextrace.reporter import generate_change_report

def create_parser():
    parser = argparse.ArgumentParser(
        prog="nextrace",
        description="Automated Network Reconnaissance Tool"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="NEXTRACE 1.0.0"
    )
    parser.add_argument(
        "--target",
        nargs="+",
        required=True,
        help="Authorized IP addresses or hostnames"
    )
    parser.add_argument("--ports", default="1-1000")
    parser.add_argument("--authorized", action="store_true")
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not args.authorized:
        parser.error("Authorization confirmation required.")

    for target in args.target:
        if not validate_target(target):
            parser.error(f"Invalid target: {target}")

    if not validate_ports(args.ports):
        parser.error("Invalid port range.")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    for target in args.target:
        slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)

        print(f"\n[+] Target: {target}")

        # Host discovery
        try:
            host_info = discover_host(target)
            status = host_info["status"]
            print(f"[+] Host status: {status}")

            if status == "down":
                print(
                    "[!] Discovery reports host down. "
                    "Continuing scan because discovery probes "
                    "can be filtered."
                )

        except (
            RuntimeError,
            OSError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            ET.ParseError,
        ) as error:
            print(f"[!] Host discovery failed: {error}")
            print("[+] Continuing with port scan...")

        # Port and service scan
        try:
            print("[+] Starting Nmap scan...")

            xml_output = run_scan(target, args.ports)
            results = parse_scan_results(xml_output)
            host_metadata = parse_host_info(xml_output)
            findings = generate_findings(results)

            current_data = {
                "hosts": host_metadata,
                "ports": results,
                "findings": findings,
            }

            previous = load_previous_snapshot(target, slug)

            if previous:
                changes = compare_scans(previous, current_data)
                print("[+] Previous scan found. Comparing results...")
            else:
                changes = None
                print("[+] No previous scan found. Creating baseline.")

            history_file = save_snapshot(
                target,
                current_data,
                f"{slug}_{timestamp}.json"
            )

            json_file = export_json(
                results,
                f"{slug}_{timestamp}.json",
                host_metadata,
                findings
            )
            csv_file = export_csv(
                results, f"{slug}_{timestamp}.csv"
            )
            report_file = generate_report(
                target,
                results,
                f"{slug}_{timestamp}.md",
                host_metadata,
                findings
            )

            if changes is not None:
                change_file = generate_change_report(
                    target,
                    changes,
                    f"{slug}_{timestamp}_changes.md"
                )

                print(
                    "[+] Changes: "
                    f"Opened={len(changes['newly_opened'])}, "
                    f"Closed={len(changes['closed'])}, "
                    f"Service changes={len(changes['service_changed'])}, "
                    f"No longer observed={len(changes['no_longer_observed'])}"
                )

                print(f"[+] Comparison report: {change_file}")

            print(f"[+] History snapshot: {history_file}")

            print(f"[+] Port records: {len(results)}")
            print(f"[+] Security findings: {len(findings)}")

            for finding in findings:
                print(
                    f"    [{finding['severity'].upper()}] "
                    f"{finding['title']} "
                    f"(port {finding['port']})"
                )
            print(f"[+] JSON: {json_file}")
            print(f"[+] CSV: {csv_file}")
            print(f"[+] Report: {report_file}")

        except (
            RuntimeError,
            OSError,
            ValueError,
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            ET.ParseError,
        ) as error:
            print(f"[-] Scan failed for {target}: {error}")
            continue


if __name__ == "__main__":
    main()
