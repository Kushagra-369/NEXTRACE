
import argparse
import re
from datetime import datetime, timezone

from nextrace.discovery import validate_target
from nextrace.scanner import (
    run_scan, parse_scan_results, validate_ports
)
from nextrace.exporter import export_json, export_csv
from nextrace.reporter import generate_report


def create_parser():
    parser = argparse.ArgumentParser(
        prog="nextrace",
        description="Automated Network Reconnaissance Tool"
    )

    parser.add_argument("--version", action="version", version="NEXTRACE 1.0.0")
    parser.add_argument(
        "--target", nargs="+", required=True,
        help="One or more authorized IP addresses or hostnames"
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
        parser.error("Invalid port range. Example: 22,80,443,8000-8100")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    for target in args.target:
        slug = re.sub(r"[^a-zA-Z0-9_-]", "_", target)

        print(f"\n[+] Target: {target}")
        print("[+] Starting Nmap scan...")

        try:
            xml_output = run_scan(target, args.ports)
            results = parse_scan_results(xml_output)

            json_file = export_json(results, f"{slug}_{timestamp}.json")
            csv_file = export_csv(results, f"{slug}_{timestamp}.csv")
            report_file = generate_report(
                target, results, f"{slug}_{timestamp}.md"
            )

            print(f"[+] Port records: {len(results)}")
            print(f"[+] JSON: {json_file}")
            print(f"[+] CSV: {csv_file}")
            print(f"[+] Report: {report_file}")

        except (RuntimeError, OSError, ValueError,
                TimeoutError, Exception) as error:
            print(f"[-] Scan failed for {target}: {error}")
            continue


if __name__ == "__main__":
    main()
