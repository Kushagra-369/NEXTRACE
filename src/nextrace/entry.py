import json
import sys
from pathlib import Path


VERSION = "1.0.0"


def show_help():
    print(f"""
NEXTRACE {VERSION} — Network Reconnaissance Tool

Usage:
  nextrace scan --target IP_OR_HOST --authorized [--ports PORTS]
  nextrace doctor
  nextrace history
  nextrace --version
  nextrace --help

Examples:
  nextrace scan --target 127.0.0.1 --ports 5432,8000 --authorized
  nextrace doctor
  nextrace history

Only scan systems you own or are explicitly authorized to assess.
""")


def show_history():
    history_dir = Path("history")

    if not history_dir.is_dir():
        print("[!] No history directory found.")
        return

    snapshots = sorted(
        history_dir.glob("*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not snapshots:
        print("[+] No scan history available.")
        return

    print("\nNEXTRACE SCAN HISTORY")
    print("=" * 65)

    for path in snapshots:
        try:
            with path.open(encoding="utf-8") as file:
                data = json.load(file)

            print(
                f"Target: {data.get('target', 'unknown')} | "
                f"Snapshot: {path.name} | "
                f"Ports: {len(data.get('ports', []))}"
            )
        except (OSError, json.JSONDecodeError) as error:
            print(f"[!] Could not read {path.name}: {error}")


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h"):
        show_help()
        return

    if args[0] == "--version":
        print(f"NEXTRACE {VERSION}")
        return

    if args[0] == "scan":
        from nextrace.cli import main as scan_main

        sys.argv = [sys.argv[0], *args[1:]]
        scan_main()
        return

    if args[0] == "doctor":
        from nextrace.doctor import main as doctor_main
        doctor_main()
        return

    if args[0] == "history":
        show_history()
        return

    print(f"[!] Unknown command: {args[0]}")
    show_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
