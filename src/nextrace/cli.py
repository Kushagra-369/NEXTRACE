
import argparse
from nextrace.discovery import validate_target


def create_parser():
    parser = argparse.ArgumentParser(
        prog="nextrace",
        description="NEXTRACE - Automated Network Reconnaissance Tool"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="NEXTRACE 1.0.0"
    )

    parser.add_argument(
        "--target",
        type=str,
        help="IP address or hostname of an authorized target"
    )

    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm permission to assess this target"
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.target:
        if not args.authorized:
            parser.error("Authorization confirmation is required.")

        if not validate_target(args.target):
            parser.error("Invalid IP address or hostname.")

        print(f"[+] Valid target: {args.target}")
        print("[+] Authorization confirmed.")
        print("[*] Scanning functionality will be added next.")

    else:
        parser.print_help()
