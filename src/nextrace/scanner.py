
import shutil
import subprocess
import xml.etree.ElementTree as ET

def check_nmap():
    """Check whether Nmap is installed and accessible."""

    nmap_path = shutil.which("nmap")

    if not nmap_path:
        raise RuntimeError("Nmap is not installed or not in PATH.")

    return nmap_path


def get_nmap_version():
    """Retrieve the installed Nmap version."""

    nmap_path = check_nmap()

    result = subprocess.run(
        [nmap_path, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True
    )

    return result.stdout.splitlines()[0]


def run_local_scan():
    """Perform a basic scan against the local machine."""

    nmap_path = check_nmap()

    result = subprocess.run(
        [
            nmap_path,
            "-sT",
            "-F",
            "-oX",
            "-",
            "127.0.0.1"
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True
    )

    return result.stdout


def parse_scan_results(xml_output):
    """Extract host, port, state and service information from Nmap XML."""

    root = ET.fromstring(xml_output)
    results = []

    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr") if address is not None else "Unknown"

        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")

            results.append({
                "host": ip,
                "protocol": port.get("protocol"),
                "port": int(port.get("portid")),
                "state": state.get("state") if state is not None else "unknown",
                "service": (
                    service.get("name") if service is not None else "unknown"
                ),
                "version": (
                    service.get("version", "unknown")
                    if service is not None else "unknown"
                )
            })

    return results



if __name__ == "__main__":
    print("[+] Nmap:", get_nmap_version())

    xml_output = run_local_scan()
    results = parse_scan_results(xml_output)

    print(f"\n[+] Parsed {len(results)} port records")

    for item in results:
        print(item)
