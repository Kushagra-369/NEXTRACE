
import shutil
import subprocess
import xml.etree.ElementTree as ET


def check_nmap():
    path = shutil.which("nmap")
    if not path:
        raise RuntimeError("Nmap is not installed.")
    return path


def get_nmap_version():
    result = subprocess.run(
        [check_nmap(), "--version"],
        capture_output=True, text=True, timeout=10, check=True
    )
    return result.stdout.splitlines()[0]


def validate_ports(ports):
    """Accept comma-separated ports and ranges, e.g. 22,80,443,8000-8100."""

    if not ports or not isinstance(ports, str):
        return False

    try:
        for part in ports.split(","):
            part = part.strip()

            if "-" in part:
                if part.count("-") != 1:
                    return False
                start, end = map(int, part.split("-"))
                if not (1 <= start <= end <= 65535):
                    return False
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    return False

        return True
    except ValueError:
        return False



from nextrace.discovery import validate_target

def run_scan(target, ports="1-1000"):
    if not validate_target(target):
        raise ValueError("Invalid target.")

    if not validate_ports(ports):
        raise ValueError("Invalid port specification.")

    result = subprocess.run(
        [
            check_nmap(),
            "-sT",
            "-sV",
            "-p",
            ports,
            "-oX",
            "-",
            target,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )

    return result.stdout

def discover_host(target):
    result = subprocess.run(
        [check_nmap(), "-sn", "-oX", "-", target],
        capture_output=True,
        text=True,
        timeout=60,
        check=True
    )

    root = ET.fromstring(result.stdout)
    host = root.find("host")

    if host is None:
        return {"target": target, "status": "not_found"}

    status = host.find("status")
    address = host.find("address")

    return {
        "target": target,
        "address": address.get("addr") if address is not None else target,
        "status": status.get("state") if status is not None else "unknown"
    }


def parse_scan_results(xml_output):
    root = ET.fromstring(xml_output)
    results = []

    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr") if address is not None else "Unknown"

        status = host.find("status")
        host_status = status.get("state") if status is not None else "unknown"

        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")

            results.append({
                "host": ip,
                "host_status": host_status,
                "protocol": port.get("protocol"),
                "port": int(port.get("portid")),
                "state": state.get("state") if state is not None else "unknown",
                "service": service.get("name") if service is not None else "unknown",
                "product": service.get("product", "unknown") if service is not None else "unknown",
                "version": service.get("version", "unknown") if service is not None else "unknown"
            })

    return results
