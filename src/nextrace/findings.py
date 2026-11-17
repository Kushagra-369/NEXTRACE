
import ipaddress


DATABASE_SERVICES = {
    "postgresql", "mysql", "mariadb", "mongodb",
    "redis", "ms-sql-s", "oracle", "memcached",
}

CLEARTEXT_SERVICES = {
    "ftp", "telnet", "rlogin", "rsh",
}

REMOTE_ACCESS_SERVICES = {
    "ssh", "ms-wbt-server", "rdp",
}


def is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def generate_findings(results):
    findings = []

    for item in results:
        if item.get("state") != "open":
            continue

        service = (item.get("service") or "unknown").lower()
        host = item.get("host", "unknown")
        port = item.get("port", "unknown")
        loopback = is_loopback(host)

        base = {
            "host": host,
            "port": port,
            "service": service,
        }

        if service in CLEARTEXT_SERVICES:
            findings.append({
                **base,
                "id": "plaintext_protocol",
                "severity": "medium",
                "title": "Potentially unencrypted protocol",
                "description": (
                    f"{service} was identified on an open port. "
                    "This protocol may transmit credentials or data "
                    "without encryption."
                ),
                "recommendation": (
                    "Verify the service configuration and prefer "
                    "an encrypted alternative where appropriate."
                ),
            })

        elif service == "http" and not loopback:
            findings.append({
                **base,
                "id": "unencrypted_http",
                "severity": "low",
                "title": "HTTP service observed",
                "description": (
                    "HTTP was identified on a non-loopback address. "
                    "The scan does not establish whether sensitive "
                    "traffic is transmitted."
                ),
                "recommendation": (
                    "Verify whether HTTPS is enforced and sensitive "
                    "traffic is protected."
                ),
            })

        elif service in DATABASE_SERVICES and not loopback:
            findings.append({
                **base,
                "id": "network_exposed_database",
                "severity": "medium",
                "title": "Network-accessible database service",
                "description": (
                    f"{service} is listening on a non-loopback "
                    "address. Exposure alone does not prove "
                    "unauthorized access."
                ),
                "recommendation": (
                    "Verify network restrictions, authentication "
                    "and firewall rules."
                ),
            })

        elif service in REMOTE_ACCESS_SERVICES and not loopback:
            findings.append({
                **base,
                "id": "remote_access_service",
                "severity": "low",
                "title": "Remote access service exposed",
                "description": (
                    f"{service} is listening on a non-loopback "
                    "address. This is an exposure observation, "
                    "not proof of a vulnerability."
                ),
                "recommendation": (
                    "Verify access controls, authentication and "
                    "network restrictions."
                ),
            })

        else:
            findings.append({
                **base,
                "id": "open_service_observed",
                "severity": "informational",
                "title": "Open service observed",
                "description": (
                    f"An open {service} service was detected. "
                    "No vulnerability is inferred from this result."
                ),
                "recommendation": (
                    "Confirm that this service is expected and "
                    "appropriately configured."
                ),
            })

    return findings
