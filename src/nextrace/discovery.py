
import ipaddress
import re


def validate_target(target: str) -> bool:
    """Validate an IPv4, IPv6, or hostname without contacting it."""

    if not target or target != target.strip():
        return False

    # Check IP addresses first
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Reject malformed dotted numeric IP addresses
    if re.fullmatch(r"[0-9.]+", target):
        return False

    # Validate hostname syntax
    hostname = target.rstrip(".")

    if not hostname or len(hostname) > 253:
        return False

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                label
            )
        ):
            return False

    return True
