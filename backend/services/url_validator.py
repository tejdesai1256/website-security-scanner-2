import socket
import ipaddress
from urllib.parse import urlparse


def validate_public_url(url: str) -> tuple[bool, str, str]:
    """
    Parses the URL, resolves hostname to an IP address, and validates
    that the target host is a public IP address. Rejects private, loopback,
    link-local, multicast, reserved, unspecified IPs and cloud metadata addresses.

    Returns:
        (True, resolved_ip, "") if IP is public
        (False, "", reason_string) if hostname cannot be resolved or IP is non-public
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "", "Invalid URL: missing hostname"
    except Exception as e:
        return False, "", f"Invalid URL format: {str(e)}"

    # Check if hostname is an IP address literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        resolved_ip = str(ip_obj)
    except ValueError:
        # Resolve domain name to IP via socket.gethostbyname
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
        except socket.gaierror:
            return False, "", "Could not resolve hostname"
        except Exception as e:
            return False, "", f"DNS resolution error: {str(e)}"

    # Reject standard non-public IP ranges
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False, "", f"Target host resolves to a non-public IP address ({resolved_ip})"

    # Explicitly reject cloud metadata (169.254.169.254), IPv6 loopback (::1), and fd00::/8
    ip_str = str(ip_obj)
    if ip_str == "169.254.169.254" or ip_str == "::1":
        return False, "", f"Target host resolves to a restricted IP address ({resolved_ip})"

    try:
        fd00_net = ipaddress.ip_network("fd00::/8")
        if ip_obj in fd00_net:
            return False, "", f"Target host resolves to a restricted network ({resolved_ip})"
    except Exception:
        pass

    return True, resolved_ip, ""
