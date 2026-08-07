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


import requests
from requests.adapters import HTTPAdapter


class PinnedIPAdapter(HTTPAdapter):
    """
    Custom HTTPAdapter that overrides the connection target IP address while keeping
    the original request Host header and TLS SNI hostname. Prevents DNS rebinding TOCTOU gaps.
    """
    def __init__(self, pinned_ip: str, *args, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def get_connection(self, url, proxies=None):
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        pinned_url = f"{parsed.scheme}://{self.pinned_ip}:{port}"
        conn = super().get_connection(pinned_url, proxies=proxies)
        if parsed.scheme == "https":
            conn.assert_hostname = parsed.hostname
            conn.server_hostname = parsed.hostname
        return conn


def safe_request(method: str, url: str, pinned_ip: str = None, **kwargs) -> requests.Response:
    """
    Executes an HTTP request. When pinned_ip is provided, mounts PinnedIPAdapter to pin the socket connection IP.
    """
    if pinned_ip:
        session = requests.Session()
        adapter = PinnedIPAdapter(pinned_ip)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session.request(method, url, **kwargs)
    else:
        return requests.request(method, url, **kwargs)


def safe_get(url: str, pinned_ip: str = None, **kwargs) -> requests.Response:
    """
    Helper function to perform a GET request with optional IP pinning.
    """
    return safe_request("GET", url, pinned_ip=pinned_ip, **kwargs)

