import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def scan_ssl(url):

    try:
        hostname = urlparse(url).hostname

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:

            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                cert = ssock.getpeercert()

                expiry_date = datetime.strptime(
                    cert['notAfter'],
                    '%b %d %H:%M:%S %Y %Z'
                )

                days_left = (expiry_date - datetime.now()).days

                return {
                    "success": True,
                    "ssl_enabled": True,
                    "expiry_date": cert['notAfter'],
                    "days_left": days_left
                }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }