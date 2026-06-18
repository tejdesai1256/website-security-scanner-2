import socket
import dns.resolver
from urllib.parse import urlparse


def scan_dns(url):

    try:

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        hostname = urlparse(url).hostname

        result = {
            "success": True,
            "hostname": hostname
        }

        # IP Address
        try:
            result["ip_address"] = socket.gethostbyname(hostname)
        except:
            result["ip_address"] = "Not Found"

        # A Records
        try:
            answers = dns.resolver.resolve(hostname, "A")
            result["A"] = [str(r) for r in answers]
        except:
            result["A"] = []

        # MX Records
        try:
            answers = dns.resolver.resolve(hostname, "MX")
            result["MX"] = [str(r.exchange) for r in answers]
        except:
            result["MX"] = []

        # NS Records
        try:
            answers = dns.resolver.resolve(hostname, "NS")
            result["NS"] = [str(r.target) for r in answers]
        except:
            result["NS"] = []

        # TXT Records
        try:
            answers = dns.resolver.resolve(hostname, "TXT")
            result["TXT"] = [
                "".join(
                    txt.decode() if isinstance(txt, bytes) else txt
                    for txt in r.strings
                )
                for r in answers
            ]
        except:
            result["TXT"] = []

        return result

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }