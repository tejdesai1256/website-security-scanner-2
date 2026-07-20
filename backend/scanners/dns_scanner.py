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

        # SPF (from TXT records you already fetched)
        spf_record = next((t for t in result["TXT"] if t.lower().startswith("v=spf1")), None)
        result["spf_record"] = spf_record
        result["has_spf"] = spf_record is not None

        # DMARC (separate lookup)
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{hostname}", "TXT")
            dmarc_txt = "".join(
                r.strings[0].decode() if isinstance(r.strings[0], bytes) else r.strings[0]
                for r in dmarc_answers
            )
            result["dmarc_record"] = dmarc_txt
            result["has_dmarc"] = True
        except Exception:
            result["dmarc_record"] = None
            result["has_dmarc"] = False

        return result

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }