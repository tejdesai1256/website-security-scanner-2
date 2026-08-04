import socket
from urllib.parse import urlparse

# Common ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-ALT"
}

# Port severity levels
PORT_SEVERITIES = {
    23: "CRITICAL",
    21: "HIGH",
    3306: "HIGH",
    25: "MEDIUM",
    110: "MEDIUM",
    143: "MEDIUM",
    22: "LOW",
    53: "LOW",
    80: "LOW",
    8080: "LOW",
    443: "INFO"
}

RISK_NOTES = {
    21: "FTP transmits credentials in plain text — prefer SFTP/FTPS.",
    22: "Public SSH access exposed — restrict access using firewall or key-based auth.",
    23: "Telnet is unencrypted remote access — should never be exposed publicly.",
    25: "Open SMTP can be abused as an open relay for spam.",
    53: "DNS service exposed publicly — ensure recursion controls are active.",
    80: "Unencrypted HTTP service exposed — enforce HTTPS redirection.",
    110: "POP3 transmits email and credentials in plaintext.",
    143: "IMAP transmits email and credentials in plaintext.",
    3306: "Public MySQL access is a common breach vector — restrict to internal only.",
    8080: "Alternative HTTP server port exposed — review application exposure."
}


def scan_ports(url):

    try:

        # =========================
        # EXTRACT HOSTNAME
        # =========================

        parsed_url = urlparse(url)

        hostname = parsed_url.hostname

        if not hostname:

            return {
                "success": False,
                "error": "Invalid hostname"
            }

        # =========================
        # RESOLVE IP
        # =========================

        ip_address = socket.gethostbyname(
            hostname
        )

        open_ports = []

        # =========================
        # PORT SCAN
        # =========================

        for port, service in COMMON_PORTS.items():

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(1)

            result = sock.connect_ex(
                (ip_address, port)
            )

            if result == 0:
                severity = PORT_SEVERITIES.get(port, "LOW")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "status": "OPEN",
                    "severity": severity,
                    "note": RISK_NOTES.get(port, "")
                })

            sock.close()

        # =========================
        # RISK LEVEL & COUNTS
        # =========================

        vulnerable_ports = []
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        risky_ports = [21, 23, 25, 110, 143, 3306]

        for port_data in open_ports:
            p_num = port_data["port"]
            sev = port_data["severity"].lower()
            if sev in counts:
                counts[sev] += 1

            if p_num in risky_ports:
                vulnerable_ports.append(p_num)

        # =========================
        # RESPONSE
        # =========================

        return {
            "success": True,
            "hostname": hostname,
            "ip_address": ip_address,
            "total_open_ports": len(open_ports),
            "open_ports": open_ports,
            "vulnerable_ports": vulnerable_ports,
            "vulnerability_counts": counts,
            "risk_notes": {p["port"]: p["note"] for p in open_ports if p["note"]}
        }

    except socket.gaierror:

        return {
            "success": False,
            "error": "Could not resolve hostname"
        }

    except socket.timeout:

        return {
            "success": False,
            "error": "Connection timed out"
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }