import socket
from urllib.parse import urlparse

# Common ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-ALT"
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

                open_ports.append({
                    "port": port,
                    "service": service,
                    "status": "OPEN"
                })

            sock.close()

        # =========================
        # RISK LEVEL
        # =========================

        vulnerable_ports = []

        risky_ports = [21, 23, 25, 3306]

        for port_data in open_ports:

            if port_data["port"] in risky_ports:

                vulnerable_ports.append(
                    port_data["port"]
                )

        # =========================
        # RESPONSE
        # =========================

        RISK_NOTES = {
            21: "FTP transmits credentials in plain text — prefer SFTP/FTPS.",
            23: "Telnet is unencrypted remote access — should never be exposed publicly.",
            25: "Open SMTP can be abused as an open relay for spam.",
            3306: "Public MySQL access is a common breach vector — restrict to internal only."
        }

        return {
            "success": True,
            "hostname": hostname,
            "ip_address": ip_address,
            "total_open_ports": len(open_ports),
            "open_ports": open_ports,
            "vulnerable_ports": vulnerable_ports,
            "risk_notes": {p: RISK_NOTES.get(p, "") for p in vulnerable_ports}
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

        # additional button added below this