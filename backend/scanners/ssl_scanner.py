import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def scan_ssl(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_name, tls_version, _ = ssock.cipher()
                
                # Example expiry format: 'Nov 17 00:00:00 2026 GMT'
                expiry_date = datetime.strptime(
                    cert['notAfter'],
                    '%b %d %H:%M:%S %Y %Z'
                )
                days_left = (expiry_date - datetime.now()).days

                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                san_domains = [entry[1] for entry in cert.get('subjectAltName', [])]
                is_self_signed = issuer.get('commonName') == subject.get('commonName')

                return {
                    "success": True,
                    "ssl_enabled": True,
                    "protocol_version": ssock.version(), # e.g. "TLSv1.3"
                    "cipher_suite": cipher_name, # e.g. "TLS_AES_256_GCM_SHA384"
                    "issued_date": cert.get('notBefore'),
                    "expiry_date": cert.get('notAfter'),
                    "days_left": days_left,
                    "issuer": issuer.get('organizationName', issuer.get('commonName', '-')),
                    "subject_common_name": subject.get('commonName', hostname),
                    "san_domains": san_domains,
                    "is_self_signed": is_self_signed,
                    "serial_number": cert.get('serialNumber')
                }

    except Exception as e:
        return {
            "success": False,
            "ssl_enabled": False,
            "error": str(e)
        }