from urllib.parse import urlparse
from datetime import datetime
import socket

try:
    import whois
except ImportError:
    try:
        from python_whois import whois
    except ImportError:
        whois = None

def scan_whois(url):
    try:
        # Check if whois module is available
        if whois is None:
            return _error_response("WHOIS module not installed. Install: pip install python-whois")
        
        # Normalize URL - add scheme if missing
        if not url.startswith(('http://', 'https://', '//', 'ftp://')):
            url = f"https://{url}"
        
        # Parse hostname
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.path.split('/')[0]
        
        if not hostname or len(hostname) == 0:
            return _error_response("Invalid hostname")

        # Remove www prefix if present
        if hostname.startswith("www."):
            hostname = hostname[4:]

        try:
            # Query WHOIS database
            domain = whois.whois(hostname)
        except socket.timeout:
            return _error_response("WHOIS query timeout")
        except Exception as query_error:
            return _error_response(f"WHOIS lookup failed: {str(query_error)}")

        # Safe attribute extraction
        creation = _get_attr(domain, 'creation_date')
        expiration = _get_attr(domain, 'expiration_date')
        updated = _get_attr(domain, 'updated_date')
        registrar = _get_attr(domain, 'registrar')
        name_servers = _get_attr(domain, 'name_servers')
        status = _get_attr(domain, 'status')
        emails = _get_attr(domain, 'emails')

        # Handle list returns
        if isinstance(creation, list) and creation:
            creation = creation[0]
        if isinstance(expiration, list) and expiration:
            expiration = expiration[0]
        if isinstance(updated, list) and updated:
            updated = updated[0]

        # Calculate domain age
        domain_age = None
        if creation:
            try:
                domain_age = (datetime.now() - creation).days
            except:
                domain_age = None

        return {
            "success": True,
            "domain": hostname,
            "registrar": str(registrar) if registrar else None,
            "creation_date": str(creation) if creation else None,
            "expiration_date": str(expiration) if expiration else None,
            "updated_date": str(updated) if updated else None,
            "domain_age_days": domain_age,
            "name_servers": name_servers if isinstance(name_servers, list) else (
                [name_servers] if name_servers else []
            ),
            "status": status if isinstance(status, list) else (
                [status] if status else []
            ),
            "emails": emails if isinstance(emails, list) else (
                [emails] if emails else []
            )
        }

    except Exception as e:
        return _error_response(str(e))

def _get_attr(obj, attr):
    """Safely get attribute from object"""
    try:
        return getattr(obj, attr, None)
    except:
        return None

def _error_response(error_msg):
    """Return error response with default values"""
    return {
        "success": False,
        "error": error_msg,
        "domain": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "domain_age_days": None,
        "name_servers": [],
        "status": [],
        "emails": []
        }