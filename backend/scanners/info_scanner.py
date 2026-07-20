import socket
import requests
from urllib.parse import urlparse
from datetime import datetime

def get_rdap_info(domain):
    """
    Get domain registration info from RDAP.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            registrar = None
            created_date = None
            
            # Find registrar
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                registrar = prop[3]
                                break
                if registrar:
                    break
                    
            # Find created/registration date
            for event in data.get("events", []):
                action = event.get("eventAction", "").lower()
                if action == "registration" or action == "creation":
                    created_date = event.get("eventDate")
                    break
            
            if created_date:
                try:
                    # RDAP dates are usually ISO8601 like "1997-09-15T04:00:00Z"
                    date_part = created_date.split("T")[0]
                    dt = datetime.strptime(date_part, "%Y-%m-%d")
                    formatted_created = dt.strftime("%B %d, %Y")
                    age_years = datetime.now().year - dt.year
                    age_str = f"{formatted_created} ({age_years} years old)"
                except Exception:
                    age_str = created_date
            else:
                age_str = None
                
            return {
                "success": True,
                "registrar": registrar or "Unknown",
                "created": age_str or "Unknown",
                "raw_created": created_date
            }
    except Exception:
        pass
    return {"success": False}

def get_socket_whois_info(domain):
    """
    Fallback WHOIS lookup using raw sockets on TCP port 43.
    """
    def query_whois(dom, server):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((server, 43))
            s.send((dom + "\r\n").encode("utf-8"))
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            s.close()
            return resp.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    try:
        iana_res = query_whois(domain, "whois.iana.org")
        refer_server = None
        for line in iana_res.splitlines():
            if line.strip().lower().startswith("refer:"):
                refer_server = line.split(":", 1)[1].strip()
                break
        
        if not refer_server:
            tld = domain.split(".")[-1]
            refer_server = f"whois.nic.{tld}" if tld != "com" else "whois.verisign-grs.com"
            
        whois_res = query_whois(domain, refer_server)
        if not whois_res:
            whois_res = query_whois(domain, "whois.verisign-grs.com") # global fallback

        registrar = None
        created_date = None
        
        for line in whois_res.splitlines():
            line_strip = line.strip()
            line_lower = line_strip.lower()
            
            # Match registrar
            if not registrar:
                if line_lower.startswith("registrar:") or line_lower.startswith("sponsoring registrar:"):
                    parts = line_strip.split(":", 1)
                    if len(parts) > 1:
                        registrar = parts[1].strip()
            
            # Match created/creation date
            if not created_date:
                if any(k in line_lower for k in ["creation date:", "created:", "created on:", "registration date:", "registered:"]):
                    parts = line_strip.split(":", 1)
                    if len(parts) > 1:
                        created_date = parts[1].strip()
                    
        # Parse created date to format nicely if possible
        age_str = created_date
        if created_date:
            date_word = created_date.split()[0] if created_date.split() else created_date
            date_word = date_word.replace("T", " ").replace("Z", "").strip()
            for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%b-%Y", "%Y.%m.%d"):
                try:
                    dt = datetime.strptime(date_word.split()[0], fmt)
                    formatted_created = dt.strftime("%B %d, %Y")
                    age_years = datetime.now().year - dt.year
                    age_str = f"{formatted_created} ({age_years} years old)"
                    break
                except Exception:
                    pass
                    
        return {
            "success": True,
            "registrar": registrar or "Unknown",
            "created": age_str or "Unknown"
        }
    except Exception:
        return {"success": False}

def scan_info(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        hostname = urlparse(url).hostname
        if not hostname:
            return {"success": False, "error": "Invalid URL"}
            
        # Get IP address
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = "Unknown"
            
        # Geolocation
        country = "Unknown"
        isp = "Unknown"
        asn = "Unknown"
        
        if ip != "Unknown":
            try:
                geo_res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                if geo_res.get("status") == "success":
                    country = geo_res.get("country", "Unknown")
                    isp = geo_res.get("isp", "Unknown")
                    asn = geo_res.get("as", "Unknown")
            except Exception:
                pass
                
        # WHOIS / RDAP lookup (first try RDAP, then raw WHOIS)
        domain_parts = hostname.split('.')
        if len(domain_parts) > 2:
            registered_domain = ".".join(domain_parts[-2:])
        else:
            registered_domain = hostname
            
        whois_data = get_rdap_info(registered_domain)
        if not whois_data.get("success") or whois_data.get("registrar") == "Unknown":
            alt_whois = get_socket_whois_info(registered_domain)
            if alt_whois.get("success"):
                if whois_data.get("registrar") == "Unknown" and alt_whois.get("registrar") != "Unknown":
                    whois_data["registrar"] = alt_whois.get("registrar")
                if whois_data.get("created") == "Unknown" and alt_whois.get("created") != "Unknown":
                    whois_data["created"] = alt_whois.get("created")
            
        return {
            "success": True,
            "ip_address": ip,
            "country": country,
            "isp": isp,
            "asn": asn,
            "registrar": whois_data.get("registrar", "Unknown") if whois_data else "Unknown",
            "created": whois_data.get("created", "Unknown") if whois_data else "Unknown",
            "registered_domain": registered_domain
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
