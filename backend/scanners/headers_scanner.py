import requests

def scan_headers(url):

    try:
        response = requests.get(url, timeout=5)

        headers = response.headers

        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy")
        }

        HEADER_INFO = {
            "Content-Security-Policy": "Prevents XSS by controlling which resources can be loaded.",
            "Strict-Transport-Security": "Forces browsers to only use HTTPS for this site.",
            "X-Frame-Options": "Prevents clickjacking via hidden iframes.",
            "X-Content-Type-Options": "Stops browsers from MIME-sniffing files as something else.",
            "Referrer-Policy": "Controls how much referrer info is leaked to other sites."
        }

        missing_headers = [name for name, value in security_headers.items() if not value]

        return {
            "success": True,
            "headers": security_headers,
            "missing_headers": missing_headers,
            "header_descriptions": HEADER_INFO
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }