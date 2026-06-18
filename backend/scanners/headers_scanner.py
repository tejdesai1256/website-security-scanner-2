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

        return {
            "success": True,
            "headers": security_headers
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }