import builtwith
import requests
from bs4 import BeautifulSoup

def scan_technology(url):
    try:
        technologies = builtwith.parse(url)
        additional_detection = {}

        try:
            resp = requests.get(
                url,
                timeout=8,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            generator_tag = soup.find("meta", attrs={"name": "generator"})
            additional_detection = {
                "server": resp.headers.get("Server"),
                "powered_by": resp.headers.get("X-Powered-By"),
                "generator": generator_tag.get("content") if generator_tag else None,
                "cookies_detected": list(resp.cookies.keys())
            }
        except Exception:
            pass

        return {
            "success": True,
            "technologies": technologies,
            "additional_detection": additional_detection
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }