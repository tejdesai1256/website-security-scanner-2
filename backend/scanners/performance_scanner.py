import requests
import os

from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("PAGESPEED_API_KEY")

def scan_performance(url):

    try:

        api_url = (
            "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        )

        params = {
            "url": url,
            "key": API_KEY,
            "strategy": "mobile"
        }

        response = requests.get(
            api_url,
            params=params,
            timeout=20
        )

        data = response.json()

        lighthouse = data["lighthouseResult"]

        categories = lighthouse["categories"]

        audits = lighthouse["audits"]

        performance_score = (
            categories["performance"]["score"] * 100
        )

        opportunities = []
        for key in ["render-blocking-resources", "unused-css-rules", "uses-responsive-images", "offscreen-images", "unminified-css", "unminified-javascript"]:
            audit = audits.get(key)
            if audit and audit.get("score", 1) < 0.9:
                opportunities.append({
                    "title": audit.get("title"),
                    "potential_savings": audit.get("displayValue", "")
                })

        return {
            "success": True,
            "performance_score": performance_score,
            "first_contentful_paint":
                audits["first-contentful-paint"]["displayValue"],
            "largest_contentful_paint":
                audits["largest-contentful-paint"]["displayValue"],
            "speed_index":
                audits["speed-index"]["displayValue"],
            "total_blocking_time": audits.get("total-blocking-time", {}).get("displayValue", "0 ms"),
            "cumulative_layout_shift": audits.get("cumulative-layout-shift", {}).get("displayValue", "0"),
            "opportunities": opportunities
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }   