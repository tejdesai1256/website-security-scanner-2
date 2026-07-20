import requests

url = "http://localhost:8000/chat"
payload = {
    "message": "How do I fix the missing CSP header?",
    "scan_results": {
        "website": "example.com",
        "summary": {
            "security_score": 62,
            "risk_level": "MEDIUM",
            "recommendations": ["Enable SSL certificate", "3 security headers missing"]
        },
        "scans": {
            "ssl": {"ssl_enabled": False},
            "headers": {"missing_headers": ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]},
            "ports": {"open_ports": []},
            "performance": {"performance_score": 85}
        }
    }
}

try:
    response = requests.post(url, json=payload)
    print("Status Code:", response.status_code)
    if response.status_code == 200:
        bot_response = response.json()["response"]
        with open("test_output.txt", "w", encoding="utf-8") as f:
            f.write(bot_response)
        print("Success! Saved response to test_output.txt")
    else:
        print("Error details:", response.text)
except Exception as e:
    print("Connection Error:", str(e))
