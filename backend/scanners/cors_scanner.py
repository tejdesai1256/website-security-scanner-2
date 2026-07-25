import requests

# A fake, clearly-nonexistent origin used to test whether the target
# reflects arbitrary origins back (the classic CORS misconfiguration).
FAKE_ORIGIN = "https://evil-attacker-test.com"

# Some servers specifically allow the literal string "null" as an origin,
# which real browsers send in certain contexts (sandboxed iframes, local
# files, some redirects) — attackers can trigger this deliberately.
NULL_ORIGIN = "null"

CORS_HEADER_INFO = {
    "Access-Control-Allow-Origin": "Tells the browser which origins may read the response.",
    "Access-Control-Allow-Credentials": "If 'true', cookies/auth headers are included in cross-origin requests.",
    "Access-Control-Allow-Methods": "HTTP methods allowed for cross-origin requests.",
    "Access-Control-Allow-Headers": "Custom headers allowed for cross-origin requests."
}


def _request_with_origin(url, origin, timeout=8):
    """Send a GET request with a spoofed Origin header and return the CORS-related response headers."""
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (Website-Security-Scanner CORS-Check)"
    }
    response = requests.get(url, headers=headers, timeout=timeout)
    return {
        "status_code": response.status_code,
        "acao": response.headers.get("Access-Control-Allow-Origin"),
        "acac": response.headers.get("Access-Control-Allow-Credentials"),
        "acam": response.headers.get("Access-Control-Allow-Methods"),
        "acah": response.headers.get("Access-Control-Allow-Headers"),
    }


def scan_cors(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        findings = []
        risk_level = "LOW"

        # TEST 1: Reflected arbitrary origin
        fake_result = _request_with_origin(url, FAKE_ORIGIN)
        acao = fake_result["acao"]
        acac = (fake_result["acac"] or "").lower() == "true"

        reflects_arbitrary_origin = acao == FAKE_ORIGIN
        wildcard_origin = acao == "*"

        if reflects_arbitrary_origin and acac:
            risk_level = "CRITICAL"
            findings.append({
                "issue": "Arbitrary origin reflected WITH credentials allowed",
                "detail": (
                    "The server echoes back any Origin header it receives and also sets "
                    "Access-Control-Allow-Credentials: true. This means any malicious website "
                    "can make authenticated, cookie-carrying requests to this site on behalf of "
                    "a logged-in visitor and read the response — a critical account/data takeover risk."
                ),
                "severity": "CRITICAL"
            })
        elif reflects_arbitrary_origin:
            risk_level = "HIGH"
            findings.append({
                "issue": "Arbitrary origin reflected",
                "detail": (
                    "The server reflects any Origin header back in Access-Control-Allow-Origin "
                    "instead of validating it against an allowlist. Any website can read non-credentialed "
                    "responses from this API, which can leak data not intended for public sharing."
                ),
                "severity": "HIGH"
            })
        elif wildcard_origin and acac:
            risk_level = "HIGH"
            findings.append({
                "issue": "Wildcard origin combined with credentials flag",
                "detail": (
                    "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is 'true'. "
                    "This combination is invalid per spec and browsers will block it, but it signals a "
                    "misconfigured CORS setup that should be corrected."
                ),
                "severity": "HIGH"
            })
        elif wildcard_origin:
            risk_level = "MEDIUM"
            findings.append({
                "issue": "Wildcard origin allowed",
                "detail": (
                    "Access-Control-Allow-Origin is set to '*', allowing any website to read "
                    "non-credentialed responses. This is safe only if the endpoint serves purely "
                    "public data with no sensitive information."
                ),
                "severity": "MEDIUM"
            })

        # TEST 2: Null origin allowed
        null_result = _request_with_origin(url, NULL_ORIGIN)
        if null_result["acao"] == "null":
            if risk_level not in ("CRITICAL",):
                risk_level = "HIGH" if risk_level in ("LOW", "MEDIUM") else risk_level
            findings.append({
                "issue": "'null' origin explicitly allowed",
                "detail": (
                    "The server sets Access-Control-Allow-Origin: null. Attackers can trigger requests "
                    "with a 'null' Origin using sandboxed iframes or crafted redirects, effectively "
                    "bypassing origin restrictions."
                ),
                "severity": "HIGH"
            })

        if not findings:
            findings.append({
                "issue": "No CORS misconfiguration detected",
                "detail": (
                    "The server did not reflect the test origin, did not use an unsafe wildcard/credentials "
                    "combination, and did not allow the 'null' origin."
                ),
                "severity": "INFO"
            })

        return {
            "success": True,
            "hostname": url,
            "risk_level": risk_level,
            "findings": findings,
            "raw_checks": {
                "fake_origin_test": fake_result,
                "null_origin_test": null_result
            },
            "cors_header_descriptions": CORS_HEADER_INFO
        }

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Connection error"}
    except Exception as e:
        return {"success": False, "error": str(e)}
