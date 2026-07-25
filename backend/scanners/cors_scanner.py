import requests
from urllib.parse import urlparse, urljoin

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

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _escalate_risk(current_risk, new_risk):
    """Escalate risk level if new_risk is higher than current_risk."""
    if RISK_ORDER.get(new_risk, 0) > RISK_ORDER.get(current_risk, 0):
        return new_risk
    return current_risk


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
        "vary": response.headers.get("Vary"),
    }


def _build_remediation(findings):
    """Generate 2-4 actionable remediation tips based on triggered findings."""
    tips = []
    issues = [f["issue"].lower() for f in findings if f.get("severity") != "INFO"]

    if any("arbitrary origin reflected" in i or "wildcard origin" in i or "api endpoint" in i for i in issues):
        tips.append("Replace wildcard/reflected origins with an explicit allowlist of trusted domains.")

    if any("credentials" in i for i in issues):
        tips.append("Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.")

    if any("prefix/suffix" in i for i in issues):
        tips.append("Validate the Origin header with exact string equality, never substring/prefix matching.")

    if any("preflight" in i for i in issues):
        tips.append("Restrict allowed methods and headers in preflight responses to strictly required values.")

    if any("missing vary" in i for i in issues):
        tips.append("Add 'Vary: Origin' whenever Access-Control-Allow-Origin is set dynamically.")

    if any("multiple values" in i for i in issues):
        tips.append("Ensure Access-Control-Allow-Origin returns exactly one origin or '*' per response.")

    if any("'null' origin" in i for i in issues):
        tips.append("Avoid setting Access-Control-Allow-Origin: null as sandboxed frames and local files send null origins.")

    if not tips:
        tips.append("Maintain an explicit allowlist of trusted origins and audit CORS configurations across all endpoints.")

    return tips[:4]


def scan_cors(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        findings = []
        risk_level = "LOW"
        raw_checks = {}

        # TEST 1: Reflected arbitrary origin
        fake_result = _request_with_origin(url, FAKE_ORIGIN)
        raw_checks["fake_origin_test"] = fake_result

        acao = fake_result["acao"]
        acac = (fake_result["acac"] or "").lower() == "true"

        reflects_arbitrary_origin = acao == FAKE_ORIGIN
        wildcard_origin = acao == "*"

        if reflects_arbitrary_origin and acac:
            risk_level = _escalate_risk(risk_level, "CRITICAL")
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
            risk_level = _escalate_risk(risk_level, "HIGH")
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
            risk_level = _escalate_risk(risk_level, "HIGH")
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
            risk_level = _escalate_risk(risk_level, "MEDIUM")
            findings.append({
                "issue": "Wildcard origin allowed",
                "detail": (
                    "Access-Control-Allow-Origin is set to '*', allowing any website to read "
                    "non-credentialed responses. This is safe only if the endpoint serves purely "
                    "public data with no sensitive information."
                ),
                "severity": "MEDIUM"
            })

        # CHECK 3: Vary: Origin Header Check (Cache Poisoning Risk)
        if reflects_arbitrary_origin:
            try:
                vary_hdr = fake_result.get("vary") or ""
                vary_list = [v.strip().lower() for v in vary_hdr.split(",")]
                if "origin" not in vary_list:
                    findings.append({
                        "issue": "Missing Vary: Origin header alongside dynamic CORS reflection",
                        "detail": (
                            "The server dynamically reflects the Origin header in Access-Control-Allow-Origin "
                            "without including 'Vary: Origin'. Intermediate caches (CDNs, proxies) may cache "
                            "this response and serve it to other origins, leading to cache poisoning and data leakage."
                        ),
                        "severity": "MEDIUM"
                    })
                    risk_level = _escalate_risk(risk_level, "MEDIUM")
            except Exception:
                pass

        # CHECK 4: Multiple-Origin Value Test (Malformed Header Check)
        try:
            if acao and "," in acao:
                findings.append({
                    "issue": "Multiple values in Access-Control-Allow-Origin header",
                    "detail": (
                        "The Access-Control-Allow-Origin header contains multiple comma-separated values. "
                        "This is invalid per the CORS spec, which requires a single origin or '*'."
                    ),
                    "severity": "MEDIUM"
                })
                risk_level = _escalate_risk(risk_level, "MEDIUM")
        except Exception:
            pass

        # TEST 2: Null origin allowed
        null_result = _request_with_origin(url, NULL_ORIGIN)
        raw_checks["null_origin_test"] = null_result

        if null_result["acao"] == "null":
            risk_level = _escalate_risk(risk_level, "HIGH")
            findings.append({
                "issue": "'null' origin explicitly allowed",
                "detail": (
                    "The server sets Access-Control-Allow-Origin: null. Attackers can trigger requests "
                    "with a 'null' Origin using sandboxed iframes or crafted redirects, effectively "
                    "bypassing origin restrictions."
                ),
                "severity": "HIGH"
            })

        # CHECK 1: Subdomain / Prefix-Suffix Bypass Test
        try:
            parsed_url = urlparse(url)
            real_domain = parsed_url.netloc.split(":")[0]
            if real_domain:
                domain_no_dots = real_domain.replace(".", "")
                crafted_origins = [
                    f"https://evil-{real_domain}",
                    f"https://{real_domain}.attacker.com",
                    f"https://attacker{real_domain}",
                    f"https://{domain_no_dots}.com"
                ]
                bypass_results = []
                bypass_detected = False
                for test_origin in crafted_origins:
                    res = _request_with_origin(url, test_origin, timeout=4)
                    reflected = res.get("acao") == test_origin
                    bypass_results.append({
                        "origin": test_origin,
                        "reflected": reflected,
                        "status_code": res.get("status_code")
                    })
                    if reflected and not bypass_detected:
                        bypass_detected = True
                        findings.append({
                            "issue": "Origin validation bypass via prefix/suffix matching",
                            "detail": (
                                "The server's origin check appears to use substring matching instead of an exact allowlist. "
                                f"Crafted origin '{test_origin}' was reflected back in Access-Control-Allow-Origin, "
                                "allowing an attacker to register lookalike domains to bypass validation."
                            ),
                            "severity": "CRITICAL"
                        })
                        risk_level = _escalate_risk(risk_level, "CRITICAL")
                raw_checks["subdomain_bypass_tests"] = bypass_results
        except Exception:
            pass

        # CHECK 2: Preflight (OPTIONS) Request Test
        try:
            preflight_headers = {
                "Origin": FAKE_ORIGIN,
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
                "User-Agent": "Mozilla/5.0 (Website-Security-Scanner CORS-Check)"
            }
            options_resp = requests.options(url, headers=preflight_headers, timeout=8)
            pf_acao = options_resp.headers.get("Access-Control-Allow-Origin")
            pf_acac = options_resp.headers.get("Access-Control-Allow-Credentials")
            pf_acam = options_resp.headers.get("Access-Control-Allow-Methods") or ""
            pf_acah = options_resp.headers.get("Access-Control-Allow-Headers") or ""

            preflight_result = {
                "status_code": options_resp.status_code,
                "acao": pf_acao,
                "acac": pf_acac,
                "acam": pf_acam,
                "acah": pf_acah,
            }
            raw_checks["preflight_test"] = preflight_result

            allowed_methods = [m.strip().upper() for m in pf_acam.split(",")]
            allowed_headers = [h.strip().lower() for h in pf_acah.split(",")]

            has_sensitive_method = any(m in allowed_methods for m in ["DELETE", "PUT", "PATCH", "*"])
            has_auth_header = any(h in allowed_headers for h in ["authorization", "*"])
            origin_reflected = pf_acao == FAKE_ORIGIN or pf_acao == "*"

            if origin_reflected and has_sensitive_method and has_auth_header:
                findings.append({
                    "issue": "Preflight allows sensitive methods/headers for untrusted origin",
                    "detail": (
                        "The preflight OPTIONS response allows sensitive HTTP methods (e.g. DELETE/PUT) "
                        "and Authorization headers for an untrusted origin. An attacker's website could issue "
                        "destructive authenticated cross-origin requests."
                    ),
                    "severity": "HIGH"
                })
                risk_level = _escalate_risk(risk_level, "HIGH")
        except Exception:
            pass

        # CHECK 5: Additional Common API Paths Test
        try:
            additional_paths = ["/api/", "/api/v1/", "/login"]
            paths_results = []
            endpoint_misconfig_found = False

            for path in additional_paths:
                try:
                    target_path_url = urljoin(url, path)
                    res = _request_with_origin(target_path_url, FAKE_ORIGIN, timeout=4)
                    status_code = res.get("status_code", 0)
                    is_reflected = (res.get("acao") == FAKE_ORIGIN) if status_code != 404 else False
                    paths_results.append({"path": path, "reflected": is_reflected})

                    if is_reflected and not reflects_arbitrary_origin and not endpoint_misconfig_found:
                        endpoint_misconfig_found = True
                        findings.append({
                            "issue": f"CORS misconfiguration on API endpoint {path} not present on root",
                            "detail": (
                                f"The endpoint '{path}' reflects the untrusted origin even though the root URL does not. "
                                "Misconfigurations are often isolated to specific API routes developers forgot to secure."
                            ),
                            "severity": "HIGH"
                        })
                        risk_level = _escalate_risk(risk_level, "HIGH")
                except Exception:
                    continue
            raw_checks["additional_paths_tested"] = paths_results
        except Exception:
            pass

        if not findings:
            findings.append({
                "issue": "No CORS misconfiguration detected",
                "detail": (
                    "The server did not reflect test origins, did not use unsafe wildcard configurations, "
                    "and properly validated origins across preflight and subpath checks."
                ),
                "severity": "INFO"
            })

        remediation = _build_remediation(findings)

        return {
            "success": True,
            "hostname": url,
            "risk_level": risk_level,
            "findings": findings,
            "raw_checks": raw_checks,
            "cors_header_descriptions": CORS_HEADER_INFO,
            "remediation": remediation
        }

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Connection error"}
    except Exception as e:
        return {"success": False, "error": str(e)}
