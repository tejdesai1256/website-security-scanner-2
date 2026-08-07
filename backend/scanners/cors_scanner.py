import logging
import requests
import re
import json
from urllib.parse import urlparse, urljoin
from services.url_validator import safe_get, safe_request

# Set up logging for CORS scanner error handling and diagnostics
logger = logging.getLogger("cors_scanner")

# Default attacker origin for testing
DEFAULT_ATTACKER_ORIGIN = "https://evil-attacker-test.com"
SECONDARY_ATTACKER_ORIGIN = "https://another-attacker-test.com"
NULL_ORIGIN = "null"

# Common API discovery subpaths (capped and safe)
COMMON_DISCOVERY_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/v1",
    "/api/v2",
    "/api",
    "/graphql",
    "/auth/user",
]

CORS_HEADER_INFO = {
    "Access-Control-Allow-Origin": "Tells the browser which origins may read the response.",
    "Access-Control-Allow-Credentials": "If 'true', cookies/auth headers are included in cross-origin requests.",
    "Access-Control-Allow-Methods": "HTTP methods allowed for cross-origin requests.",
    "Access-Control-Allow-Headers": "Custom headers allowed for cross-origin requests.",
    "Vary": "Informs caches if response varies based on Origin header."
}

RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# High-confidence sensitive field names in JSON
SENSITIVE_JSON_KEYS = {
    "password", "password_hash", "access_token", "refresh_token", "session_token",
    "api_key", "secret", "authorization", "credit_card", "card_number", "ssn",
    "private_key", "auth_token", "jwt", "secret_key"
}

# User profile / structure field names
USER_PROFILE_KEYS = {
    "user_id", "account_id", "email", "phone", "username", "profile", "billing",
    "order_history", "payment_methods", "private_messages"
}

# Values/Keywords that indicate public static text rather than sensitive data leaks
PUBLIC_TEXT_SUBSTRINGS = [
    "please enter your", "your profile page is public", "enter email",
    "forgot password", "login to your account", "sign in to continue",
    "privacy policy", "terms of service", "documentation"
]


def _escalate_risk(current_risk, new_risk):
    """Escalate risk level if new_risk is higher than current_risk."""
    if RISK_ORDER.get(new_risk, 0) > RISK_ORDER.get(current_risk, 0):
        return new_risk
    return current_risk


def _sanitize_evidence_headers(headers):
    """Redact sensitive values like authorization tokens or cookie values from evidence."""
    if not headers:
        return {}
    sanitized = {}
    for k, v in headers.items():
        lk = k.lower()
        if any(sec in lk for sec in ["auth", "token", "cookie", "secret", "key", "pass"]):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = str(v)
    return sanitized


def _request_with_origin(url, origin, timeout=5, custom_headers=None, pinned_ip=None):
    """
    Send a GET request with a specified Origin header and return CORS details.
    Safely handles network errors and limits response body size read.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Website-Security-Scanner CORS-Check)"
    }
    if origin is not None:
        headers["Origin"] = origin

    if custom_headers:
        headers.update(custom_headers)

    try:
        response = safe_get(url, pinned_ip=pinned_ip, headers=headers, timeout=timeout, allow_redirects=True)
        content_type = response.headers.get("Content-Type", "")
        
        # Limit text content read to 10KB to avoid memory overhead
        text_content = ""
        if "json" in content_type.lower() or "text" in content_type.lower() or "javascript" in content_type.lower():
            text_content = response.text[:10000]

        return {
            "success": True,
            "status_code": response.status_code,
            "acao": response.headers.get("Access-Control-Allow-Origin"),
            "acac": response.headers.get("Access-Control-Allow-Credentials"),
            "acam": response.headers.get("Access-Control-Allow-Methods"),
            "acah": response.headers.get("Access-Control-Allow-Headers"),
            "vary": response.headers.get("Vary"),
            "set_cookie": response.headers.get("Set-Cookie"),
            "content_type": content_type,
            "text_content": text_content,
            "headers": dict(response.headers),
            "error": None
        }
    except requests.exceptions.Timeout:
        logger.warning(f"CORS Scanner: Request timeout for {url} (Origin: {origin})")
        return {"success": False, "error": "Request timeout", "status_code": None}
    except requests.exceptions.ConnectionError:
        logger.warning(f"CORS Scanner: Connection error for {url} (Origin: {origin})")
        return {"success": False, "error": "Connection error", "status_code": None}
    except requests.exceptions.RequestException as re:
        logger.warning(f"CORS Scanner: Request exception for {url}: {re}")
        return {"success": False, "error": str(re), "status_code": None}
    except Exception as e:
        logger.error(f"CORS Scanner: Unexpected error scanning {url}: {e}", exc_info=True)
        return {"success": False, "error": f"Unexpected error: {str(e)}", "status_code": None}


def inspect_sensitive_data(response_dict):
    """
    Structured sensitive data inspection:
    - Recursively inspect JSON objects for sensitive field names.
    - Check for user profile structures.
    - Filter out static public page text.
    - Return (sensitive_data_detected, sensitive_data_types, confidence).
    """
    if not response_dict or not response_dict.get("success"):
        return False, [], "LOW"

    text = response_dict.get("text_content", "")
    content_type = (response_dict.get("content_type") or "").lower()

    if not text:
        return False, [], "LOW"

    # Check if text contains typical public/marketing keywords
    lower_text = text.lower()
    if any(pub in lower_text for pub in PUBLIC_TEXT_SUBSTRINGS):
        return False, [], "LOW"

    detected_types = set()

    # Attempt structured JSON parsing
    if "json" in content_type or text.strip().startswith(("{", "[")):
        try:
            data = json.loads(text)

            def recurse_keys(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        lk = str(k).lower()
                        if lk in SENSITIVE_JSON_KEYS:
                            detected_types.add(f"credential_secret:{lk}")
                        elif lk in USER_PROFILE_KEYS:
                            detected_types.add(f"user_data:{lk}")
                        recurse_keys(v)
                elif isinstance(obj, list):
                    for item in obj[:10]: # Cap list inspection
                        recurse_keys(item)

            recurse_keys(data)

            if detected_types:
                # High confidence if explicit sensitive keys found in structured JSON
                has_secret = any(t.startswith("credential_secret") for t in detected_types)
                confidence = "HIGH" if has_secret else "MEDIUM"
                return True, sorted(list(detected_types)), confidence

        except Exception:
            pass

    # Conservative regex fallback for plain text / non-JSON
    # Look for OAuth/Bearer tokens, API keys, or private key blocks
    if re.search(r'("|\')?(access_token|refresh_token|api_key|secret_key)("|\')?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{10,}["\']', lower_text):
        detected_types.add("credential_secret:token")
        return True, sorted(list(detected_types)), "MEDIUM"

    if "-----BEGIN PRIVATE KEY-----" in text or "-----BEGIN RSA PRIVATE KEY-----" in text:
        detected_types.add("credential_secret:private_key")
        return True, sorted(list(detected_types)), "HIGH"

    return False, [], "LOW"


def generate_origin_test_matrix(target_url):
    """
    Build a dynamic origin test matrix based on the target hostname:
    - Arbitrary attacker origin
    - Target domain suffix bypass
    - Target domain prefix bypass
    - HTTP protocol confusion
    - Port variation
    - Null origin
    """
    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(":")[0] if parsed.netloc else "example.com"
    scheme = parsed.scheme or "https"

    matrix = [
        {"type": "arbitrary_origin", "origin": DEFAULT_ATTACKER_ORIGIN, "desc": "Arbitrary attacker domain"},
        {"type": "suffix_bypass", "origin": f"{scheme}://{hostname}.evil-attacker-test.com", "desc": "Domain suffix validation bypass"},
        {"type": "prefix_bypass", "origin": f"{scheme}://evil-{hostname}", "desc": "Domain prefix validation bypass"},
        {"type": "null_origin", "origin": NULL_ORIGIN, "desc": "Null origin trust"},
    ]

    # Add HTTP protocol confusion if target is HTTPS
    if scheme == "https":
        matrix.append({"type": "http_confusion", "origin": f"http://{hostname}", "desc": "HTTP unencrypted scheme confusion"})
    else:
        matrix.append({"type": "https_confusion", "origin": f"https://{hostname}", "desc": "HTTPS scheme variation"})

    # Custom port variation
    matrix.append({"type": "port_variation", "origin": f"{scheme}://{hostname}:8443", "desc": "Non-standard port trust"})

    return matrix, hostname


def discover_api_endpoints(target_url, timeout=4, pinned_ip=None):
    """
    Safely discover potential API endpoints from HTML links and common paths.
    Respects rate limits, max endpoints (<=8), max timeout, and non-destructive GETs.
    """
    discovered = [target_url]
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # Safe GET on root page to extract basic href/src endpoints
    res = _request_with_origin(target_url, origin=None, timeout=timeout, pinned_ip=pinned_ip)
    if res.get("success") and res.get("text_content"):
        html = res.get("text_content")
        # Extract relative API endpoints like /api/v1/user
        found_paths = re.findall(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']', html)
        for path in found_paths:
            full_url = urljoin(base_origin, path)
            if full_url not in discovered and len(discovered) < 6:
                discovered.append(full_url)

    # Check common discovery paths if room remains
    for path in COMMON_DISCOVERY_PATHS:
        if len(discovered) >= 8:
            break
        candidate = urljoin(base_origin, path)
        if candidate not in discovered:
            discovered.append(candidate)

    return discovered[:8]


def _build_remediation(findings):
    """Generate concise actionable remediation guidance based on findings."""
    tips = []
    issues = [f.get("title", "").lower() + " " + f.get("issue", "").lower() for f in findings if f.get("severity") != "INFO"]

    if any("arbitrary" in i or "wildcard" in i or "bypass" in i for i in issues):
        tips.append("Replace wildcard or arbitrary origin reflection with an explicit server-side allowlist of trusted origins.")

    if any("credentials" in i for i in issues):
        tips.append("Never enable Access-Control-Allow-Credentials: true when Access-Control-Allow-Origin is set to '*' or dynamically reflects untrusted origins.")

    if any("suffix" in i or "prefix" in i or "bypass" in i for i in issues):
        tips.append("Validate request Origin headers using exact string matching against an explicit trusted allowlist rather than regular expression or substring matching.")

    if any("preflight" in i or "method" in i for i in issues):
        tips.append("Restrict Access-Control-Allow-Methods and Access-Control-Allow-Headers in OPTIONS responses strictly to necessary values.")

    if any("vary" in i for i in issues):
        tips.append("Include 'Vary: Origin' whenever Access-Control-Allow-Origin is generated dynamically to avoid CDN cache poisoning.")

    if any("null" in i for i in issues):
        tips.append("Do not include 'null' in Access-Control-Allow-Origin; sandboxed iframes and local files send null origins.")

    if not tips:
        tips.append("Maintain an explicit server allowlist for allowed origins and review CORS configuration across all API endpoints.")

    # Deduplicate while preserving order
    seen = set()
    unique_tips = []
    for tip in tips:
        if tip not in seen:
            seen.add(tip)
            unique_tips.append(tip)
    return unique_tips[:4]


def scan_cors(url, pinned_ip=None):
    """
    Upgraded, evidence-based CORS Misconfiguration Scanner.
    Non-destructive, accurate, and structured.
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        findings = []
        tests_performed = []
        endpoints_tested = []
        raw_checks = {}
        overall_risk = "LOW"

        origin_matrix, target_hostname = generate_origin_test_matrix(url)

        # ----------------------------------------------------------------------
        # 1. DISCOVER TARGET ENDPOINTS
        # ----------------------------------------------------------------------
        endpoints_to_test = discover_api_endpoints(url, timeout=4, pinned_ip=pinned_ip)
        endpoints_tested = endpoints_to_test

        # We test primary endpoint first, then sample remaining discovered endpoints
        primary_endpoint = endpoints_to_test[0]

        # ----------------------------------------------------------------------
        # 2. ORIGIN MATRIX TESTS ON PRIMARY ENDPOINT
        # ----------------------------------------------------------------------
        primary_res = _request_with_origin(primary_endpoint, DEFAULT_ATTACKER_ORIGIN, timeout=5, pinned_ip=pinned_ip)
        raw_checks["primary_test"] = primary_res

        if not primary_res["success"]:
            logger.warning(f"CORS Scanner: Target unreachable at {url}: {primary_res.get('error')}")
            return {
                "success": False,
                "hostname": url,
                "error": primary_res.get("error", "Target unreachable"),
                "risk_level": "LOW",
                "findings": [],
                "tests_performed": [],
                "endpoints_tested": [url],
                "remediation": ["Ensure the target website is online and accessible."],
                "cors_header_descriptions": CORS_HEADER_INFO
            }

        # Analyze primary endpoint response
        has_sensitive, sensitive_types, sens_confidence = inspect_sensitive_data(primary_res)
        primary_acao = primary_res.get("acao")
        primary_acac = (primary_res.get("acac") or "").lower() == "true"
        has_set_cookie = bool(primary_res.get("set_cookie"))

        # Test A: Arbitrary Origin Reflection / Wildcard
        tests_performed.append("Arbitrary Origin Reflection Test")

        if primary_acao == DEFAULT_ATTACKER_ORIGIN:
            if primary_acac:
                if has_sensitive:
                    # Verified sensitive data + credentials + arbitrary reflection => CRITICAL
                    overall_risk = _escalate_risk(overall_risk, "CRITICAL")
                    findings.append({
                        "title": "Confirmed Exploitable CORS Policy: Arbitrary Origin Reflected with Credentials & Sensitive Data",
                        "issue": "Arbitrary origin reflected with credentials on endpoint leaking sensitive data",
                        "severity": "CRITICAL",
                        "confidence": sens_confidence,
                        "exploitability": "CONFIRMED_POLICY_WEAKNESS",
                        "endpoint": primary_endpoint,
                        "test_type": "Arbitrary Origin Test",
                        "sensitive_data_detected": True,
                        "sensitive_data_types": sensitive_types,
                        "evidence": {
                            "request_origin": DEFAULT_ATTACKER_ORIGIN,
                            "access_control_allow_origin": primary_acao,
                            "access_control_allow_credentials": "true",
                            "sensitive_fields": ", ".join(sensitive_types)
                        },
                        "impact": "An attacker website can issue cross-origin requests with user credentials (cookies/auth) and read sensitive user data.",
                        "remediation": "Restrict Access-Control-Allow-Origin to an explicit allowlist and remove credentials flag if not strictly required."
                    })
                else:
                    # Credentials + reflection without verified sensitive payload => HIGH
                    overall_risk = _escalate_risk(overall_risk, "HIGH")
                    findings.append({
                        "title": "Potentially Exploitable CORS Policy: Arbitrary Origin Reflected with Credentials",
                        "issue": "Arbitrary origin reflected with credentials flag enabled",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "exploitability": "LIKELY",
                        "endpoint": primary_endpoint,
                        "test_type": "Arbitrary Origin Test",
                        "sensitive_data_detected": False,
                        "sensitive_data_types": [],
                        "evidence": {
                            "request_origin": DEFAULT_ATTACKER_ORIGIN,
                            "access_control_allow_origin": primary_acao,
                            "access_control_allow_credentials": "true"
                        },
                        "impact": "Browsers allow cross-origin credentialed reads for any domain. If authenticated endpoints use this policy, session data can be exposed.",
                        "remediation": "Validate origins strictly against an server allowlist. Never reflect Origin when credentials are allowed."
                    })
            else:
                # Arbitrary reflection without credentials => MEDIUM
                overall_risk = _escalate_risk(overall_risk, "MEDIUM")
                findings.append({
                    "title": "CORS Policy Weakness: Arbitrary Origin Reflected without Credentials",
                    "issue": "Arbitrary origin reflected in Access-Control-Allow-Origin",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "POTENTIAL",
                    "endpoint": primary_endpoint,
                    "test_type": "Arbitrary Origin Test",
                    "sensitive_data_detected": has_sensitive,
                    "sensitive_data_types": sensitive_types,
                    "evidence": {
                        "request_origin": DEFAULT_ATTACKER_ORIGIN,
                        "access_control_allow_origin": primary_acao,
                        "access_control_allow_credentials": "false"
                    },
                    "impact": "Any website can read unauthenticated responses from this endpoint. If public data, risk is low, but policy is overly permissive.",
                    "remediation": "Use an explicit list of trusted frontend origins."
                })

        elif primary_acao == "*":
            if primary_acac:
                # Invalid spec: ACAO: * + ACAC: true => Browsers reject, but policy is invalid => MEDIUM
                overall_risk = _escalate_risk(overall_risk, "MEDIUM")
                findings.append({
                    "title": "Invalid CORS Configuration: Wildcard Origin with Credentials Flag",
                    "issue": "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "NOT_CONFIRMED",
                    "endpoint": primary_endpoint,
                    "test_type": "Wildcard Check",
                    "sensitive_data_detected": False,
                    "sensitive_data_types": [],
                    "evidence": {
                        "access_control_allow_origin": "*",
                        "access_control_allow_credentials": "true"
                    },
                    "impact": "Modern browsers reject credentialed requests when ACAO is wildcard (*). This configuration is invalid according to W3C spec.",
                    "remediation": "Remove Access-Control-Allow-Credentials or specify an explicit trusted origin instead of wildcard '*'."
                })
            else:
                # Wildcard CORS on public resource => LOW / INFO
                findings.append({
                    "title": "Permissive CORS Policy: Wildcard Origin Allowed",
                    "issue": "Access-Control-Allow-Origin is set to '*'",
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "exploitability": "POTENTIAL",
                    "endpoint": primary_endpoint,
                    "test_type": "Wildcard Check",
                    "sensitive_data_detected": False,
                    "sensitive_data_types": [],
                    "evidence": {
                        "access_control_allow_origin": "*"
                    },
                    "impact": "Public endpoints may safely allow wildcard access. Audit to ensure no authenticated or private user data is served here.",
                    "remediation": "Restrict wildcard origins if non-public data is processed."
                })

        # ----------------------------------------------------------------------
        # 3. ORIGIN VALIDATION MATRIX (Suffix, Prefix, Null, Scheme)
        # ----------------------------------------------------------------------
        tests_performed.append("Origin Validation Bypass Matrix Test")
        for test_item in origin_matrix[1:]: # Skip index 0 (already tested above)
            ttype = test_item["type"]
            torigin = test_item["origin"]
            tdesc = test_item["desc"]

            res = _request_with_origin(primary_endpoint, torigin, timeout=4, pinned_ip=pinned_ip)
            if res.get("success") and res.get("acao") == torigin:
                acac_flag = (res.get("acac") or "").lower() == "true"
                has_sens, sens_t, sens_conf = inspect_sensitive_data(res)

                if ttype in ["suffix_bypass", "prefix_bypass"]:
                    sev = "CRITICAL" if (acac_flag and has_sens) else ("HIGH" if acac_flag else "HIGH")
                    expl = "CONFIRMED_POLICY_WEAKNESS" if (acac_flag and has_sens) else "LIKELY"
                    overall_risk = _escalate_risk(overall_risk, sev)

                    findings.append({
                        "title": f"CORS Validation Bypass Detected: {tdesc}",
                        "issue": f"Origin check bypass using lookalike origin '{torigin}'",
                        "severity": sev,
                        "confidence": "HIGH",
                        "exploitability": expl,
                        "endpoint": primary_endpoint,
                        "test_type": "Origin Bypass Test",
                        "sensitive_data_detected": has_sens,
                        "sensitive_data_types": sens_t,
                        "evidence": {
                            "tested_origin": torigin,
                            "access_control_allow_origin": torigin,
                            "access_control_allow_credentials": str(acac_flag)
                        },
                        "impact": f"The server uses flawed prefix/suffix origin matching. Attackers can register '{torigin}' to exploit cross-origin data access.",
                        "remediation": "Validate Origin headers using exact string matching against an explicit trusted allowlist."
                    })

                elif ttype == "null_origin":
                    sev = "CRITICAL" if (acac_flag and has_sens) else ("HIGH" if acac_flag else "MEDIUM")
                    overall_risk = _escalate_risk(overall_risk, sev)

                    findings.append({
                        "title": "CORS Weakness: Trusting Null Origin ('Access-Control-Allow-Origin: null')",
                        "issue": "Explicitly accepting 'null' origin in CORS policy",
                        "severity": sev,
                        "confidence": "HIGH",
                        "exploitability": "LIKELY" if acac_flag else "POTENTIAL",
                        "endpoint": primary_endpoint,
                        "test_type": "Null Origin Test",
                        "sensitive_data_detected": has_sens,
                        "sensitive_data_types": sens_t,
                        "evidence": {
                            "request_origin": "null",
                            "access_control_allow_origin": "null",
                            "access_control_allow_credentials": str(acac_flag)
                        },
                        "impact": "Attackers can trigger null-origin requests using sandboxed HTML5 iframes (`<iframe sandbox='allow-scripts'>`) to bypass origin checks.",
                        "remediation": "Avoid returning 'null' in Access-Control-Allow-Origin."
                    })

        # ----------------------------------------------------------------------
        # 4. DYNAMIC VARY: ORIGIN CHECK
        # ----------------------------------------------------------------------
        tests_performed.append("Vary: Origin Cache Check")
        res_a = primary_res
        res_b = _request_with_origin(primary_endpoint, SECONDARY_ATTACKER_ORIGIN, timeout=4, pinned_ip=pinned_ip)

        if res_a.get("success") and res_b.get("success"):
            acao_a = res_a.get("acao")
            acao_b = res_b.get("acao")

            # Check if CORS header dynamically changes based on Origin
            is_dynamic_reflection = (acao_a == DEFAULT_ATTACKER_ORIGIN and acao_b == SECONDARY_ATTACKER_ORIGIN)
            vary_hdr = (res_a.get("vary") or "").lower()

            if is_dynamic_reflection and "origin" not in vary_hdr:
                overall_risk = _escalate_risk(overall_risk, "MEDIUM")
                findings.append({
                    "title": "CORS Cache Poisoning Risk: Missing 'Vary: Origin' Header",
                    "issue": "Dynamic origin reflection without specifying Vary: Origin",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "POTENTIAL",
                    "endpoint": primary_endpoint,
                    "test_type": "Vary Header Test",
                    "sensitive_data_detected": False,
                    "sensitive_data_types": [],
                    "evidence": {
                        "origin_a": DEFAULT_ATTACKER_ORIGIN,
                        "acao_a": acao_a,
                        "origin_b": SECONDARY_ATTACKER_ORIGIN,
                        "acao_b": acao_b,
                        "vary": res_a.get("vary") or "Missing"
                    },
                    "impact": "Intermediate CDNs or reverse proxies might cache responses generated for one origin and serve them to a different origin.",
                    "remediation": "Include 'Vary: Origin' in response headers whenever Access-Control-Allow-Origin is set dynamically."
                })

        # ----------------------------------------------------------------------
        # 5. MULTIPLE ORIGIN VALUES CHECK
        # ----------------------------------------------------------------------
        tests_performed.append("Header Specification Compliance Test")
        if primary_acao and "," in primary_acao:
            overall_risk = _escalate_risk(overall_risk, "MEDIUM")
            findings.append({
                "title": "Invalid CORS Header Specification: Multiple Origin Values Returned",
                "issue": "Comma-separated multiple values in Access-Control-Allow-Origin",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "exploitability": "NOT_CONFIRMED",
                "endpoint": primary_endpoint,
                "test_type": "Multiple Values Check",
                "evidence": {
                    "access_control_allow_origin": primary_acao
                },
                "impact": "CORS specs mandate exactly one origin or '*'. Returning multiple comma-separated values breaks browser CORS evaluation.",
                "remediation": "Return only a single allowed origin per request."
            })

        # ----------------------------------------------------------------------
        # 6. SAFE NON-DESTRUCTIVE PREFLIGHT (OPTIONS) TEST
        # ----------------------------------------------------------------------
        tests_performed.append("Safe Preflight (OPTIONS) Test")
        try:
            pf_headers = {
                "Origin": DEFAULT_ATTACKER_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
                "User-Agent": "Mozilla/5.0 (Website-Security-Scanner CORS-Check)"
            }
            opt_resp = safe_request("OPTIONS", primary_endpoint, pinned_ip=pinned_ip, headers=pf_headers, timeout=5)
            pf_acao = opt_resp.headers.get("Access-Control-Allow-Origin")
            pf_acam = opt_resp.headers.get("Access-Control-Allow-Methods") or ""
            pf_acah = opt_resp.headers.get("Access-Control-Allow-Headers") or ""

            raw_checks["preflight_test"] = {
                "status_code": opt_resp.status_code,
                "acao": pf_acao,
                "acam": pf_acam,
                "acah": pf_acah
            }

            allowed_methods = [m.strip().upper() for m in pf_acam.split(",")]
            allowed_headers = [h.strip().lower() for h in pf_acah.split(",")]

            has_wildcard_or_sens_method = any(m in allowed_methods for m in ["DELETE", "PUT", "PATCH", "*"])
            has_auth = any(h in allowed_headers for h in ["authorization", "*"])

            if pf_acao == DEFAULT_ATTACKER_ORIGIN and has_wildcard_or_sens_method and has_auth:
                overall_risk = _escalate_risk(overall_risk, "HIGH")
                findings.append({
                    "title": "Preflight Policy Weakness: Sensitive Methods and Auth Headers Allowed for Untrusted Origin",
                    "issue": "Preflight permits state-changing HTTP methods and Authorization headers for arbitrary origins",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "exploitability": "POTENTIAL",
                    "endpoint": primary_endpoint,
                    "test_type": "Preflight Check",
                    "evidence": {
                        "preflight_origin": DEFAULT_ATTACKER_ORIGIN,
                        "allowed_methods": pf_acam,
                        "allowed_headers": pf_acah
                    },
                    "impact": "Attacker scripts can send preflighted requests with custom headers and state-changing methods cross-origin.",
                    "remediation": "Restrict Access-Control-Allow-Methods and Access-Control-Allow-Headers in preflight responses to strictly required values."
                })
        except Exception as pe:
            logger.warning(f"CORS Scanner: Preflight check failed for {primary_endpoint}: {pe}")

        # ----------------------------------------------------------------------
        # 7. SUBPATH ENDPOINT COMPARISON TEST
        # ----------------------------------------------------------------------
        tests_performed.append("API Subpath Endpoint Coverage Check")
        if len(endpoints_to_test) > 1:
            for sub_ep in endpoints_to_test[1:]:
                res_sub = _request_with_origin(sub_ep, DEFAULT_ATTACKER_ORIGIN, timeout=3, pinned_ip=pinned_ip)
                if res_sub.get("success") and res_sub.get("status_code") != 404:
                    sub_acao = res_sub.get("acao")
                    sub_acac = (res_sub.get("acac") or "").lower() == "true"
                    sub_sens, sub_t, sub_conf = inspect_sensitive_data(res_sub)

                    if sub_acao == DEFAULT_ATTACKER_ORIGIN and primary_acao != DEFAULT_ATTACKER_ORIGIN:
                        sev = "CRITICAL" if (sub_acac and sub_sens) else ("HIGH" if sub_acac else "HIGH")
                        overall_risk = _escalate_risk(overall_risk, sev)

                        findings.append({
                            "title": f"Endpoint-Specific CORS Misconfiguration on Discovered API Route ({urlparse(sub_ep).path})",
                            "issue": "Discovered subpath reflects untrusted origins despite root page having strict policy",
                            "severity": sev,
                            "confidence": "HIGH",
                            "exploitability": "CONFIRMED_POLICY_WEAKNESS" if (sub_acac and sub_sens) else "LIKELY",
                            "endpoint": sub_ep,
                            "test_type": "Endpoint Discovery Check",
                            "sensitive_data_detected": sub_sens,
                            "sensitive_data_types": sub_t,
                            "evidence": {
                                "discovered_endpoint": sub_ep,
                                "access_control_allow_origin": sub_acao,
                                "access_control_allow_credentials": str(sub_acac)
                            },
                            "impact": "Root domain CORS settings are not consistently inherited across API routes, exposing subpath endpoints to cross-origin extraction.",
                            "remediation": "Apply consistent CORS origin validation middleware across all API subpaths."
                        })

        # ----------------------------------------------------------------------
        # 8. DEFAULT INFORMATIONAL FINDING IF SAFE
        # ----------------------------------------------------------------------
        if not findings:
            findings.append({
                "title": "Secure CORS Configuration Detected",
                "issue": "No CORS misconfiguration detected",
                "severity": "INFO",
                "confidence": "HIGH",
                "exploitability": "NOT_CONFIRMED",
                "endpoint": primary_endpoint,
                "test_type": "Comprehensive CORS Audit",
                "sensitive_data_detected": False,
                "sensitive_data_types": [],
                "evidence": {
                    "tested_origin": DEFAULT_ATTACKER_ORIGIN,
                    "access_control_allow_origin": primary_acao or "None (Default Same-Origin Policy)"
                },
                "impact": "The server correctly restricts cross-origin access, enforcing the browser Same-Origin Policy.",
                "remediation": "Maintain current strict CORS validation rules."
            })

        remediation = _build_remediation(findings)

        # Build clean, backward-compatible result schema
        return {
            "success": True,
            "hostname": url,
            "risk_level": overall_risk,
            "summary": f"CORS audit completed. Overall risk: {overall_risk}. Total findings: {len(findings)}.",
            "findings": findings,
            "tests_performed": tests_performed,
            "endpoints_tested": endpoints_tested,
            "raw_checks": raw_checks,
            "remediation": remediation,
            "cors_header_descriptions": CORS_HEADER_INFO
        }

    except Exception as e:
        logger.error(f"CORS Scanner: Top-level error scanning {url}: {e}", exc_info=True)
        return {
            "success": False,
            "hostname": url,
            "error": f"Unexpected scan error: {str(e)}",
            "risk_level": "LOW",
            "findings": [],
            "tests_performed": [],
            "endpoints_tested": [url],
            "remediation": ["Ensure server is reachable and supports standard HTTP requests."],
            "cors_header_descriptions": CORS_HEADER_INFO
        }
