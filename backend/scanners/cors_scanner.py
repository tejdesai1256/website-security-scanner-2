import logging
import requests
from urllib.parse import urlparse, urljoin

# Set up logging for CORS scanner error handling and diagnostics
logger = logging.getLogger("cors_scanner")

# A fake, clearly-nonexistent origin used to test whether the target
# reflects arbitrary origins back (the classic CORS misconfiguration).
FAKE_ORIGIN = "https://evil-attacker-test.com"

# Some servers specifically allow the literal string "null" as an origin,
# which real browsers send in certain contexts (sandboxed iframes, local
# files, some redirects) — attackers can trigger this deliberately.
NULL_ORIGIN = "null"

# Common API subpaths to check for endpoint-specific CORS policies
API_SUBPATHS = [
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/auth/",
    "/login"
]

CORS_HEADER_INFO = {
    "Access-Control-Allow-Origin": "Tells the browser which origins may read the response.",
    "Access-Control-Allow-Credentials": "If 'true', cookies/auth headers are included in cross-origin requests.",
    "Access-Control-Allow-Methods": "HTTP methods allowed for cross-origin requests.",
    "Access-Control-Allow-Headers": "Custom headers allowed for cross-origin requests."
}

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _escalate_risk(current_risk, new_risk):
    """
    Escalate risk level if new_risk is higher than current_risk.
    Prevents higher-risk findings from being overwritten by lower-risk ones.
    """
    if RISK_ORDER.get(new_risk, 0) > RISK_ORDER.get(current_risk, 0):
        return new_risk
    return current_risk


def _request_with_origin(url, origin, timeout=6):
    """
    Send a GET request with a spoofed Origin header and return CORS-related details.
    Catches specific network exceptions (Timeout, ConnectionError, RequestException)
    to prevent scan crashes while logging diagnostic trace information.
    """
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (Website-Security-Scanner CORS-Check)"
    }
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        content_type = response.headers.get("Content-Type", "")
        # Inspect response text preview (first 500 chars) for evidence of sensitive data
        body_preview = response.text[:500] if "json" in content_type.lower() or "text" in content_type.lower() else ""

        return {
            "success": True,
            "status_code": response.status_code,
            "acao": response.headers.get("Access-Control-Allow-Origin"),
            "acac": response.headers.get("Access-Control-Allow-Credentials"),
            "acam": response.headers.get("Access-Control-Allow-Methods"),
            "acah": response.headers.get("Access-Control-Allow-Headers"),
            "vary": response.headers.get("Vary"),
            "content_type": content_type,
            "body_preview": body_preview,
            "error": None
        }
    except requests.exceptions.Timeout:
        logger.warning(f"CORS Scanner: Request timeout scanning {url} with Origin: {origin}")
        return {"success": False, "error": "Request timeout", "status_code": None}
    except requests.exceptions.ConnectionError:
        logger.warning(f"CORS Scanner: Connection error scanning {url} with Origin: {origin}")
        return {"success": False, "error": "Connection error", "status_code": None}
    except requests.exceptions.RequestException as re:
        logger.warning(f"CORS Scanner: Request exception scanning {url} with Origin {origin}: {re}")
        return {"success": False, "error": str(re), "status_code": None}
    except Exception as e:
        logger.error(f"CORS Scanner: Unexpected error scanning {url}: {e}", exc_info=True)
        return {"success": False, "error": f"Unexpected error: {str(e)}", "status_code": None}


def _is_sensitive_endpoint_or_response(path, res_dict):
    """
    Evaluates whether an endpoint or response body contains strong evidence of sensitive
    authenticated data (e.g. auth routes, session tokens, user profile fields).
    This evidence is required before classifying a CORS reflection as CRITICAL.
    """
    if not res_dict or not res_dict.get("success"):
        return False

    path_lower = path.lower()
    sensitive_path_keywords = ["/auth/", "/login", "/user", "/account", "/profile", "/session"]
    path_is_sensitive = any(kw in path_lower for kw in sensitive_path_keywords)

    body_preview = (res_dict.get("body_preview") or "").lower()
    sensitive_body_keywords = ["user_id", "email", "session", "token", "password", "auth_token", "account_id", "profile"]
    body_has_sensitive_data = any(kw in body_preview for kw in sensitive_body_keywords)

    return path_is_sensitive or body_has_sensitive_data


def _build_remediation(findings):
    """Generate 2-4 actionable remediation tips based on triggered findings."""
    tips = []
    issues = [f["issue"].lower() for f in findings if f.get("severity") != "INFO"]

    if any("arbitrary origin" in i or "wildcard origin" in i or "bypass" in i or "endpoint" in i for i in issues):
        tips.append("Replace wildcard or reflected origins with an explicit allowlist of trusted domains.")

    if any("credentials" in i for i in issues):
        tips.append("Never combine Access-Control-Allow-Origin: * or arbitrary reflection with Access-Control-Allow-Credentials: true.")

    if any("prefix" in i or "suffix" in i or "bypass" in i for i in issues):
        tips.append("Validate the Origin header using exact string equality against a trusted allowlist, avoiding substring or prefix/suffix matching.")

    if any("preflight" in i for i in issues):
        tips.append("Restrict Access-Control-Allow-Methods and Access-Control-Allow-Headers in preflight OPTIONS responses to required trusted values.")

    if any("missing vary" in i for i in issues):
        tips.append("Add 'Vary: Origin' whenever Access-Control-Allow-Origin is set dynamically to prevent intermediate CDN cache poisoning.")

    if any("multiple values" in i for i in issues):
        tips.append("Ensure Access-Control-Allow-Origin returns exactly one allowed origin or '*' per response.")

    if any("null" in i for i in issues):
        tips.append("Avoid setting Access-Control-Allow-Origin: null as sandboxed iframes and local files send null origins.")

    if not tips:
        tips.append("Maintain an explicit allowlist of trusted origins and re-evaluate CORS policies across all subpaths.")

    # Deduplicate while preserving insertion order, capped at 4 tips
    seen = set()
    unique_tips = []
    for tip in tips:
        if tip not in seen:
            seen.add(tip)
            unique_tips.append(tip)
    return unique_tips[:4]


def scan_cors(url):
    """
    Scans a web target for potential CORS misconfigurations accurately and evidence-based.
    
    Risk Level Guidelines:
    - LOW: No significant CORS issues detected. Missing optional headers alone is not a vulnerability.
    - MEDIUM: Wildcard origin (ACAO: *), null origin allowed without credentials, invalid specs (ACAO: * + ACAC: true), missing Vary: Origin.
    - HIGH: Arbitrary origin reflected, validation bypass detected, null origin with credentials, sensitive preflight methods allowed.
    - CRITICAL: Arbitrary or bypassed origin reflection + credentials AND verified sensitive authenticated endpoint data.
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        findings = []
        risk_level = "LOW"
        raw_checks = {}

        # ======================================================================
        # 1. ARBITRARY ORIGIN REFLECTION & WILDCARD ANALYSIS (GET Test)
        # ======================================================================
        fake_result = _request_with_origin(url, FAKE_ORIGIN, timeout=6)
        raw_checks["fake_origin_test"] = fake_result

        if not fake_result["success"]:
            logger.warning(f"CORS Scanner: Initial request to {url} failed: {fake_result.get('error')}")
            return {
                "success": False,
                "hostname": url,
                "error": fake_result.get("error", "Scan target unreachable"),
                "risk_level": "LOW",
                "findings": [],
                "raw_checks": raw_checks,
                "cors_header_descriptions": CORS_HEADER_INFO,
                "remediation": ["Ensure the target website is online and accessible."]
            }

        acao = fake_result.get("acao")
        acac = (fake_result.get("acac") or "").lower() == "true"
        reflects_arbitrary_origin = (acao == FAKE_ORIGIN)
        wildcard_origin = (acao == "*")
        is_sensitive = _is_sensitive_endpoint_or_response(url, fake_result)

        if reflects_arbitrary_origin:
            if acac and is_sensitive:
                # Strong evidence: arbitrary origin reflected + credentials + sensitive endpoint/data
                risk_level = _escalate_risk(risk_level, "CRITICAL")
                findings.append({
                    "issue": "Potential exploitable CORS misconfiguration: Arbitrary origin reflected with credentials on sensitive endpoint",
                    "detail": (
                        "The server reflects any arbitrary Origin header back in Access-Control-Allow-Origin, "
                        "enables Access-Control-Allow-Credentials: true, and serves sensitive authenticated data. "
                        "An attacker site can make authenticated cross-origin requests and read sensitive response data."
                    ),
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "exploitability": "Confirmed",
                    "endpoint": url,
                    "evidence": {
                        "request_origin": FAKE_ORIGIN,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": str(acac)
                    }
                })
            elif acac:
                # High risk: credentials allowed with reflection, but no confirmed sensitive response data on root
                risk_level = _escalate_risk(risk_level, "HIGH")
                findings.append({
                    "issue": "Potential CORS misconfiguration: Arbitrary origin reflected with credentials flag",
                    "detail": (
                        "The server reflects arbitrary Origin headers in Access-Control-Allow-Origin and enables "
                        "Access-Control-Allow-Credentials: true. If sensitive endpoints share this policy, malicious sites "
                        "could read visitor data."
                    ),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "exploitability": "Potential",
                    "endpoint": url,
                    "evidence": {
                        "request_origin": FAKE_ORIGIN,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": str(acac)
                    }
                })
            else:
                # High risk: non-credentialed arbitrary reflection
                risk_level = _escalate_risk(risk_level, "HIGH")
                findings.append({
                    "issue": "Potential CORS misconfiguration: Arbitrary origin reflected",
                    "detail": (
                        "The server reflects arbitrary Origin request headers in Access-Control-Allow-Origin. "
                        "Any website can read unauthenticated responses from this endpoint."
                    ),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "exploitability": "Potential",
                    "endpoint": url,
                    "evidence": {
                        "request_origin": FAKE_ORIGIN,
                        "access_control_allow_origin": acao
                    }
                })
        elif wildcard_origin:
            if acac:
                # Browsers reject credentialed requests when ACAO is wildcard (*). Report as invalid config.
                risk_level = _escalate_risk(risk_level, "MEDIUM")
                findings.append({
                    "issue": "Invalid CORS configuration: Wildcard origin combined with credentials flag",
                    "detail": (
                        "Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is 'true'. "
                        "Modern web browsers reject credentialed requests when origin is '*', so this configuration "
                        "is not directly exploitable in modern browsers, but indicates an invalid CORS policy."
                    ),
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "Unlikely",
                    "endpoint": url,
                    "evidence": {
                        "access_control_allow_origin": "*",
                        "access_control_allow_credentials": "true"
                    }
                })
            else:
                # Wildcard CORS on public data is acceptable; report as MEDIUM/informational potential issue
                risk_level = _escalate_risk(risk_level, "MEDIUM")
                findings.append({
                    "issue": "Potential CORS configuration issue: Wildcard origin allowed",
                    "detail": (
                        "Access-Control-Allow-Origin is set to '*', allowing any origin to read unauthenticated responses. "
                        "This is acceptable for public APIs, but should be audited if any non-public data is served."
                    ),
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "Potential",
                    "endpoint": url,
                    "evidence": {
                        "access_control_allow_origin": "*"
                    }
                })

        # ======================================================================
        # 2. VARY: ORIGIN HEADER ANALYSIS (Cache Poisoning Risk)
        # ======================================================================
        if reflects_arbitrary_origin:
            try:
                vary_hdr = fake_result.get("vary") or ""
                vary_list = [v.strip().lower() for v in vary_hdr.split(",")]
                if "origin" not in vary_list:
                    risk_level = _escalate_risk(risk_level, "MEDIUM")
                    findings.append({
                        "issue": "Secondary CORS configuration issue: Missing Vary: Origin header alongside dynamic reflection",
                        "detail": (
                            "The server dynamically reflects the request Origin header in Access-Control-Allow-Origin "
                            "without specifying 'Vary: Origin'. Reverse proxies or CDNs might cache a response "
                            "for one origin and serve it to another, creating cache poisoning risks."
                        ),
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "exploitability": "Potential",
                        "endpoint": url,
                        "evidence": {
                            "vary": vary_hdr if vary_hdr else "Header missing"
                        }
                    })
            except Exception as ve:
                logger.warning(f"CORS Scanner: Error evaluating Vary header for {url}: {ve}")

        # ======================================================================
        # 3. MULTIPLE ORIGIN VALUES TEST (Malformed Header Check)
        # ======================================================================
        try:
            if acao and "," in acao:
                risk_level = _escalate_risk(risk_level, "MEDIUM")
                findings.append({
                    "issue": "Invalid CORS configuration: Multiple values in Access-Control-Allow-Origin header",
                    "detail": (
                        "The Access-Control-Allow-Origin header contains multiple comma-separated values. "
                        "The CORS specification requires exactly one origin or '*'. Non-standard clients may misinterpret this."
                    ),
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "Unlikely",
                    "endpoint": url,
                    "evidence": {
                        "access_control_allow_origin": acao
                    }
                })
        except Exception as me:
            logger.warning(f"CORS Scanner: Error checking multiple origin values for {url}: {me}")

        # ======================================================================
        # 4. NULL ORIGIN TEST
        # ======================================================================
        null_result = _request_with_origin(url, NULL_ORIGIN, timeout=6)
        raw_checks["null_origin_test"] = null_result

        if null_result.get("success") and null_result.get("acao") == "null":
            null_acac = (null_result.get("acac") or "").lower() == "true"
            null_sensitive = _is_sensitive_endpoint_or_response(url, null_result)

            if null_acac and null_sensitive:
                risk_level = _escalate_risk(risk_level, "CRITICAL")
                findings.append({
                    "issue": "Potential exploitable CORS misconfiguration: 'null' origin allowed with credentials on sensitive endpoint",
                    "detail": (
                        "The server sets Access-Control-Allow-Origin: null alongside Access-Control-Allow-Credentials: true "
                        "on an endpoint serving sensitive data. Attackers can trigger requests with a null origin using "
                        "sandboxed iframes to read user data."
                    ),
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "exploitability": "Confirmed",
                    "endpoint": url,
                    "evidence": {
                        "request_origin": "null",
                        "access_control_allow_origin": "null",
                        "access_control_allow_credentials": str(null_acac)
                    }
                })
            elif null_acac:
                risk_level = _escalate_risk(risk_level, "HIGH")
                findings.append({
                    "issue": "Potential CORS misconfiguration: 'null' origin allowed with credentials flag",
                    "detail": (
                        "The server allows Origin: null with credentials enabled. Sandboxed iframes or local file schemes "
                        "can trigger null origin requests to interact with this route."
                    ),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "exploitability": "Potential",
                    "endpoint": url,
                    "evidence": {
                        "request_origin": "null",
                        "access_control_allow_origin": "null",
                        "access_control_allow_credentials": str(null_acac)
                    }
                })
            else:
                risk_level = _escalate_risk(risk_level, "MEDIUM")
                findings.append({
                    "issue": "Potential CORS misconfiguration: 'null' origin explicitly allowed",
                    "detail": (
                        "The server sets Access-Control-Allow-Origin: null. Attackers can issue cross-origin requests "
                        "with a null origin via sandboxed HTML5 iframes."
                    ),
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "exploitability": "Potential",
                    "endpoint": url,
                    "evidence": {
                        "request_origin": "null",
                        "access_control_allow_origin": "null"
                    }
                })

        # ======================================================================
        # 5. SUBDOMAIN / PREFIX-SUFFIX VALIDATION BYPASS TEST
        # ======================================================================
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
                    is_reflected = (res.get("success") and res.get("acao") == test_origin)
                    bypass_results.append({
                        "origin": test_origin,
                        "reflected": is_reflected,
                        "status_code": res.get("status_code")
                    })

                    if is_reflected and not bypass_detected:
                        bypass_detected = True
                        bp_acac = (res.get("acac") or "").lower() == "true"
                        bp_sensitive = _is_sensitive_endpoint_or_response(url, res)

                        if bp_acac and bp_sensitive:
                            risk_level = _escalate_risk(risk_level, "CRITICAL")
                            findings.append({
                                "issue": "Potential exploitable CORS validation bypass: Lookalike origin reflected with credentials on sensitive endpoint",
                                "detail": (
                                    f"The server's origin check allowed crafted lookalike origin '{test_origin}' "
                                    "with credentials enabled on a sensitive endpoint. Attackers can register lookalike domains "
                                    "to perform authenticated data extraction."
                                ),
                                "severity": "CRITICAL",
                                "confidence": "HIGH",
                                "exploitability": "Confirmed",
                                "endpoint": url,
                                "evidence": {
                                    "tested_origin": test_origin,
                                    "access_control_allow_origin": test_origin,
                                    "access_control_allow_credentials": str(bp_acac)
                                }
                            })
                        else:
                            risk_level = _escalate_risk(risk_level, "HIGH")
                            findings.append({
                                "issue": "Potential CORS validation bypass: Lookalike origin reflected",
                                "detail": (
                                    f"The server's origin validation appears to use prefix/suffix matching instead of exact equality. "
                                    f"Crafted origin '{test_origin}' was reflected back in Access-Control-Allow-Origin."
                                ),
                                "severity": "HIGH",
                                "confidence": "HIGH",
                                "exploitability": "Potential",
                                "endpoint": url,
                                "evidence": {
                                    "tested_origin": test_origin,
                                    "access_control_allow_origin": test_origin
                                }
                            })
                raw_checks["subdomain_bypass_tests"] = bypass_results
        except Exception as bpe:
            logger.warning(f"CORS Scanner: Error testing origin bypass for {url}: {bpe}")

        # ======================================================================
        # 6. PREFLIGHT (OPTIONS) REQUEST TEST
        # ======================================================================
        try:
            preflight_headers = {
                "Origin": FAKE_ORIGIN,
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "Authorization",
                "User-Agent": "Mozilla/5.0 (Website-Security-Scanner CORS-Check)"
            }
            options_resp = requests.options(url, headers=preflight_headers, timeout=6)
            pf_acao = options_resp.headers.get("Access-Control-Allow-Origin")
            pf_acac = options_resp.headers.get("Access-Control-Allow-Credentials")
            pf_acam = options_resp.headers.get("Access-Control-Allow-Methods") or ""
            pf_acah = options_resp.headers.get("Access-Control-Allow-Headers") or ""

            preflight_result = {
                "success": True,
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
            origin_reflected = (pf_acao == FAKE_ORIGIN)

            if origin_reflected and has_sensitive_method and has_auth_header:
                risk_level = _escalate_risk(risk_level, "HIGH")
                findings.append({
                    "issue": "Potential preflight CORS misconfiguration: Sensitive methods/headers allowed for untrusted origin",
                    "detail": (
                        "The preflight OPTIONS response permits state-changing HTTP methods (e.g. DELETE/PUT) "
                        "and Authorization headers for an untrusted origin. Attacker scripts could issue "
                        "state-modifying requests if authenticated."
                    ),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "exploitability": "Potential",
                    "endpoint": url,
                    "evidence": {
                        "preflight_origin": FAKE_ORIGIN,
                        "allowed_methods": pf_acam,
                        "allowed_headers": pf_acah
                    }
                })
        except requests.exceptions.RequestException as pre:
            logger.warning(f"CORS Scanner: Preflight OPTIONS request failed for {url}: {pre}")
        except Exception as pe:
            logger.warning(f"CORS Scanner: Unexpected error during preflight check for {url}: {pe}")

        # ======================================================================
        # 7. ADDITIONAL COMMON API SUBPATHS TEST
        # ======================================================================
        try:
            paths_results = []
            subpath_misconfig_found = False

            for path in API_SUBPATHS:
                try:
                    target_path_url = urljoin(url, path)
                    res = _request_with_origin(target_path_url, FAKE_ORIGIN, timeout=4)

                    if not res.get("success") or res.get("status_code") == 404:
                        paths_results.append({
                            "path": path,
                            "endpoint": target_path_url,
                            "reflected": False,
                            "status_code": res.get("status_code")
                        })
                        continue

                    is_reflected = (res.get("acao") == FAKE_ORIGIN)
                    paths_results.append({
                        "path": path,
                        "endpoint": target_path_url,
                        "reflected": is_reflected,
                        "status_code": res.get("status_code")
                    })

                    if is_reflected and not reflects_arbitrary_origin and not subpath_misconfig_found:
                        subpath_misconfig_found = True
                        sub_acac = (res.get("acac") or "").lower() == "true"
                        sub_sensitive = _is_sensitive_endpoint_or_response(target_path_url, res)

                        if sub_acac and sub_sensitive:
                            risk_level = _escalate_risk(risk_level, "CRITICAL")
                            findings.append({
                                "issue": f"Potential exploitable CORS misconfiguration on API endpoint {path}",
                                "detail": (
                                    f"The subpath endpoint '{path}' reflects the untrusted origin with credentials "
                                    "enabled on a sensitive route, despite the root page having strict CORS."
                                ),
                                "severity": "CRITICAL",
                                "confidence": "HIGH",
                                "exploitability": "Confirmed",
                                "endpoint": target_path_url,
                                "evidence": {
                                    "endpoint_path": path,
                                    "access_control_allow_origin": res.get("acao"),
                                    "access_control_allow_credentials": str(sub_acac)
                                }
                            })
                        else:
                            risk_level = _escalate_risk(risk_level, "HIGH")
                            findings.append({
                                "issue": f"Potential CORS misconfiguration on API endpoint {path} not present on root",
                                "detail": (
                                    f"The endpoint '{path}' reflects untrusted origins in Access-Control-Allow-Origin, "
                                    "whereas the main homepage does not. Endpoint-specific CORS policies should be reviewed."
                                ),
                                "severity": "HIGH",
                                "confidence": "HIGH",
                                "exploitability": "Potential",
                                "endpoint": target_path_url,
                                "evidence": {
                                    "endpoint_path": path,
                                    "access_control_allow_origin": res.get("acao")
                                }
                            })
                except Exception as sube:
                    logger.warning(f"CORS Scanner: Error scanning subpath {path} on {url}: {sube}")
                    continue

            raw_checks["additional_paths_tested"] = paths_results
        except Exception as sub_all_e:
            logger.warning(f"CORS Scanner: Error scanning subpaths for {url}: {sub_all_e}")

        # ======================================================================
        # 8. DEFAULT INFORMATIONAL FINDING & REMEDIATION BUILD
        # ======================================================================
        if not findings:
            findings.append({
                "issue": "No significant CORS misconfiguration detected",
                "detail": (
                    "The server did not reflect untrusted origins, properly validated request origins, "
                    "and maintained consistent CORS policies across tested endpoints."
                ),
                "severity": "INFO",
                "confidence": "HIGH",
                "exploitability": "None",
                "endpoint": url,
                "evidence": {
                    "fake_origin_acao": acao or "None"
                }
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
        return {"success": False, "hostname": url, "error": "Request timeout"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "hostname": url, "error": "Connection error"}
    except requests.exceptions.RequestException as re:
        return {"success": False, "hostname": url, "error": str(re)}
    except Exception as e:
        logger.error(f"CORS Scanner: Unexpected top-level scan error for {url}: {e}", exc_info=True)
        return {"success": False, "hostname": url, "error": f"Unexpected error: {str(e)}"}
