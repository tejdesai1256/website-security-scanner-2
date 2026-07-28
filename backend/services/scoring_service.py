def calculate_score(headers, ssl_data, ports, seo=None, performance=None, dns=None, cors=None, exposed_paths=None):
    try:
        headers = headers or {}
        ssl_data = ssl_data or {}
        ports = ports or {}

        score = 100
        recommendations = []

        # =========================
        # SSL CHECKS
        # =========================
        if not ssl_data.get("success"):
            score -= 30
            recommendations.append(
                "Enable SSL certificate"
            )

        # =========================
        # SECURITY HEADERS
        # =========================
        important_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        missing_headers = 0

        headers_dict = headers.get("headers", {}) or {}
        for header in important_headers:
            if headers_dict.get(header) is None:
                missing_headers += 1

        score -= missing_headers * 5

        if missing_headers > 0:
            recommendations.append(
                f"{missing_headers} security headers missing"
            )

        # =========================
        # PORT CHECKS
        # =========================
        risky_ports = [21, 22, 25, 3306]
        open_ports = ports.get("open_ports", [])
        risky_found = False

        for port_data in open_ports:
            if isinstance(port_data, dict) and port_data.get("port") in risky_ports:
                score -= 10
                risky_found = True

        if risky_found:
            recommendations.append(
                "Some risky ports are open"
            )

        # =========================
        # SEO CHECKS
        # =========================
        if seo and isinstance(seo, dict):
            if not seo.get("title"):
                score -= 5

            if not seo.get("meta_description"):
                score -= 5

        # =========================
        # PERFORMANCE CHECKS
        # =========================
        if performance and isinstance(performance, dict):
            perf_score = performance.get(
                "performance_score",
                100
            )

            if perf_score < 50:
                score -= 15
            elif perf_score < 70:
                score -= 10

        # =========================
        # CORS CHECKS (dedup-aware: penalize by highest unique root-cause severity)
        # =========================
        if cors and cors.get("success"):
            cors_findings = cors.get("findings", [])
            # Collect unique root-cause severity levels (avoid double-counting)
            unique_severities = set()
            for finding in cors_findings:
                sev = (finding.get("severity") or "INFO").upper()
                if sev not in ("INFO",):
                    unique_severities.add(sev)

            # Apply penalty based on the single highest unique CORS severity
            CORS_PENALTIES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 0}
            max_penalty = 0
            max_sev = "LOW"
            for sev in unique_severities:
                p = CORS_PENALTIES.get(sev, 0)
                if p > max_penalty:
                    max_penalty = p
                    max_sev = sev

            if max_penalty > 0:
                score -= max_penalty
                recommendations.append(
                    f"CORS misconfiguration detected ({max_sev.lower()} risk) — restrict "
                    f"Access-Control-Allow-Origin to a trusted allowlist"
                )

        # =========================
        # EXPOSED SENSITIVE PATHS CHECKS
        # =========================
        if exposed_paths and exposed_paths.get("success"):
            EXPOSED_PATH_PENALTIES = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 2}
            for finding in exposed_paths.get("exposed_paths", []):
                sev = finding.get("severity", "LOW")
                if sev == "INFO":
                    continue
                penalty = EXPOSED_PATH_PENALTIES.get(sev, 0)
                score -= penalty
                recommendations.append(
                    f"Sensitive file exposed at {finding.get('path')} ({sev.lower()} risk) — "
                    f"restrict access or remove it from the public web root"
                )

        # =========================
        # FINAL SCORE
        # =========================
        if score < 0:
            score = 0

        # Risk level
        if score >= 80:
            risk = "LOW"
        elif score >= 50:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        return {
            "security_score": score,
            "risk_level": risk,
            "recommendations": recommendations
        }
    except Exception as e:
        print(f"Error calculating score: {e}")
        return {
            "security_score": 50,
            "risk_level": "UNKNOWN",
            "recommendations": [f"Partial score calculated due to error: {str(e)}"]
        }