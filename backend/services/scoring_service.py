def calculate_score(headers, ssl_data, ports, seo=None, performance=None, dns=None):
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