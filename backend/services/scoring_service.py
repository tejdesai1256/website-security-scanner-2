def calculate_score(headers, ssl_data, ports, seo=None, performance=None):

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

    for header in important_headers:

        if headers["headers"].get(header) is None:

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

        if port_data["port"] in risky_ports:

            score -= 10

            risky_found = True

    if risky_found:

        recommendations.append(
            "Some risky ports are open"
        )

    # =========================
    # SEO CHECKS
    # =========================
    if seo:

        if not seo.get("title"):
            score -= 5

        if not seo.get("meta_description"):
            score -= 5

    # =========================
    # PERFORMANCE CHECKS
    # =========================
    if performance:

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