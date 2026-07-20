from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanners.technology_scanner import scan_technology
from scanners.headers_scanner import scan_headers
from scanners.ssl_scanner import scan_ssl
from scanners.port_scanner import scan_ports
from scanners.dns_scanner import scan_dns
from scanners.info_scanner import scan_info

from services.scoring_service import calculate_score
from scanners.seo_scanner import scan_seo
from scanners.performance_scanner import scan_performance
from services.ai_service import get_ai_response

app = FastAPI()

# Mount static files for frontend serving
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="../frontend"), name="static")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class ScanRequest(BaseModel):
    url: str

class ChatRequest(BaseModel):
    message: str
    scan_results: dict = None
    api_key: str = None
    module: str = None
    is_suggestion: bool = False

# Home route
@app.get("/")
def home():
    return {
        "message": "Website Security Scanner API Running"
    }

# Chat route
@app.post("/chat")
def chat_with_advisor(data: ChatRequest):
    response_data = get_ai_response(data.message, data.scan_results, data.api_key, data.module, data.is_suggestion)
    return response_data


def generate_human_summary(website_info, score_result, ssl_result, headers_result, ports_result, performance_result):
    if not website_info or not website_info.get("success"):
        website_info = {}
        
    domain = website_info.get("registered_domain") or "the website"
    ip = website_info.get("ip_address") or "Unknown"
    country = website_info.get("country") or "Unknown"
    isp = website_info.get("isp") or "Unknown"
    registrar = website_info.get("registrar") or "Unknown"
    created = website_info.get("created") or "Unknown"

    # Introduction
    if country != "Unknown" and isp != "Unknown":
        intro = f"This website ({domain}) is hosted on server IP {ip} in {country} and is managed by {isp}."
    else:
        intro = f"This website ({domain}) is hosted on server IP {ip}."

    if registrar != "Unknown" and created != "Unknown":
        intro += f" The domain is registered with {registrar} and was established on {created}."
    elif registrar != "Unknown":
        intro += f" The domain is registered with {registrar}."
    elif created != "Unknown":
        intro += f" The domain was established on {created}."

    # Security Score
    score = score_result.get("security_score", 100) if score_result else 100
    risk = (score_result.get("risk_level", "LOW") if score_result else "LOW").upper()
    sec_intro = f" Our security scan rated this website's risk level as {risk} with a security score of {score}/100."

    # SSL TLS Summary
    ssl_ok = False
    if ssl_result and ssl_result.get("success"):
        ssl_ok = ssl_result.get("ssl_enabled", False)
        
    if ssl_ok:
        proto = ssl_result.get("protocol_version", "HTTPS")
        issuer = ssl_result.get("issuer", "a verified authority")
        ssl_text = f" The website is secure for standard visitors, establishing an encrypted connection using {proto} issued by {issuer}."
    else:
        ssl_text = " ⚠️ WARNING: The website does not use a secure connection (SSL is disabled or invalid). Visitors' personal information, like passwords, is exposed to potential interceptors."

    # Headers & Ports Summary
    concerns = []
    if headers_result and headers_result.get("success"):
        missing_headers = len(headers_result.get("missing_headers", []))
        if missing_headers > 0:
            concerns.append(f"it is missing {missing_headers} essential security headers (which protect against cross-site attacks)")
            
    if ports_result and ports_result.get("success"):
        open_ports = ports_result.get("open_ports", [])
        if open_ports:
            port_list = [str(p["port"]) for p in open_ports]
            concerns.append(f"it has exposed services on open ports: {', '.join(port_list)}")

    if concerns:
        threat_text = " However, we detected potential safety concerns: " + " and ".join(concerns) + "."
    else:
        threat_text = " The server configuration is secure with no high-risk open ports detected."

    # Performance
    perf_score = 100
    load_time = "-"
    if performance_result and performance_result.get("success"):
        perf_score = performance_result.get("performance_score", 100)
        load_time = performance_result.get("first_contentful_paint", "-")
        
    if perf_score >= 80:
        perf_text = f" In terms of speed, the website is fast (Performance Score: {perf_score}/100), loading in about {load_time}."
    elif perf_score >= 50:
        perf_text = f" Performance is moderate (Performance Score: {perf_score}/100), with a load time of {load_time}."
    else:
        perf_text = f" ⚠️ Performance is slow (Performance Score: {perf_score}/100). The page takes {load_time} to render, which could frustrate visitors."

    # Final verdict
    if score >= 80:
        verdict = " Overall, this website appears highly secure and well-configured for everyday use."
    elif score >= 50:
        verdict = " Overall, the website is moderately secure, but we advise implementing the recommendations below to guard against common threats."
    else:
        verdict = " 🔴 CRITICAL: The website has significant security concerns. Administrators should address these vulnerabilities immediately to protect their users."

    return intro + sec_intro + ssl_text + threat_text + perf_text + verdict

# Scan route
@app.post("/scan")
def scan_website(data: ScanRequest):

    headers_result = scan_headers(data.url)

    ssl_result = scan_ssl(data.url)

    ports_result = scan_ports(data.url)

    seo_result = scan_seo(data.url)

    dns_result = scan_dns(data.url)

    technology_result = scan_technology(data.url)

    performance_result = scan_performance(data.url)
    
    info_result = scan_info(data.url)

    score_result = calculate_score(
        headers_result,
        ssl_result,
        ports_result,
        seo_result,
        performance_result,
        dns_result,
    )

    human_summary = generate_human_summary(
        info_result,
        score_result,
        ssl_result,
        headers_result,
        ports_result,
        performance_result
    )

    return {
        "success": True,
        "website": data.url,
        "summary": {
            "security_score": score_result["security_score"],
            "risk_level": score_result["risk_level"],
            "recommendations": score_result["recommendations"],
            "human_summary": human_summary
        },
        "website_info": info_result,
        "scans": {
            "ssl": ssl_result,
            "headers": headers_result,
            "ports": ports_result,
            "seo": seo_result,
            "dns": dns_result,
            "performance": performance_result,
            "technology": technology_result
        }
    }