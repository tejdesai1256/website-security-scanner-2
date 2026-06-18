from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanners.headers_scanner import scan_headers
from scanners.ssl_scanner import scan_ssl
from scanners.port_scanner import scan_ports

from services.scoring_service import calculate_score
from scanners.seo_scanner import scan_seo
from scanners.performance_scanner import scan_performance

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request model
class ScanRequest(BaseModel):
    url: str

# Home route
@app.get("/")
def home():
    return {
        "message": "Website Security Scanner API Running"
    }

# Scan route
@app.post("/scan")
def scan_website(data: ScanRequest):

    headers_result = scan_headers(data.url)

    ssl_result = scan_ssl(data.url)

    ports_result = scan_ports(data.url)

    seo_result = scan_seo(data.url)

    performance_result = scan_performance(data.url)

    score_result = calculate_score(
        headers_result,
        ssl_result,
        ports_result,
        seo_result,
        performance_result
    )

    return {

    "website": data.url,

    "summary": {
        "security_score":
            score_result["security_score"],

        "risk_level":
            score_result["risk_level"],

        "recommendations":
            score_result["recommendations"]
    },

    "scans": {

        "ssl": ssl_result,

        "headers": headers_result,

        "ports": ports_result,

        "seo": seo_result,

        "performance": performance_result
    }
}