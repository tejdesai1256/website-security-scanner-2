# Quick Start Guide - Website Security Scanner

## Prerequisites
- Python 3.7+
- pip or conda
- Browser (Chrome, Firefox, Safari, Edge)

## Installation & Setup

### 1. Install Dependencies
```bash
cd c:\PROJECTS\Website Security Scanner2
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
The `.env` file already contains:
- `PAGESPEED_API_KEY` - for performance testing

### 3. Start Backend Server
```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
Press CTRL+C to quit
```

### 4. Open Frontend
Option A: Direct file open
- Navigate to `frontend/index.html` and open in browser

Option B: Python HTTP Server
```bash
cd frontend
python -m http.server 8080
```
Then visit: `http://localhost:8080/index.html`

## Testing

### Test Case 1: Basic Scan
1. Open the application
2. Enter URL: `google.com`
3. Click "Scan Now"
4. Expected results:
   - Security Score (0-100)
   - SSL Status
   - DNS Information (IP, A records, MX, NS, TXT)
   - Port Scan Results
   - Performance Metrics
   - SEO Analysis
   - Recommendations

### Test Case 2: With Protocol
1. Enter URL: `https://github.com`
2. Click "Scan Now"
3. Verify results populate correctly

### Test Case 3: Local Domain
1. Enter URL: `localhost:8000`
2. Click "Scan Now"
3. Verify scanner handles local IPs

### Test Case 4: Error Handling
1. Enter URL: `invalid-domain-12345-xyz.test`
2. Click "Scan Now"
3. Verify error message displays gracefully

### Test Case 5: Download Report
1. Complete a scan
2. Click "Download Report"
3. Verify `.txt` file downloads with all scan data

## API Endpoints

### Health Check
```bash
GET http://localhost:8000/
```

### Scan Website
```bash
POST http://localhost:8000/scan
Content-Type: application/json

{
  "url": "example.com"
}
```

Response:
```json
{
  "success": true,
  "website": "example.com",
  "summary": {
    "security_score": 85,
    "risk_level": "LOW",
    "recommendations": [...]
  },
  "scans": {
    "ssl": {...},
    "headers": {...},
    "ports": {...},
    "dns": {...},
    "seo": {...},
    "performance": {...}
  }
}
```

## DNS Scan Response Example

```json
"dns": {
  "success": true,
  "hostname": "example.com",
  "ip_address": "93.184.216.34",
  "A": ["93.184.216.34"],
  "MX": ["0 ., 10 mail.example.com."],
  "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
  "TXT": ["v=spf1 ... -all"]
}
```

## Troubleshooting

### Backend won't start
- Ensure Python 3.7+ is installed
- Verify dependencies: `pip list | grep fastapi`
- Check port 8000 isn't in use: `netstat -an | findstr :8000`

### DNS results empty
- Check internet connection
- Verify dnspython is installed: `pip install dnspython`
- Try different domain (e.g., google.com)

### API endpoint not found
- Confirm backend is running on port 8000
- Check frontend API URL setting in `script.js`
- Look for CORS errors in browser console

### SSL certificate errors
- Some sites may have SSL issues
- Check firewall/proxy settings
- Verify network connectivity

## Performance Notes

- First scan of a domain may take 10-15 seconds
- Performance testing requires Google PageSpeed API key
- DNS lookups are relatively fast (< 1 second)
- Port scanning takes ~10 seconds (10 ports checked)

## Files Structure

```
Website Security Scanner2/
├── backend/
│   ├── main.py                 # FastAPI server
│   ├── .env                    # Configuration
│   └── scanners/
│       ├── dns_scanner.py      # ✅ DNS lookup
│       ├── ssl_scanner.py      # SSL certificate check
│       ├── port_scanner.py     # Port scanning
│       ├── headers_scanner.py  # Security headers
│       ├── seo_scanner.py      # SEO analysis
│       └── performance_scanner.py # Performance test
│   └── services/
│       └── scoring_service.py  # ✅ Scoring calculation
├── frontend/
│   ├── index.html              # Main interface
│   ├── dashboard.html          # Dashboard interface
│   ├── script.js               # ✅ Dynamic functionality
│   ├── styles.css              # Styling
│   └── auth.js                 # Authentication
├── requirements.txt            # Dependencies
└── FIX_SUMMARY.md             # This guide

```

## Next Steps

1. ✅ Test with sample domains
2. ✅ Verify all scan results display
3. ✅ Download and review report
4. ✅ Check DNS data specifically
5. Deploy to production (e.g., Render, Heroku, Azure)

## Support

For issues or questions:
1. Check FIX_SUMMARY.md for detailed changes
2. Review error messages in browser console (F12)
3. Check backend logs in terminal
4. Verify all requirements are installed
