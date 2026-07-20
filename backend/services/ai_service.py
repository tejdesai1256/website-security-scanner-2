# =============================================================================
# Hybrid AI Chatbot Service — Website Security Assistant
# =============================================================================
# Architecture:
#   1. Intent Detection Engine  — fuzzy keyword/synonym matching
#   2. Rule Engine              — pre-written Markdown responses (instant)
#   3. AI Service               — Gemini API for open-ended questions
#   4. Prompt Builder           — constructs contextual AI prompts
#   5. Response Cache           — avoids redundant AI calls
#   6. Scan Context Builder     — formats scan data for AI context
#   7. Response Generator       — orchestrates the full flow
# =============================================================================

import os
import re
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# IN-MEMORY AI RESPONSE CACHE
# =============================================================================
_ai_cache = {}


def _cache_key(message: str) -> str:
    """Generate a normalized cache key from a user message."""
    normalized = re.sub(r'\s+', ' ', message.lower().strip())
    return hashlib.md5(normalized.encode()).hexdigest()


# =============================================================================
# SCAN CONTEXT BUILDER
# =============================================================================
def format_scan_context(scan_results: dict) -> str:
    """Format full scan results into structured text for AI prompt context."""
    if not scan_results:
        return "No scan results available."

    website = scan_results.get("website", "unknown domain")
    summary = scan_results.get("summary", {})
    score = summary.get("security_score", 100)
    risk = summary.get("risk_level", "LOW")
    recs = summary.get("recommendations", [])
    human_summary = summary.get("human_summary", "")

    scans = scan_results.get("scans", {})
    ssl = scans.get("ssl", {})
    headers = scans.get("headers", {})
    ports = scans.get("ports", {})
    perf = scans.get("performance", {})
    dns = scans.get("dns", {})
    seo = scans.get("seo", {})
    tech = scans.get("technology", {})

    ssl_status = "Enabled" if ssl.get("ssl_enabled") else "Disabled"
    missing_headers = headers.get("missing_headers", [])
    open_ports = [f"Port {p.get('port')} ({p.get('service')})" for p in ports.get("open_ports", [])]
    perf_score = perf.get("performance_score", 100)

    dns_info = ""
    if dns.get("success"):
        dns_info = f"""
DNS Records:
  A Records: {', '.join(dns.get('A', [])) or 'None'}
  MX Records: {', '.join(dns.get('MX', [])) or 'None'}
  NS Records: {', '.join(dns.get('NS', [])) or 'None'}
  SPF Present: {'Yes' if dns.get('has_spf') else 'No'}
  DMARC Present: {'Yes' if dns.get('has_dmarc') else 'No'}"""

    seo_info = ""
    if seo.get("success"):
        seo_info = f"""
SEO Analysis:
  Title: {seo.get('title', 'Missing')}
  Meta Description: {'Present' if seo.get('meta_description') else 'Missing'}
  H1 Count: {seo.get('h1_count', 0)}
  Missing Alt Images: {seo.get('missing_alt_images', 0)}
  Word Count: {seo.get('word_count', 0)}"""

    tech_info = ""
    if tech.get("success") and tech.get("technologies"):
        techs = [f"  {k}: {', '.join(v) if isinstance(v, list) else v}" for k, v in tech.get("technologies", {}).items()]
        tech_info = "\nTechnologies Detected:\n" + "\n".join(techs)

    return f"""Website: {website}
Security Score: {score}/100
Risk Level: {risk}
SSL/TLS: {ssl_status} (Protocol: {ssl.get('protocol_version', 'None')}, Issuer: {ssl.get('issuer', 'N/A')}, Expires: {ssl.get('expiry_date', 'N/A')}, Self-Signed: {ssl.get('is_self_signed', False)})
Open Ports: {', '.join(open_ports) if open_ports else 'None'}
Missing Security Headers: {', '.join(missing_headers) if missing_headers else 'None'}
Performance Score: {perf_score}/100
First Contentful Paint: {perf.get('first_contentful_paint', 'N/A')}
Largest Contentful Paint: {perf.get('largest_contentful_paint', 'N/A')}
Speed Index: {perf.get('speed_index', 'N/A')}{dns_info}{seo_info}{tech_info}
Recommendations: {', '.join(recs) if recs else 'None'}
Human Summary: {human_summary}"""


# =============================================================================
# INTENT DETECTION ENGINE
# =============================================================================

INTENTS = [
    {
        "name": "explain_scan",
        "patterns": [
            r"explain.*(?:scan|report|result|finding)",
            r"(?:my|the)\s*(?:scan|report|result|finding)",
            r"summarize.*(?:scan|report|result)",
            r"what.*(?:scan|report)\s*(?:say|show|mean)",
            r"overview.*(?:scan|result)",
            r"tell me about.*(?:scan|report|result)",
            r"analyze.*(?:report|result|scan)",
        ],
    },
    {
        "name": "explain_ssl",
        "patterns": [
            r"\bssl\b",
            r"\btls\b",
            r"ssl.*certificate",
            r"secure.*socket",
            r"what is ssl",
            r"explain.*ssl",
            r"ssl.*mean",
        ],
    },
    {
        "name": "explain_https",
        "patterns": [
            r"\bhttps?\b",
            r"http vs https",
            r"what is https",
            r"explain.*https",
            r"secure.*connection",
            r"https.*mean",
        ],
    },
    {
        "name": "explain_security_headers",
        "patterns": [
            r"security.*header",
            r"header.*security",
            r"what.*(?:are|is).*(?:security\s*)?header",
            r"explain.*header",
            r"missing.*header",
        ],
    },
    {
        "name": "explain_csp",
        "patterns": [
            r"\bcsp\b",
            r"content.security.policy",
            r"what is csp",
            r"explain.*csp",
            r"fix.*csp",
            r"add.*csp",
            r"configure.*csp",
            r"implement.*csp",
        ],
    },
    {
        "name": "explain_hsts",
        "patterns": [
            r"\bhsts\b",
            r"strict.transport.security",
            r"what is hsts",
            r"explain.*hsts",
            r"fix.*hsts",
            r"add.*hsts",
            r"configure.*hsts",
        ],
    },
    {
        "name": "explain_xss",
        "patterns": [
            r"\bxss\b",
            r"cross.site.scripting",
            r"what is xss",
            r"explain.*xss",
            r"prevent.*xss",
            r"protect.*xss",
        ],
    },
    {
        "name": "explain_sql_injection",
        "patterns": [
            r"sql.*injection",
            r"\bsqli\b",
            r"what is sql injection",
            r"explain.*sql.*injection",
            r"prevent.*sql.*injection",
        ],
    },
    {
        "name": "explain_open_ports",
        "patterns": [
            r"open.*port",
            r"port.*open",
            r"exposed.*port",
            r"what.*port",
            r"explain.*port",
            r"port.*scan",
            r"\b(?:port\s*)?(?:21|22|25|3306|8080)\b",
        ],
    },
    {
        "name": "explain_score",
        "patterns": [
            r"(?:security\s*)?score",
            r"points",
            r"why.*(?:my|the)?\s*score",
            r"rating",
            r"how.*(?:score|rating).*calculated",
            r"score.*(?:low|bad|poor|high)",
            r"improve.*score",
            r"increase.*score",
        ],
    },
    {
        "name": "explain_performance",
        "patterns": [
            r"performance.*(?:score|issue|problem|result)",
            r"(?:page|site|website).*(?:speed|slow|fast|load)",
            r"(?:fcp|lcp|speed\s*index|cls|tbt)",
            r"first.*contentful.*paint",
            r"largest.*contentful.*paint",
            r"loading.*(?:time|speed)",
        ],
    },
    {
        "name": "explain_cookies",
        "patterns": [
            r"\bcookie",
            r"what.*cookie",
            r"explain.*cookie",
            r"cookie.*security",
            r"secure.*cookie",
            r"httponly.*cookie",
            r"samesite",
        ],
    },
    {
        "name": "explain_dns",
        "patterns": [
            r"\bdns\b",
            r"domain.*name.*system",
            r"what is dns",
            r"explain.*dns",
            r"dns.*record",
            r"\bspf\b",
            r"\bdmarc\b",
            r"\bmx\b.*record",
        ],
    },
    {
        "name": "explain_vulnerabilities",
        "patterns": [
            r"vulnerabilit",
            r"what.*vulnerable",
            r"explain.*vulnerab",
            r"common.*vulnerab",
            r"security.*(?:flaw|weakness|issue|bug|hole|risk|threat)",
        ],
    },
    {
        "name": "improve_security",
        "patterns": [
            r"improve.*security",
            r"increase.*security",
            r"secure.*(?:my|the)?\s*(?:website|site|server)",
            r"make.*(?:website|site).*(?:secure|safe)",
            r"harden",
            r"security.*(?:tips|advice|recommend|best.*practice)",
            r"website.*security.*tips",
            r"how to.*(?:secure|protect|harden)",
        ],
    },
    {
        "name": "explain_owasp",
        "patterns": [
            r"\bowasp\b",
            r"what is owasp",
            r"explain.*owasp",
            r"owasp.*top\s*(?:10|ten)",
        ],
    },
    {
        "name": "explain_cve",
        "patterns": [
            r"\bcve\b",
            r"what is cve",
            r"explain.*cve",
            r"common.*vulnerab.*expos",
        ],
    },
    {
        "name": "fix_x_frame_options",
        "patterns": [
            r"x.frame.options",
            r"clickjacking",
            r"fix.*x.frame",
            r"iframe.*security",
            r"frame.*(?:busting|protect)",
        ],
    },
    {
        "name": "fix_x_content_type",
        "patterns": [
            r"x.content.type.options",
            r"nosniff",
            r"mime.*sniff",
            r"content.*type.*option",
        ],
    },
    {
        "name": "fix_referrer_policy",
        "patterns": [
            r"referrer.policy",
            r"referer.*policy",
            r"referrer.*leak",
            r"fix.*referrer",
        ],
    },
    {
        "name": "prioritize_fixes",
        "patterns": [
            r"(?:which|what).*(?:fix|address|resolve).*first",
            r"prioriti",
            r"fix.*first",
            r"order.*fix",
            r"most.*important.*fix",
            r"should.*fix",
            r"what.*next",
            r"roadmap",
        ],
    },
    {
        "name": "beginner_guide",
        "patterns": [
            r"beginner",
            r"(?:explain|tell).*(?:simple|simply|easy|plain|basic)",
            r"non.technical",
            r"what does.*mean",
            r"explain.*like.*(?:5|five|kid|child|beginner|newbie|non.tech|simple|basic)",
            r"eli5",
            r"layman",
            r"in simple",
        ],
    },
    {
        "name": "developer_mode",
        "patterns": [
            r"(?:fix|configure|setup|add|implement|enable).*(?:for|on|in)\s*(?:apache|nginx|node|express|php|fastapi|django|iis)",
            r"(?:apache|nginx|node|express|php|fastapi|django|iis).*(?:config|setup|fix|header|example)",
            r"(?:server|web\s*server).*config",
            r"code.*(?:fix|example|snippet|sample)",
            r"give.*(?:config|example|code|snippet)",
        ],
    },
    {
        "name": "greeting",
        "patterns": [
            r"^(?:hi|hello|hey|howdy|greetings|good\s*(?:morning|afternoon|evening)|sup|yo|what'?s?\s*up)[\s!?.]*$",
            r"^(?:help|help\s*me)[\s!?.]*$",
        ],
    },
]


def detect_intent(message: str) -> tuple:
    """
    Match user message against predefined intents.
    Returns (intent_name, confidence) or (None, 0.0).
    """
    msg_lower = message.lower().strip()

    best_intent = None
    best_confidence = 0.0

    for intent in INTENTS:
        for pattern in intent["patterns"]:
            match = re.search(pattern, msg_lower)
            if match:
                match_len = match.end() - match.start()
                coverage = match_len / max(len(msg_lower), 1)
                confidence = min(0.7 + (coverage * 0.3), 1.0)

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_intent = intent["name"]

    return (best_intent, best_confidence)


# =============================================================================
# RULE ENGINE — Pre-written responses for each intent
# =============================================================================

def get_rule_response(intent: str, scan_results: dict = None) -> str:
    """Return a rich Markdown response for the matched intent."""

    # Extract scan data helpers
    website = "the scanned website"
    score = 100
    risk = "LOW"
    ssl_enabled = True
    missing_headers = []
    open_ports = []
    perf_score = 100
    seo_issues = []
    ssl_data = {}
    perf_data = {}
    dns_data = {}

    if scan_results:
        website = scan_results.get("website", "the scanned website")
        summary = scan_results.get("summary", {})
        score = summary.get("security_score", 100)
        risk = summary.get("risk_level", "LOW")

        scans = scan_results.get("scans", {})
        ssl_data = scans.get("ssl", {})
        ssl_enabled = ssl_data.get("ssl_enabled", True)

        headers = scans.get("headers", {})
        missing_headers = headers.get("missing_headers", [])

        ports = scans.get("ports", {})
        open_ports = ports.get("open_ports", [])

        perf_data = scans.get("performance", {})
        perf_score = perf_data.get("performance_score", 100)

        dns_data = scans.get("dns", {})

        seo = scans.get("seo", {})
        if seo and seo.get("success"):
            if not seo.get("title"):
                seo_issues.append("Missing title tag")
            if not seo.get("meta_description"):
                seo_issues.append("Missing meta description")

    # -------------------------------------------------------------------------
    if intent == "explain_scan":
        strengths = []
        weaknesses = []

        if ssl_enabled:
            strengths.append("✅ SSL Certificate is valid and active")
        else:
            weaknesses.append("❌ SSL Certificate is missing or invalid")

        if not missing_headers:
            strengths.append("✅ All security headers are configured")
        else:
            for h in missing_headers:
                weaknesses.append(f"❌ Missing {h}")

        if not open_ports or len(open_ports) == 0:
            strengths.append("✅ No risky open ports detected")
        else:
            risky = [21, 22, 25, 3306]
            for p in open_ports:
                if p.get("port") in risky:
                    weaknesses.append(f"❌ Port {p.get('port')} ({p.get('service')}) is exposed")

        if perf_score >= 80:
            strengths.append(f"✅ Performance score is excellent ({perf_score}/100)")
        elif perf_score >= 50:
            weaknesses.append(f"⚠️ Performance score is moderate ({perf_score}/100)")
        else:
            weaknesses.append(f"❌ Performance score is poor ({perf_score}/100)")

        strengths_str = "\n".join(strengths) if strengths else "- *No strong points detected*"
        weaknesses_str = "\n".join(weaknesses) if weaknesses else "- *No issues detected — great job!*"

        recommendations = []
        if not ssl_enabled:
            recommendations.append("1. **Enable SSL/TLS** — Install a valid certificate (free via Let's Encrypt)")
        if missing_headers:
            recommendations.append(f"2. **Add security headers** — Configure {', '.join(missing_headers)}")
        risky_ports_list = [p for p in open_ports if p.get("port") in [21, 22, 25, 3306]]
        if risky_ports_list:
            recommendations.append(f"3. **Close risky ports** — Block ports {', '.join(str(p.get('port')) for p in risky_ports_list)}")
        if perf_score < 70:
            recommendations.append(f"4. **Optimize performance** — Current score {perf_score}/100 needs improvement")

        recs_str = "\n".join(recommendations) if recommendations else "- *Your website is well-configured!*"

        return f"""### 📊 Scan Report Summary for {website}

Your website scored **{score}/100** with a **{risk}** risk level.

#### 💪 Strengths
{strengths_str}

#### ⚠️ Weaknesses
{weaknesses_str}

#### 🔧 Recommendations
{recs_str}

> 💡 Ask me about any specific finding for a detailed explanation and fix guide!"""

    # -------------------------------------------------------------------------
    elif intent == "explain_ssl":
        ssl_status_text = ""
        if scan_results:
            if ssl_enabled:
                ssl_status_text = f"\n\n> 🟢 **Your website:** SSL is **enabled** using {ssl_data.get('protocol_version', 'HTTPS')}, issued by {ssl_data.get('issuer', 'a verified authority')}. Expires: {ssl_data.get('expiry_date', 'N/A')}."
            else:
                ssl_status_text = "\n\n> 🔴 **Your website:** SSL is **disabled or invalid**. Your visitors' data is transmitted in plaintext!"

        return f"""### 🔒 SSL/TLS Certificate Explained

**SSL (Secure Sockets Layer)** and its modern successor **TLS (Transport Layer Security)** are encryption protocols that create a secure channel between a user's browser and the web server.

#### How it works:
1. Browser connects to the server and requests a secure session
2. Server sends its **SSL certificate** with a public key
3. Browser verifies the certificate with a trusted **Certificate Authority (CA)**
4. Both sides agree on an encryption key using a **TLS handshake**
5. All data is now **encrypted** in transit

#### Why it matters:
- **Protects sensitive data** (passwords, credit cards, personal info)
- **Prevents eavesdropping** by attackers on the network
- **Boosts SEO** — Google ranks HTTPS sites higher
- **Builds trust** — browsers show a padlock icon for HTTPS sites
- **Required for compliance** (PCI-DSS, GDPR, HIPAA)

#### 🗣️ Simple Explanation:
> Think of SSL like a **sealed envelope**. Without it, your data travels like a postcard — anyone who handles it can read it. With SSL, it's sealed and only the intended recipient can open it.{ssl_status_text}"""

    # -------------------------------------------------------------------------
    elif intent == "explain_https":
        return """### 🌐 HTTP vs HTTPS Explained

| Feature | HTTP | HTTPS |
|---------|------|-------|
| **Encryption** | ❌ None | ✅ SSL/TLS |
| **Data Privacy** | Plaintext | Encrypted |
| **Port** | 80 | 443 |
| **SEO Ranking** | Lower | Higher |
| **Browser Trust** | "Not Secure" warning | Padlock icon |
| **Required For** | — | Payments, Login, Forms |

#### What is HTTPS?
**HTTPS (HyperText Transfer Protocol Secure)** is HTTP with encryption. It ensures that all data between the browser and server is **encrypted and tamper-proof**.

#### Why switch to HTTPS?
1. **Security** — Prevents man-in-the-middle attacks
2. **Privacy** — Hides user data from network snoopers
3. **Trust** — Modern browsers flag HTTP sites as "Not Secure"
4. **SEO** — Google uses HTTPS as a ranking signal
5. **Compliance** — Required by GDPR, PCI-DSS

#### 🗣️ Simple Explanation:
> HTTP is like shouting your credit card number across a crowded room. HTTPS is like whispering it through a private, encrypted telephone line."""

    # -------------------------------------------------------------------------
    elif intent == "explain_security_headers":
        header_status = ""
        if scan_results and missing_headers:
            header_status = f"\n\n> ⚠️ **Your website** is missing {len(missing_headers)} security headers: **{', '.join(missing_headers)}**"
        elif scan_results:
            header_status = "\n\n> ✅ **Your website** has all critical security headers configured!"

        return f"""### 🛡️ Security Headers Explained

Security headers are **HTTP response headers** that tell the browser how to behave when handling your website's content. They are your first line of defense against common web attacks.

#### Essential Security Headers:

| Header | Purpose | Protects Against |
|--------|---------|-----------------|
| **Content-Security-Policy** | Controls which resources can load | XSS, data injection |
| **Strict-Transport-Security** | Forces HTTPS connections | Downgrade attacks |
| **X-Frame-Options** | Prevents iframe embedding | Clickjacking |
| **X-Content-Type-Options** | Prevents MIME sniffing | Content-type attacks |
| **Referrer-Policy** | Controls referrer info leaks | Privacy leaks |
| **Permissions-Policy** | Controls browser feature access | Feature abuse |

#### 🗣️ Simple Explanation:
> Security headers are like **rules posted at the door** of a building. They tell every visitor (browser) what they're allowed to do and what's off-limits, before they even enter.{header_status}"""

    # -------------------------------------------------------------------------
    elif intent == "explain_csp":
        return """### 🛡️ Content-Security-Policy (CSP)

**CSP** is a security header that tells the browser which content sources are trusted. It's the most powerful defense against **Cross-Site Scripting (XSS)** attacks.

#### How CSP works:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';
```

#### Server Configuration Examples:

##### Nginx
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;
```

##### Apache (.htaccess)
```apache
<IfModule mod_headers.c>
    Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
</IfModule>
```

##### Node.js / Express
```javascript
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"]
    }
}));
```

##### FastAPI / Python
```python
@app.middleware("http")
async def add_csp(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    return response
```

##### PHP
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
```

#### 🗣️ Simple Explanation:
> CSP is like a **guest list** for your website. Only the sources you explicitly allow (trusted scripts, styles, images) are permitted in — everything else is blocked at the door."""

    # -------------------------------------------------------------------------
    elif intent == "explain_hsts":
        return """### 🔐 HSTS (Strict-Transport-Security)

**HSTS** tells browsers to **always use HTTPS** when connecting to your site, even if the user types `http://`. This prevents **SSL stripping attacks**.

#### How it works:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- `max-age=31536000` — Remember this rule for 1 year
- `includeSubDomains` — Apply to all subdomains too
- `preload` — Allow adding to browser's built-in HSTS list

#### Server Configuration Examples:

##### Nginx
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

##### Apache
```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
```

##### Node.js / Express
```javascript
const helmet = require('helmet');
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));
```

##### FastAPI / Python
```python
@app.middleware("http")
async def add_hsts(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response
```

##### PHP
```php
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
```

#### 🗣️ Simple Explanation:
> HSTS is like telling your browser: **"Never visit this website without encryption — not even once."** It forces every connection to be secure, no exceptions."""

    # -------------------------------------------------------------------------
    elif intent == "explain_xss":
        return """### ⚠️ Cross-Site Scripting (XSS)

**XSS** is a web vulnerability where attackers inject **malicious scripts** into web pages viewed by other users. It's one of the **OWASP Top 10** most critical web security risks.

#### Types of XSS:

| Type | How it works | Example |
|------|-------------|---------|
| **Stored XSS** | Malicious script saved in database | Comments, forum posts |
| **Reflected XSS** | Script in URL reflected back | Search results, error pages |
| **DOM-based XSS** | Script manipulates page DOM | Client-side JavaScript |

#### How an attack works:
1. Attacker injects `<script>document.cookie</script>` into a form
2. Server stores/reflects the script without sanitization
3. When a victim visits the page, the script executes in their browser
4. Attacker steals session cookies, credentials, or redirects users

#### Prevention:
1. **Sanitize all user input** — never trust user data
2. **Use Content-Security-Policy** — blocks inline scripts
3. **Encode output** — escape HTML entities
4. **Use HTTPOnly cookies** — prevents JavaScript cookie access
5. **Use modern frameworks** — React, Angular auto-escape by default

#### 🗣️ Simple Explanation:
> XSS is like someone slipping a **fake announcement** into a trusted newspaper. Readers believe it because it looks like it comes from the paper itself. Attackers inject malicious code into trusted websites to trick users."""

    # -------------------------------------------------------------------------
    elif intent == "explain_sql_injection":
        return """### 💉 SQL Injection Explained

**SQL Injection** is a code injection attack where an attacker inserts **malicious SQL queries** through user input fields to manipulate or steal data from your database.

#### How it works:
```
Normal login:   Username = "admin", Password = "mypassword"
SQL Query:      SELECT * FROM users WHERE username='admin' AND password='mypassword'

Attack input:   Username = "admin' --", Password = "anything"
Resulting SQL:  SELECT * FROM users WHERE username='admin' --' AND password='anything'
```
The `--` comments out the password check, granting access!

#### Real-world impact:
- **Data theft** — Entire databases dumped
- **Authentication bypass** — Login without credentials
- **Data manipulation** — Modify or delete records
- **Server takeover** — Execute system commands

#### Prevention:
1. **Use parameterized queries / prepared statements**
```python
# BAD (vulnerable):
cursor.execute(f"SELECT * FROM users WHERE id = '{user_input}'")

# GOOD (safe):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```
2. **Use ORM frameworks** (SQLAlchemy, Django ORM, Sequelize)
3. **Validate and sanitize all input**
4. **Use least-privilege database accounts**
5. **Enable WAF (Web Application Firewall)**

#### 🗣️ Simple Explanation:
> SQL Injection is like someone adding their own instructions to a form you submit. Instead of filling in their name, they write a command that tricks the database into doing something it shouldn't."""

    # -------------------------------------------------------------------------
    elif intent == "explain_open_ports":
        port_status = ""
        if scan_results and open_ports:
            port_list = "\n".join([f"- **Port {p.get('port')}** ({p.get('service')})" for p in open_ports])
            port_status = f"\n\n> ⚠️ **Your website** has the following open ports:\n{port_list}"
        elif scan_results:
            port_status = "\n\n> ✅ **Your website** has no high-risk open ports detected."

        return f"""### 🔌 Open Ports Explained

**Ports** are virtual endpoints that allow network communication. Open ports are not inherently dangerous, but **unnecessary open ports increase your attack surface**.

#### Common Ports and Risk Level:

| Port | Service | Risk |
|------|---------|------|
| **21** | FTP | 🔴 High — Unencrypted file transfer |
| **22** | SSH | 🟡 Medium — Secure but targeted by brute force |
| **25** | SMTP | 🟡 Medium — Email relay abuse |
| **80** | HTTP | 🟢 Low — Expected for websites |
| **443** | HTTPS | 🟢 Low — Expected for secure websites |
| **3306** | MySQL | 🔴 High — Database should never be public |
| **5432** | PostgreSQL | 🔴 High — Database should never be public |
| **8080** | HTTP Proxy | 🟡 Medium — Development server exposure |

#### Best Practices:
1. **Close unnecessary ports** using a firewall (UFW, iptables)
2. **Bind databases to localhost** (`127.0.0.1`)
3. **Use SSH keys** instead of passwords for port 22
4. **Monitor port access** with intrusion detection systems

#### 🗣️ Simple Explanation:
> Ports are like **doors in a building**. You want the front door (port 443) open for visitors, but you don't want the back door to the vault (port 3306) open to the street.{port_status}"""

    # -------------------------------------------------------------------------
    elif intent == "explain_score":
        deductions = []
        if not ssl_enabled:
            deductions.append("- **SSL/TLS Disabled (-30 points)**: Missing active SSL certificate")
        if missing_headers:
            h_deduct = len(missing_headers) * 5
            deductions.append(f"- **Missing Security Headers (-{h_deduct} points)**: {', '.join(missing_headers)}")
        risky = [21, 22, 25, 3306]
        open_risky = [p for p in open_ports if p.get("port") in risky]
        if open_risky:
            p_deduct = len(open_risky) * 10
            port_names = ', '.join(f"Port {p.get('port')}" for p in open_risky)
            deductions.append(f"- **Exposed Risky Ports (-{p_deduct} points)**: {port_names}")
        if seo_issues:
            deductions.append(f"- **SEO Issues (-{len(seo_issues) * 5} points)**: {', '.join(seo_issues)}")
        if perf_score < 50:
            deductions.append("- **Critical Performance (-15 points)**: Score under 50")
        elif perf_score < 70:
            deductions.append("- **Moderate Performance (-10 points)**: Score under 70")

        deductions_str = "\n".join(deductions) if deductions else "- *No deductions detected — excellent!*"

        improve_steps = []
        if not ssl_enabled:
            improve_steps.append("1. Enable SSL (reclaims 30 points)")
        else:
            improve_steps.append("1. ✅ SSL already active")
        if missing_headers:
            improve_steps.append(f"2. Add missing headers (reclaims {len(missing_headers) * 5} points)")
        else:
            improve_steps.append("2. ✅ All headers configured")
        if open_risky:
            improve_steps.append(f"3. Close risky ports (reclaims {len(open_risky) * 10} points)")
        else:
            improve_steps.append("3. ✅ No risky ports exposed")

        return f"""### 📊 Security Score Analysis

Your security score is **{score}/100** — Risk Level: **{risk}**

#### Score Breakdown:
Starting from a perfect 100, here are the deductions:

{deductions_str}

#### How the score is calculated:
| Check | Penalty |
|-------|---------|
| SSL/TLS disabled | -30 points |
| Each missing security header | -5 points |
| Each risky open port (21, 22, 25, 3306) | -10 points |
| Missing SEO title/description | -5 each |
| Performance < 50 | -15 points |
| Performance < 70 | -10 points |

#### 🚀 How to improve:
{chr(10).join(improve_steps)}"""

    # -------------------------------------------------------------------------
    elif intent == "explain_performance":
        perf_info = ""
        if scan_results and perf_data:
            perf_info = f"""

> **Your website's performance data:**
> - Performance Score: **{perf_score}/100**
> - First Contentful Paint: **{perf_data.get('first_contentful_paint', 'N/A')}**
> - Largest Contentful Paint: **{perf_data.get('largest_contentful_paint', 'N/A')}**
> - Speed Index: **{perf_data.get('speed_index', 'N/A')}**"""

        return f"""### ⚡ Website Performance Explained

Website performance directly impacts user experience, SEO rankings, and conversion rates.

#### Key Metrics:

| Metric | What it measures | Good | Needs Work |
|--------|-----------------|------|------------|
| **FCP** (First Contentful Paint) | First visible content | < 1.8s | > 3.0s |
| **LCP** (Largest Contentful Paint) | Largest element loaded | < 2.5s | > 4.0s |
| **Speed Index** | Visual loading speed | < 3.4s | > 5.8s |
| **TBT** (Total Blocking Time) | Main thread blocked | < 200ms | > 600ms |
| **CLS** (Cumulative Layout Shift) | Visual stability | < 0.1 | > 0.25 |

#### How to improve:
1. **Optimize images** — Use WebP format, compress images, lazy load
2. **Minimize CSS/JS** — Remove unused code, minify files
3. **Enable caching** — Set proper cache headers
4. **Use a CDN** — Distribute content globally
5. **Reduce server response time** — Optimize backend, use faster hosting{perf_info}"""

    # -------------------------------------------------------------------------
    elif intent == "explain_cookies":
        return """### 🍪 Cookies and Security

**Cookies** are small data files stored in the user's browser. They're used for sessions, authentication, preferences, and analytics.

#### Cookie Security Attributes:

| Attribute | Purpose | Recommended |
|-----------|---------|-------------|
| **Secure** | Only sent over HTTPS | ✅ Always |
| **HttpOnly** | Not accessible via JavaScript | ✅ For session cookies |
| **SameSite** | Controls cross-site sending | ✅ Strict or Lax |
| **Path** | Limits cookie scope | ✅ Set to specific paths |
| **Expires/Max-Age** | Controls lifetime | ✅ Set appropriate expiry |

#### Secure Cookie Example:
```http
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

#### Why cookie security matters:
- **Without HttpOnly**: XSS attacks can steal session cookies
- **Without Secure**: Cookies sent over unencrypted HTTP
- **Without SameSite**: CSRF attacks can use your cookies

#### 🗣️ Simple Explanation:
> Cookies are like **ID wristbands** at an event. They prove who you are. If someone steals your wristband (cookie), they can pretend to be you. Security attributes make sure the wristband can't be easily stolen."""

    # -------------------------------------------------------------------------
    elif intent == "explain_dns":
        dns_info = ""
        if scan_results and dns_data and dns_data.get("success"):
            dns_info = f"""

> **Your website's DNS records:**
> - A Records: {', '.join(dns_data.get('A', [])) or 'None'}
> - MX Records: {', '.join(dns_data.get('MX', [])) or 'None'}
> - NS Records: {', '.join(dns_data.get('NS', [])) or 'None'}
> - SPF: {'✅ Present' if dns_data.get('has_spf') else '❌ Missing'}
> - DMARC: {'✅ Present' if dns_data.get('has_dmarc') else '❌ Missing'}"""

        return f"""### 🌐 DNS (Domain Name System) Explained

**DNS** translates human-readable domain names (like `example.com`) into IP addresses (like `93.184.216.34`) that computers use to locate each other.

#### DNS Record Types:

| Record | Purpose | Example |
|--------|---------|---------|
| **A** | Maps domain to IPv4 address | `93.184.216.34` |
| **AAAA** | Maps domain to IPv6 address | `2606:2800:220:1::` |
| **MX** | Mail server routing | `mail.example.com` |
| **NS** | Nameserver delegation | `ns1.provider.com` |
| **TXT** | Verification and policies | SPF, DMARC records |
| **CNAME** | Domain alias | `www` to `example.com` |

#### Security-relevant DNS records:
- **SPF** — Prevents email spoofing by specifying authorized mail servers
- **DMARC** — Tells receivers what to do with failed SPF/DKIM checks
- **DKIM** — Digitally signs emails to verify sender identity

#### 🗣️ Simple Explanation:
> DNS is like a **phone book** for the internet. When you type a website name, DNS looks up the actual address (IP) so your browser knows where to go.{dns_info}"""

    # -------------------------------------------------------------------------
    elif intent == "explain_vulnerabilities":
        return """### 🔓 Website Vulnerabilities Explained

A **vulnerability** is a weakness in your website's code, configuration, or infrastructure that can be exploited by attackers.

#### Most Common Web Vulnerabilities (OWASP Top 10):

| # | Vulnerability | Risk |
|---|--------------|------|
| 1 | **Broken Access Control** | Users accessing unauthorized data |
| 2 | **Cryptographic Failures** | Weak encryption, exposed secrets |
| 3 | **Injection (SQL, XSS)** | Malicious code in user input |
| 4 | **Insecure Design** | Missing security in architecture |
| 5 | **Security Misconfiguration** | Default settings, open ports, missing headers |
| 6 | **Vulnerable Components** | Outdated libraries and frameworks |
| 7 | **Authentication Failures** | Weak passwords, missing MFA |
| 8 | **Data Integrity Failures** | Untrusted software updates |
| 9 | **Logging Failures** | No monitoring or alerts |
| 10 | **SSRF** | Server making unintended requests |

#### How to protect your website:
1. **Keep software updated** — Patch known vulnerabilities
2. **Use security headers** — CSP, HSTS, X-Frame-Options
3. **Enable SSL/TLS** — Encrypt all communications
4. **Validate all input** — Never trust user data
5. **Use strong authentication** — Passwords + MFA
6. **Monitor and log** — Detect attacks early

#### 🗣️ Simple Explanation:
> Vulnerabilities are like **unlocked windows** in your house. Even if the front door is locked, an attacker can climb through an open window to get inside."""

    # -------------------------------------------------------------------------
    elif intent == "improve_security":
        checklist = []
        if scan_results:
            if not ssl_enabled:
                checklist.append("🔴 **1. Enable SSL/TLS** — Install a free certificate via Let's Encrypt")
            else:
                checklist.append("✅ ~~1. Enable SSL/TLS~~ — Already active!")

            if missing_headers:
                checklist.append(f"🟡 **2. Add Security Headers** — You're missing: {', '.join(missing_headers)}")
            else:
                checklist.append("✅ ~~2. Add Security Headers~~ — All configured!")

            risky = [p for p in open_ports if p.get("port") in [21, 22, 25, 3306]]
            if risky:
                checklist.append(f"🔴 **3. Close Risky Ports** — Block: {', '.join(str(p.get('port')) for p in risky)}")
            else:
                checklist.append("✅ ~~3. Close Risky Ports~~ — No risky ports exposed!")

            if perf_score < 70:
                checklist.append(f"🟡 **4. Improve Performance** — Current score: {perf_score}/100")
            else:
                checklist.append(f"✅ ~~4. Performance~~ — Score is good ({perf_score}/100)!")

        checklist_str = "\n".join(checklist) if checklist else ""
        site_specific = f"\n#### Based on your scan of {website}:\n{checklist_str}\n" if checklist else ""

        return f"""### 🔒 How to Improve Website Security
{site_specific}
#### General Security Checklist:
1. **Install SSL/TLS Certificate** — Use HTTPS everywhere
2. **Configure Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
3. **Close Unnecessary Ports** — Only expose required services
4. **Keep Software Updated** — Patch CMS, plugins, and server software
5. **Use Strong Authentication** — Complex passwords + 2FA
6. **Enable Web Application Firewall (WAF)** — Block common attacks
7. **Implement Rate Limiting** — Prevent brute force attacks
8. **Regular Security Audits** — Scan and test regularly
9. **Enable Logging and Monitoring** — Detect intrusions early
10. **Backup Regularly** — Maintain encrypted, offsite backups

#### 🗣️ Simple Explanation:
> Securing a website is like securing a house — you need good locks (SSL), security cameras (monitoring), a guard (WAF), and regular check-ups (audits) to stay safe."""

    # -------------------------------------------------------------------------
    elif intent == "explain_owasp":
        return """### 🏛️ OWASP Explained

**OWASP (Open Web Application Security Project)** is a nonprofit organization that produces freely available resources for web application security.

#### What is the OWASP Top 10?
The **OWASP Top 10** is the most widely recognized list of the most critical security risks facing web applications, updated every few years.

#### OWASP Top 10 (Latest):

| # | Risk | Description |
|---|------|-------------|
| A01 | **Broken Access Control** | Users acting beyond permissions |
| A02 | **Cryptographic Failures** | Data exposure due to weak crypto |
| A03 | **Injection** | SQL, NoSQL, OS, LDAP injection |
| A04 | **Insecure Design** | Missing security patterns |
| A05 | **Security Misconfiguration** | Default configs, missing patches |
| A06 | **Vulnerable Components** | Using outdated libraries |
| A07 | **Auth Failures** | Weak identity verification |
| A08 | **Data Integrity Failures** | Untrusted deserialization |
| A09 | **Logging Failures** | Insufficient monitoring |
| A10 | **SSRF** | Server-side request forgery |

#### Why OWASP matters:
- Industry standard for web security
- Used by companies worldwide for compliance
- Free tools: **ZAP (security scanner)**, **Dependency-Check**, **ASVS**
- Regular updates based on real-world vulnerability data

> 💡 **Tip:** Use OWASP as your security checklist when building or auditing web applications."""

    # -------------------------------------------------------------------------
    elif intent == "explain_cve":
        return """### 📋 CVE (Common Vulnerabilities and Exposures)

**CVE** is a standardized system for identifying and naming publicly known cybersecurity vulnerabilities.

#### CVE Format:
```
CVE-YEAR-NUMBER
Example: CVE-2021-44228 (Log4Shell)
```

#### How CVE works:
1. A vulnerability is discovered
2. It's reported to a **CNA (CVE Numbering Authority)**
3. A unique **CVE ID** is assigned
4. Details are published in the **National Vulnerability Database (NVD)**
5. A **CVSS score** (0-10) rates the severity

#### CVSS Severity Scale:

| Score | Rating | Action |
|-------|--------|--------|
| 0.0 | None | No action needed |
| 0.1-3.9 | **Low** | Fix when convenient |
| 4.0-6.9 | **Medium** | Fix soon |
| 7.0-8.9 | **High** | Fix urgently |
| 9.0-10.0 | **Critical** | Fix immediately |

#### Famous CVEs:
- **CVE-2021-44228** — Log4Shell (Apache Log4j) — CVSS 10.0
- **CVE-2014-0160** — Heartbleed (OpenSSL) — CVSS 7.5
- **CVE-2017-5638** — Equifax breach (Apache Struts) — CVSS 10.0

#### 🗣️ Simple Explanation:
> CVE is like a **police report number** for security bugs. Each known vulnerability gets a unique ID so everyone can track it, discuss it, and fix it."""

    # -------------------------------------------------------------------------
    elif intent == "fix_x_frame_options":
        return """### 🖼️ X-Frame-Options — Clickjacking Protection

**X-Frame-Options** prevents your website from being embedded in `<iframe>` elements on other sites, protecting against **clickjacking attacks**.

#### Values:
- `DENY` — Never allow framing (most secure)
- `SAMEORIGIN` — Only allow framing from your own domain

#### Server Configuration:

##### Nginx
```nginx
add_header X-Frame-Options "DENY" always;
```

##### Apache
```apache
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
```

##### Node.js / Express
```javascript
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
```

##### FastAPI / Python
```python
@app.middleware("http")
async def add_xframe(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

##### PHP
```php
header("X-Frame-Options: DENY");
```

#### 🗣️ Simple Explanation:
> X-Frame-Options prevents your website from being displayed inside a hidden frame on a malicious site, protecting against clickjacking."""

    # -------------------------------------------------------------------------
    elif intent == "fix_x_content_type":
        return """### 📄 X-Content-Type-Options

**X-Content-Type-Options: nosniff** prevents browsers from **MIME-type sniffing** — guessing the file type instead of trusting the declared Content-Type header.

#### Why it matters:
Without this header, a browser might interpret a text file as JavaScript and execute it, enabling XSS attacks.

#### Server Configuration:

##### Nginx
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

##### Apache
```apache
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
```

##### Node.js / Express
```javascript
const helmet = require('helmet');
app.use(helmet.noSniff());
```

##### FastAPI / Python
```python
@app.middleware("http")
async def add_nosniff(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
```

##### PHP
```php
header("X-Content-Type-Options: nosniff");
```

#### 🗣️ Simple Explanation:
> This header tells the browser: "Trust the file type I told you, don't try to guess." Without it, the browser might accidentally treat a harmless-looking file as dangerous code."""

    # -------------------------------------------------------------------------
    elif intent == "fix_referrer_policy":
        return """### 🔗 Referrer-Policy

**Referrer-Policy** controls how much referrer information (the URL you came from) is sent when navigating to another page.

#### Recommended Values:
- `strict-origin-when-cross-origin` — Sends origin only for cross-site (recommended)
- `no-referrer` — Never send referrer (most private)
- `same-origin` — Only send referrer for same-site links

#### Server Configuration:

##### Nginx
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

##### Apache
```apache
<IfModule mod_headers.c>
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

##### Node.js / Express
```javascript
const helmet = require('helmet');
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
```

##### FastAPI / Python
```python
@app.middleware("http")
async def add_referrer_policy(request, call_next):
    response = await call_next(request)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

##### PHP
```php
header("Referrer-Policy: strict-origin-when-cross-origin");
```

#### 🗣️ Simple Explanation:
> When you click a link from one site to another, the browser can tell the second site where you came from. Referrer-Policy controls what information gets shared."""

    # -------------------------------------------------------------------------
    elif intent == "prioritize_fixes":
        critical_high = []
        medium = []
        low = []

        if not ssl_enabled:
            critical_high.append("- **Enable SSL/TLS** — Website running on unencrypted HTTP")
        risky = [21, 22, 25, 3306]
        open_risky = [p for p in open_ports if p.get("port") in risky]
        for p in open_risky:
            critical_high.append(f"- **Close Port {p.get('port')} ({p.get('service')})** — Public exposure risk")
        if missing_headers:
            medium.append(f"- **Add Security Headers** — Missing: {', '.join(missing_headers)}")
        if perf_score < 70:
            low.append(f"- **Improve Performance** — Score: {perf_score}/100")
        if seo_issues:
            low.append(f"- **Fix SEO Issues** — {', '.join(seo_issues)}")

        ch = "\n".join(critical_high) if critical_high else "- *None — no critical issues!*"
        md = "\n".join(medium) if medium else "- *None — headers are in place!*"
        lw = "\n".join(low) if low else "- *None — performance and SEO are good!*"

        return f"""### 📋 Fix Prioritization Roadmap for {website}

#### 🔴 1. Critical — Fix Immediately
{ch}

*These present active security risks where attackers can intercept data or exploit services.*

#### 🟡 2. Medium — Fix Next
{md}

*Missing headers leave users vulnerable to browser-level attacks.*

#### 🟢 3. Low — Fix When Possible
{lw}

*These impact user experience and visibility rather than direct security.*"""

    # -------------------------------------------------------------------------
    elif intent == "beginner_guide":
        return f"""### 📖 Website Security — Beginner's Guide

Welcome! Here's a simple breakdown of what your security scan found for **{website}**:

#### Your Score: {score}/100 ({risk} Risk)

Here's what each finding means in simple terms:

| Term | Simple Explanation |
|------|-------------------|
| **SSL** | 🔒 Like a sealed envelope protecting your data in transit |
| **HTTPS** | 🌐 The secure version of HTTP — encrypts everything |
| **Security Headers** | 🛡️ Rules that tell browsers how to stay safe on your site |
| **CSP** | 📋 A guest list that blocks uninvited scripts |
| **HSTS** | 🔐 Forces browsers to always use the secure connection |
| **XSS** | ⚠️ Attackers injecting bad code into web pages |
| **Open Ports** | 🚪 Doors to your server — some should be closed |
| **DNS** | 📞 The phone book that converts website names to addresses |
| **Cookies** | 🍪 Small files that remember who you are |
| **Performance** | ⚡ How fast your website loads for visitors |

#### What should you do?
{"🔴 **First priority:** Get an SSL certificate to encrypt your website" if not ssl_enabled else "✅ Your SSL is active — great start!"}
{"🟡 **Next:** Add missing security headers (" + ', '.join(missing_headers) + ")" if missing_headers else "✅ Your security headers are configured!"}

> 💡 **Tip:** Ask me about any term above and I'll explain it in more detail!"""

    # -------------------------------------------------------------------------
    elif intent == "developer_mode":
        return """### 👨‍💻 Developer Quick Reference — Security Headers

Here's a complete configuration for **all essential security headers** on common web servers:

#### Nginx (`nginx.conf` or site config)
```nginx
server {
    # Security Headers
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
}
```

#### Apache (`.htaccess` or `httpd.conf`)
```apache
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self';"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>
```

#### Node.js / Express
```javascript
const helmet = require('helmet');
app.use(helmet()); // Enables all headers with secure defaults
```

#### FastAPI / Python
```python
from fastapi import FastAPI, Request

app = FastAPI()

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response
```

#### PHP
```php
<?php
header("Content-Security-Policy: default-src 'self';");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
?>
```

> 💡 After adding headers, test them with your scanner or securityheaders.com"""

    # -------------------------------------------------------------------------
    elif intent == "greeting":
        port_count = len(open_ports)
        header_count = len(missing_headers)
        ssl_desc = "active ✅" if ssl_enabled else "missing ❌"

        if scan_results:
            return f"""### 👋 Hello! I'm your AI Security Assistant

I've analyzed the scan results for **{website}**.

**Quick Summary:**
- 📊 **Security Score:** {score}/100
- ⚡ **Risk Level:** {risk}
- 🔒 **SSL:** {ssl_desc}
- 🔌 **Open Ports:** {port_count} detected
- 🛡️ **Missing Headers:** {header_count}

Ask me anything! Here are some ideas:
- *"Explain my scan report"*
- *"How do I fix missing headers?"*
- *"Explain SSL in simple terms"*
- *"What should I fix first?"*"""
        else:
            return """### 👋 Hello! I'm your AI Security Assistant

I'm here to help you understand website security. You can ask me about:

- 🔒 **SSL/TLS** — Encryption and certificates
- 🛡️ **Security Headers** — CSP, HSTS, X-Frame-Options
- ⚠️ **Vulnerabilities** — XSS, SQL Injection, OWASP Top 10
- 🔌 **Open Ports** — Risk assessment
- ⚡ **Performance** — Speed optimization
- 📊 **Scan Results** — Run a scan first, then ask me to explain it!

> 💡 **Tip:** Run a security scan first, then I can give you personalized recommendations!"""

    # -------------------------------------------------------------------------
    # Fallback — should not normally reach here
    return None


# =============================================================================
# AI SERVICE — Gemini API Integration
# =============================================================================

def build_ai_prompt(message: str, scan_context: str, module: str = None) -> str:
    """Build an enhanced system prompt for the AI."""
    module_focus = ""
    if module and module != "general":
        module_focus = f"\n## Focus Module:\nThe user has indicated this query relates to the **{module.upper()}** module. Pay special attention to the scan results and security concepts for this module.\n"

    return f"""You are an expert **AI Website Security Assistant** integrated into a Website Security Scanner tool.
Your purpose is to help users understand their security scan results, fix vulnerabilities, and learn about cybersecurity.{module_focus}

## Context — Latest Scan Results:
---
{scan_context}
---

## User Question:
{message}

## Response Guidelines:
1. Provide professional, concise, and helpful responses.
2. Format responses in clean **Markdown** with headings, tables, bullet points, and code blocks.
3. If the user asks about fixing issues, provide **step-by-step guides** with server configuration examples for Apache, Nginx, Node.js/Express, FastAPI, and PHP.
4. If asked to prioritize, recommend: Critical (SSL, exposed databases) then High (missing headers) then Medium (performance) then Low (SEO).
5. If the user asks for simple/non-technical explanations, use **everyday analogies** (e.g., SSL = sealed envelope).
6. Reference the scan data above when answering questions about the user's website.
7. Keep responses focused on **website security** — politely redirect off-topic questions.
8. If scan data is available, always tie your recommendations back to the specific findings.
9. End important responses with actionable next steps.
"""


def call_gemini_api(prompt: str, custom_api_key: str = None) -> str:
    """Call Gemini API and return the response text, or None on failure."""
    api_key = custom_api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

    # Skip if key is not set or is the PageSpeed key
    if not api_key or api_key == os.getenv("PAGESPEED_API_KEY"):
        return None

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        data = {
            "contents": [{"parts": [{"text": prompt}]}]
        }

        response = requests.post(url, headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            result = response.json()
            return result['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        print(f"[Hybrid Chatbot] Gemini API error: {str(e)}")

    return None


# =============================================================================
# RESPONSE GENERATOR — Orchestrates the hybrid flow
# =============================================================================

def get_ai_response(message: str, scan_results: dict = None, api_key: str = None, module: str = None, is_suggestion: bool = False) -> dict:
    """
    Main entry point for the Hybrid AI Chatbot.

    Flow:
        1. Detect intent from predefined patterns
        2. If is_suggestion is True and matched (confidence >= 0.7) -> return rule-based response (instant)
        3. Else -> check cache for similar AI response
        4. Else -> call Gemini API for dynamic response
        5. Fallback -> intelligent offline response

    Returns a dict with: response, source, intent, cached
    """
    # Step 1: Intent Detection
    intent, confidence = detect_intent(message)

    # Step 2: Rule-based response (only for suggestion pills)
    if is_suggestion and intent and confidence >= 0.7:
        rule_response = get_rule_response(intent, scan_results)
        if rule_response:
            return {
                "response": rule_response,
                "source": "rule",
                "intent": intent,
                "cached": False,
            }

    # Step 3: Check AI cache
    key = _cache_key(message)
    if key in _ai_cache:
        return {
            "response": _ai_cache[key],
            "source": "ai",
            "intent": intent,
            "cached": True,
        }

    # Step 4: Call Gemini AI
    scan_context = format_scan_context(scan_results)
    prompt = build_ai_prompt(message, scan_context, module)
    ai_response = call_gemini_api(prompt, api_key)

    if ai_response:
        _ai_cache[key] = ai_response  # Cache the response
        return {
            "response": ai_response,
            "source": "ai",
            "intent": intent,
            "cached": False,
        }

    # Step 5: Fallback — generate intelligent offline response
    fallback = _generate_fallback(message, scan_results, module)
    return {
        "response": fallback,
        "source": "fallback",
        "intent": intent,
        "cached": False,
    }


def _generate_fallback(message: str, scan_results: dict = None, module: str = None) -> str:
    """Intelligent fallback when AI is unavailable and no intent matched."""
    website = "your website"
    score = 100
    risk = "LOW"
    ssl_enabled = True
    missing_headers = []
    open_ports = []

    if scan_results:
        website = scan_results.get("website", "your website")
        summary = scan_results.get("summary", {})
        score = summary.get("security_score", 100)
        risk = summary.get("risk_level", "LOW")
        scans = scan_results.get("scans", {})
        ssl_enabled = scans.get("ssl", {}).get("ssl_enabled", True)
        missing_headers = scans.get("headers", {}).get("missing_headers", [])
        open_ports = scans.get("ports", {}).get("open_ports", [])

    module_details = ""
    if module == "ssl":
        ssl_data = scan_results.get("scans", {}).get("ssl", {}) if scan_results else {}
        protocol = ssl_data.get("protocol_version", "N/A")
        issuer = ssl_data.get("issuer", "N/A")
        expires = ssl_data.get("expiry_date", "N/A")
        module_details = f"""
### 🔒 SSL/TLS Certificate Module Status:
- Status: **{'Valid & Enabled ✅' if ssl_enabled else 'Missing or Invalid ❌'}**
- Protocol: **{protocol}**
- Issuer: **{issuer}**
- Expires: **{expires}**
"""
    elif module == "headers":
        headers_data = scan_results.get("scans", {}).get("headers", {}) if scan_results else {}
        missing_count = len(headers_data.get("missing_headers", []))
        module_details = f"""
### 🛡️ Security Headers Module Status:
- Missing Headers: **{missing_count}**
- Present Headers: **{len(headers_data.get('present_headers', [])) if headers_data else 0}**
- Missing List: {', '.join(headers_data.get('missing_headers', [])) if missing_count > 0 else 'None'}
"""
    elif module == "ports":
        ports_data = scan_results.get("scans", {}).get("ports", {}) if scan_results else {}
        open_list = [f"Port {p.get('port')} ({p.get('service')})" for p in ports_data.get("open_ports", [])] if ports_data else []
        module_details = f"""
### 🖥️ Port Scan Module Status:
- Open Ports: **{len(open_list)}**
- Exposed Services: {', '.join(open_list) if open_list else 'None'}
"""
    elif module == "dns":
        dns_data = scan_results.get("scans", {}).get("dns", {}) if scan_results else {}
        has_spf = dns_data.get("has_spf", False)
        has_dmarc = dns_data.get("has_dmarc", False)
        module_details = f"""
### 🌐 DNS Information Module Status:
- SPF Record: **{'Present ✅' if has_spf else 'Missing ❌'}**
- DMARC Record: **{'Present ✅' if has_dmarc else 'Missing ❌'}**
"""
    elif module == "seo":
        seo_data = scan_results.get("scans", {}).get("seo", {}) if scan_results else {}
        h1_count = seo_data.get("h1_count", 0)
        module_details = f"""
### 📈 SEO Analysis Module Status:
- Title: **{seo_data.get('title', 'N/A')}**
- Meta Description: **{'Present ✅' if seo_data.get('meta_description') else 'Missing ❌'}**
- H1 Count: **{h1_count}**
"""
    elif module == "performance":
        perf_data = scan_results.get("scans", {}).get("performance", {}) if scan_results else {}
        perf_score = perf_data.get("performance_score", "N/A")
        fcp = perf_data.get("first_contentful_paint", "N/A")
        module_details = f"""
### ⚡ Performance Module Status:
- Performance Score: **{perf_score}/100**
- First Contentful Paint: **{fcp}**
- Largest Contentful Paint: **{perf_data.get('largest_contentful_paint', 'N/A')}**
"""
    elif module == "technology":
        tech_data = scan_results.get("scans", {}).get("technology", {}) if scan_results else {}
        techs = [f"{k} ({', '.join(v) if isinstance(v, list) else v})" for k, v in tech_data.get("technologies", {}).items()] if tech_data else []
        module_details = f"""
### ⚙️ Technology Detector Module Status:
- Technologies Detected: {', '.join(techs) if techs else 'None'}
"""

    suggestions = {
        "ssl": ["*\"What is SSL?\"*", "*\"How to get free SSL?\"*", "*\"Is self-signed SSL safe?\"*"],
        "headers": ["*\"How to fix CSP?\"*", "*\"Explain security headers\"*", "*\"What is HSTS?\"*"],
        "ports": ["*\"What is a port scan?\"*", "*\"Fix open ports\"*", "*\"Secure database ports\"*"],
        "dns": ["*\"What is DNS?\"*", "*\"Check SPF and DMARC\"*", "*\"Verify DNS records\"*"],
        "seo": ["*\"Optimize image alt text\"*", "*\"Why H1 count matters\"*", "*\"Fix missing meta tags\"*"],
        "performance": ["*\"Improve website speed\"*", "*\"Reduce page load time\"*", "*\"Optimize speed index\"*"],
        "technology": ["*\"Are my backend versions safe?\"*", "*\"Hide server signature\"*", "*\"Explain server cookies safety\"*"]
    }.get(module, [
        "*\"Explain my scan report\"*",
        "*\"What is SSL?\"*",
        "*\"How to fix CSP?\"*",
        "*\"Explain security headers\"*",
        "*\"What should I fix first?\"*",
        "*\"Explain in simple terms\"*",
        "*\"Give me developer config examples\"*"
    ])

    suggestions_list = "\n- ".join(suggestions)

    return f"""### 🤖 I understand your question, but I need a moment

I wasn't able to match your question to my built-in knowledge, and the AI service is currently unavailable.
{module_details}
**Here's a summary of {website}:**
- Security Score: **{score}/100** ({risk} risk)
- SSL: **{'Enabled ✅' if ssl_enabled else 'Disabled ❌'}**
- Missing Headers: **{len(missing_headers)}**
- Open Ports: **{len(open_ports)}**

**Try asking me one of these related to your query:**
- {suggestions_list}

> 💡 I work best with specific security questions!"""
