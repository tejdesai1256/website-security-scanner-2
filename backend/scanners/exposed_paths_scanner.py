import requests
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from services.url_validator import safe_get

# Common sensitive paths that should never be publicly reachable.
# Format: path -> (description, severity if exposed, category)
SENSITIVE_PATHS = {
    # ── Credentials ──
    "/.env": ("Environment file — often contains API keys, DB credentials, secrets", "CRITICAL", "credentials"),
    "/.env.production": ("Production environment file — often contains live secrets", "CRITICAL", "credentials"),
    "/.aws/credentials": ("AWS credentials file — full cloud account compromise risk", "CRITICAL", "cloud"),
    "/id_rsa": ("Private SSH key — full server access risk if valid", "CRITICAL", "credentials"),
    "/.htpasswd": ("Password file — may contain hashed credentials", "HIGH", "credentials"),
    "/.npmrc": ("NPM config — may contain registry auth tokens", "HIGH", "credentials"),
    "/.vscode/sftp.json": ("VS Code SFTP config — may contain deployment credentials", "HIGH", "credentials"),

    # ── Source Control ──
    "/.git/config": ("Exposed git repository config — can lead to full source code disclosure", "CRITICAL", "source_control"),
    "/.git/HEAD": ("Exposed git repository — can lead to full source code disclosure", "CRITICAL", "source_control"),
    "/.git/logs/HEAD": ("Exposed git reflog — can leak commit history and branch names", "CRITICAL", "source_control"),
    "/.svn/entries": ("Exposed SVN metadata — can lead to source code disclosure", "HIGH", "source_control"),

    # ── Config Files ──
    "/config.php": ("PHP config file — may contain DB credentials", "CRITICAL", "config"),
    "/wp-config.php": ("WordPress config file — contains DB credentials if exposed", "CRITICAL", "config"),
    "/web.config": ("IIS/.NET config file — may contain connection strings", "HIGH", "config"),
    "/appsettings.json": (".NET config file — may contain connection strings/secrets", "HIGH", "config"),
    "/docker-compose.yml": ("Docker Compose file — may reveal service topology and embedded secrets", "HIGH", "config"),
    "/.htaccess": ("Apache config file — can reveal server rules/redirects", "MEDIUM", "server_info"),

    # ── Database ──
    "/backup.sql": ("Database backup file — may contain full database dump", "CRITICAL", "database"),
    "/database.sql": ("Database dump — may expose all site data", "CRITICAL", "database"),
    "/dump.sql": ("Database dump file", "CRITICAL", "database"),
    "/backup.zip": ("Backup archive — may contain full site/database dump", "HIGH", "database"),

    # ── Server Info ──
    "/phpinfo.php": ("PHP info page — leaks server configuration/version details", "MEDIUM", "server_info"),
    "/server-status": ("Apache server-status page — leaks live request/traffic info", "MEDIUM", "server_info"),
    "/elmah.axd": ("ELMAH error log viewer exposed — leaks stack traces/internal errors", "MEDIUM", "server_info"),

    # ── API Disclosure ──
    "/actuator": ("Spring Boot Actuator base endpoint exposed — should require authentication", "MEDIUM", "api_disclosure"),
    "/actuator/env": ("Spring Boot Actuator env endpoint — can leak environment variables, secrets, and config", "CRITICAL", "api_disclosure"),
    "/actuator/heapdump": ("Spring Boot Actuator heap dump — can leak in-memory secrets/credentials", "CRITICAL", "api_disclosure"),
    "/actuator/beans": ("Spring Boot Actuator beans endpoint — reveals internal application structure", "MEDIUM", "api_disclosure"),
    "/swagger-ui.html": ("Exposed Swagger/OpenAPI UI — reveals full internal API surface", "MEDIUM", "api_disclosure"),
    "/v2/api-docs": ("Exposed OpenAPI spec — reveals full internal API surface", "MEDIUM", "api_disclosure"),

    # ── Admin Panels ──
    "/admin/": ("Admin panel — should require authentication, not just be hidden", "LOW", "admin_panel"),
    "/adminer.php": ("Adminer DB management tool exposed — direct DB access risk if reachable", "CRITICAL", "admin_panel"),
    "/phpmyadmin/": ("phpMyAdmin panel exposed — direct DB access risk if reachable", "HIGH", "admin_panel"),

    # ── Informational ──
    "/.DS_Store": ("macOS metadata file — can leak directory listing info", "LOW", "informational"),
    "/composer.json": ("PHP dependency manifest — reveals framework/library versions", "LOW", "informational"),
    "/package.json": ("Node dependency manifest — reveals framework/library versions", "LOW", "informational"),
    "/.well-known/security.txt": ("Security contact info — informational, not a vulnerability", "INFO", "informational"),
}

# ── Content-signature verification ──
# Maps path suffixes to substrings that, if found case-insensitively in the
# (capped) response body, confirm the response is genuinely what we expect
# rather than a generic "200 OK" / custom-404 page.
SIGNATURES = {
    "/.env":              ["DB_", "API_KEY", "SECRET", "="],
    "/.env.production":   ["DB_", "API_KEY", "SECRET", "="],
    "/.git/config":       ["[core]", "repositoryformatversion"],
    "/.git/HEAD":         ["ref:"],
    "/.git/logs/HEAD":    ["ref:"],
    "/wp-config.php":     ["DB_NAME", "DB_PASSWORD", "define("],
    "/config.php":        ["DB_NAME", "DB_PASSWORD", "define("],
    "/.aws/credentials":  ["aws_access_key_id", "aws_secret_access_key"],
    "/id_rsa":            ["PRIVATE KEY"],
    "/backup.sql":        ["INSERT INTO", "CREATE TABLE"],
    "/database.sql":      ["INSERT INTO", "CREATE TABLE"],
    "/dump.sql":          ["INSERT INTO", "CREATE TABLE"],
    "/docker-compose.yml":["version:", "services:"],
    "/appsettings.json":  ["ConnectionStrings"],
    "/actuator/env":      ["propertySources", "systemEnvironment"],
}

MAX_WORKERS = 10
REQUEST_TIMEOUT = 5
MAX_BODY_BYTES = 8192


def _get_baseline(base_url, pinned_ip=None):
    """
    Request a deliberately random, nonexistent path. Some sites (SPAs, custom routers)
    return HTTP 200 for every path instead of a real 404. If that's the case here, we use
    this baseline response to avoid falsely flagging every sensitive path as 'exposed'.
    """
    random_path = f"/this-path-should-not-exist-{uuid.uuid4().hex[:12]}"
    try:
        response = safe_get(
            base_url.rstrip("/") + random_path,
            pinned_ip=pinned_ip,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 (Website-Security-Scanner Path-Check)"}
        )
        body = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=1024):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    break
        finally:
            response.close()

        bytes_read = len(body)
        header_length = None
        cl_header = response.headers.get("Content-Length")
        if cl_header:
            try:
                header_length = int(cl_header)
            except ValueError:
                header_length = None

        content_length = header_length if header_length is not None else bytes_read

        return {
            "status_code": response.status_code,
            "content_length": content_length,
            "always_returns_200": response.status_code == 200
        }
    except Exception:
        return {"status_code": None, "content_length": None, "always_returns_200": False}


def _check_path(base_url, path, description, severity, category, baseline, pinned_ip=None):
    """Check a single path and classify it as exposed, protected, or not found.

    Applies content-signature verification when a SIGNATURES entry exists for
    the path, and detects open directory listings for directory paths.
    """
    full_url = base_url.rstrip("/") + path
    try:
        response = safe_get(
            full_url,
            pinned_ip=pinned_ip,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 (Website-Security-Scanner Path-Check)"}
        )
        body = bytearray()
        stopped_early = False
        try:
            for chunk in response.iter_content(chunk_size=1024):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    stopped_early = True
                    break
        finally:
            response.close()

        status = response.status_code
        bytes_read = len(body)
        header_length = None
        cl_header = response.headers.get("Content-Length")
        if cl_header:
            try:
                header_length = int(cl_header)
            except ValueError:
                header_length = None

        content_length = header_length if header_length is not None else bytes_read
        content_truncated = stopped_early or (header_length is not None and header_length > MAX_BODY_BYTES)

        # ── State classification (unchanged baseline logic) ──
        if status == 200:
            # Guard against false positives: if the site returns 200 for literally any
            # path (common with SPAs/custom 404 pages), only count this as truly exposed
            # if its content meaningfully differs from the baseline nonexistent-path response.
            if baseline.get("always_returns_200") and baseline.get("content_length") is not None:
                length_diff = abs(content_length - baseline["content_length"])
                # If content length is nearly identical to the baseline 404-ish page, treat as NOT_FOUND
                if length_diff < 50:
                    state = "NOT_FOUND"
                else:
                    state = "EXPOSED"
            else:
                state = "EXPOSED"
        elif status in (401, 403):
            state = "PROTECTED"
        elif status in (404, 410):
            state = "NOT_FOUND"
        elif 300 <= status < 400:
            state = "REDIRECTED"
        else:
            state = "OTHER"

        # ── Content-signature verification (only when tentatively EXPOSED) ──
        confidence = None
        if state == "EXPOSED":
            # Find matching signature list: check for exact path match or suffix match
            sig_keywords = None
            for sig_path, keywords in SIGNATURES.items():
                if path == sig_path or path.endswith(sig_path):
                    sig_keywords = keywords
                    break

            if sig_keywords is not None:
                # We have a signature list — check the body for case-insensitive matches
                body_lower = bytes(body).decode("utf-8", errors="replace").lower()
                matched = any(kw.lower() in body_lower for kw in sig_keywords)
                if matched:
                    confidence = "HIGH"
                else:
                    # Signature check was available but nothing matched — likely false positive
                    confidence = "LOW"
                    state = "LIKELY_FALSE_POSITIVE"
            else:
                # No signature available for this path — length-diff heuristic only
                confidence = "MEDIUM"

        # ── Directory listing detection (for directory paths ending in "/") ──
        directory_listing_detected = False
        if path.endswith("/") and len(body) > 0:
            body_text_lower = bytes(body).decode("utf-8", errors="replace").lower()
            if "index of /" in body_text_lower or "<title>directory listing for" in body_text_lower:
                directory_listing_detected = True

        return {
            "path": path,
            "url": full_url,
            "status_code": status,
            "state": state,
            "description": description,
            "severity": severity if state == "EXPOSED" else "INFO",
            "category": category,
            "confidence": confidence,
            "directory_listing_detected": directory_listing_detected,
            "content_length": content_length if state == "EXPOSED" else None,
            "content_truncated": content_truncated if state == "EXPOSED" else False
        }

    except requests.exceptions.Timeout:
        return {"path": path, "url": full_url, "status_code": None, "state": "TIMEOUT",
                "description": description, "severity": "INFO", "category": category,
                "confidence": None, "directory_listing_detected": False,
                "content_length": None, "content_truncated": False}
    except requests.exceptions.ConnectionError:
        return {"path": path, "url": full_url, "status_code": None, "state": "CONNECTION_ERROR",
                "description": description, "severity": "INFO", "category": category,
                "confidence": None, "directory_listing_detected": False,
                "content_length": None, "content_truncated": False}
    except Exception as e:
        return {"path": path, "url": full_url, "status_code": None, "state": "ERROR",
                "description": description, "severity": "INFO", "category": category,
                "confidence": None, "directory_listing_detected": False,
                "content_length": None, "content_truncated": False, "error": str(e)}


def scan_exposed_paths(url, pinned_ip=None):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        base_url = url.rstrip("/")

        # Establish baseline behavior first (single request) before firing concurrent checks
        baseline = _get_baseline(base_url, pinned_ip=pinned_ip)

        results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_check_path, base_url, path, desc, sev, cat, baseline, pinned_ip): path
                for path, (desc, sev, cat) in SENSITIVE_PATHS.items()
            }
            for future in as_completed(futures):
                results.append(future.result())

        exposed = [r for r in results if r["state"] == "EXPOSED"]
        protected = [r for r in results if r["state"] == "PROTECTED"]
        not_found = [r for r in results if r["state"] == "NOT_FOUND"]

        exposed.sort(key=lambda r: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(r["severity"], 5))

        if any(r["severity"] == "CRITICAL" for r in exposed):
            risk_level = "CRITICAL"
        elif any(r["severity"] == "HIGH" for r in exposed):
            risk_level = "HIGH"
        elif any(r["severity"] == "MEDIUM" for r in exposed):
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        categories_found = sorted(list(set(r["category"] for r in exposed if r.get("category"))))

        return {
            "success": True,
            "hostname": base_url,
            "risk_level": risk_level,
            "total_checked": len(results),
            "exposed_count": len(exposed),
            "exposed_paths": exposed,
            "protected_paths": protected,
            "not_found_count": len(not_found),
            "categories_found": categories_found,
            "baseline_note": (
                "This site returns HTTP 200 for nonexistent paths; false-positive filtering was applied."
                if baseline.get("always_returns_200") else None
            )
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
