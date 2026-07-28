import requests
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common sensitive paths that should never be publicly reachable.
# Format: path -> (description, severity if exposed)
SENSITIVE_PATHS = {
    "/.env": ("Environment file — often contains API keys, DB credentials, secrets", "CRITICAL"),
    "/.git/config": ("Exposed git repository config — can lead to full source code disclosure", "CRITICAL"),
    "/.git/HEAD": ("Exposed git repository — can lead to full source code disclosure", "CRITICAL"),
    "/config.php": ("PHP config file — may contain DB credentials", "CRITICAL"),
    "/wp-config.php": ("WordPress config file — contains DB credentials if exposed", "CRITICAL"),
    "/backup.zip": ("Backup archive — may contain full site/database dump", "HIGH"),
    "/backup.sql": ("Database backup file — may contain full database dump", "CRITICAL"),
    "/database.sql": ("Database dump — may expose all site data", "CRITICAL"),
    "/.htaccess": ("Apache config file — can reveal server rules/redirects", "MEDIUM"),
    "/.htpasswd": ("Password file — may contain hashed credentials", "HIGH"),
    "/.aws/credentials": ("AWS credentials file — full cloud account compromise risk", "CRITICAL"),
    "/id_rsa": ("Private SSH key — full server access risk if valid", "CRITICAL"),
    "/phpinfo.php": ("PHP info page — leaks server configuration/version details", "MEDIUM"),
    "/server-status": ("Apache server-status page — leaks live request/traffic info", "MEDIUM"),
    "/.DS_Store": ("macOS metadata file — can leak directory listing info", "LOW"),
    "/web.config": ("IIS/.NET config file — may contain connection strings", "HIGH"),
    "/composer.json": ("PHP dependency manifest — reveals framework/library versions", "LOW"),
    "/package.json": ("Node dependency manifest — reveals framework/library versions", "LOW"),
    "/.npmrc": ("NPM config — may contain registry auth tokens", "HIGH"),
    "/dump.sql": ("Database dump file", "CRITICAL"),
    "/admin/": ("Admin panel — should require authentication, not just be hidden", "LOW"),
    "/.well-known/security.txt": ("Security contact info — informational, not a vulnerability", "INFO"),
}

MAX_WORKERS = 10
REQUEST_TIMEOUT = 5


def _get_baseline(base_url):
    """
    Request a deliberately random, nonexistent path. Some sites (SPAs, custom routers)
    return HTTP 200 for every path instead of a real 404. If that's the case here, we use
    this baseline response to avoid falsely flagging every sensitive path as 'exposed'.
    """
    random_path = f"/this-path-should-not-exist-{uuid.uuid4().hex[:12]}"
    try:
        response = requests.get(
            base_url.rstrip("/") + random_path,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Website-Security-Scanner Path-Check)"}
        )
        return {
            "status_code": response.status_code,
            "content_length": len(response.content),
            "always_returns_200": response.status_code == 200
        }
    except Exception:
        return {"status_code": None, "content_length": None, "always_returns_200": False}


def _check_path(base_url, path, description, severity, baseline):
    """Check a single path and classify it as exposed, protected, or not found."""
    full_url = base_url.rstrip("/") + path
    try:
        response = requests.get(
            full_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Website-Security-Scanner Path-Check)"}
        )
        status = response.status_code
        content_length = len(response.content)

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

        return {
            "path": path,
            "url": full_url,
            "status_code": status,
            "state": state,
            "description": description,
            "severity": severity if state == "EXPOSED" else "INFO",
            "content_length": content_length if state == "EXPOSED" else None
        }

    except requests.exceptions.Timeout:
        return {"path": path, "url": full_url, "status_code": None, "state": "TIMEOUT",
                "description": description, "severity": "INFO", "content_length": None}
    except requests.exceptions.ConnectionError:
        return {"path": path, "url": full_url, "status_code": None, "state": "CONNECTION_ERROR",
                "description": description, "severity": "INFO", "content_length": None}
    except Exception as e:
        return {"path": path, "url": full_url, "status_code": None, "state": "ERROR",
                "description": description, "severity": "INFO", "content_length": None, "error": str(e)}


def scan_exposed_paths(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        base_url = url.rstrip("/")

        # Establish baseline behavior first (single request) before firing concurrent checks
        baseline = _get_baseline(base_url)

        results = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_check_path, base_url, path, desc, sev, baseline): path
                for path, (desc, sev) in SENSITIVE_PATHS.items()
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

        return {
            "success": True,
            "hostname": base_url,
            "risk_level": risk_level,
            "total_checked": len(results),
            "exposed_count": len(exposed),
            "exposed_paths": exposed,
            "protected_paths": protected,
            "not_found_count": len(not_found),
            "baseline_note": (
                "This site returns HTTP 200 for nonexistent paths; false-positive filtering was applied."
                if baseline.get("always_returns_200") else None
            )
        }

    except Exception as e:
        return {"success": False, "error": str(e)}
