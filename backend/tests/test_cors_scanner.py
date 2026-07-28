"""
Unit tests for the upgraded CORS Misconfiguration Scanner.
Uses unittest.mock to simulate HTTP responses without making real network requests.

Test Scenarios:
  1. No CORS headers
  2. Wildcard ACAO: *
  3. Arbitrary origin reflection without credentials
  4. Arbitrary origin reflection with credentials
  5. Arbitrary origin + credentials + sensitive JSON
  6. Null origin + credentials + sensitive data
  7. Trusted origin only (no arbitrary-origin vulnerability)
  8. Origin suffix bypass
  9. Dynamic origin reflection without Vary: Origin
  10. Malformed / unreachable target
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Ensure the scanners package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanners.cors_scanner import (
    scan_cors,
    inspect_sensitive_data,
    generate_origin_test_matrix,
    _escalate_risk,
    DEFAULT_ATTACKER_ORIGIN,
    SECONDARY_ATTACKER_ORIGIN,
)


def _mock_response(acao=None, acac=None, acam=None, acah=None, vary=None,
                   set_cookie=None, content_type="text/html", body="",
                   status_code=200):
    """Build a fake successful response dict matching _request_with_origin output."""
    return {
        "success": True,
        "status_code": status_code,
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "acah": acah,
        "vary": vary,
        "set_cookie": set_cookie,
        "content_type": content_type,
        "text_content": body,
        "headers": {},
        "error": None,
    }


def _mock_fail(error="Connection error"):
    """Build a fake failed response dict."""
    return {"success": False, "error": error, "status_code": None}


class TestEscalateRisk(unittest.TestCase):
    def test_escalate_from_low_to_high(self):
        self.assertEqual(_escalate_risk("LOW", "HIGH"), "HIGH")

    def test_no_downgrade(self):
        self.assertEqual(_escalate_risk("HIGH", "MEDIUM"), "HIGH")

    def test_same_level(self):
        self.assertEqual(_escalate_risk("MEDIUM", "MEDIUM"), "MEDIUM")


class TestInspectSensitiveData(unittest.TestCase):
    def test_no_data(self):
        detected, types, conf = inspect_sensitive_data(None)
        self.assertFalse(detected)

    def test_public_text_false_positive(self):
        """Text with 'please enter your email' should NOT be flagged as sensitive."""
        res = _mock_response(
            content_type="text/html",
            body="<html>Please enter your email to subscribe</html>"
        )
        detected, types, conf = inspect_sensitive_data(res)
        self.assertFalse(detected)

    def test_json_with_sensitive_keys(self):
        """JSON containing 'access_token' should be detected as sensitive."""
        import json
        payload = json.dumps({"user_id": 42, "access_token": "abc123secret"})
        res = _mock_response(content_type="application/json", body=payload)
        detected, types, conf = inspect_sensitive_data(res)
        self.assertTrue(detected)
        self.assertTrue(any("credential_secret:access_token" in t for t in types))
        self.assertEqual(conf, "HIGH")

    def test_json_with_user_data_only(self):
        """JSON with user profile keys but no secrets yields MEDIUM confidence."""
        import json
        payload = json.dumps({"email": "user@example.com", "username": "testuser"})
        res = _mock_response(content_type="application/json", body=payload)
        detected, types, conf = inspect_sensitive_data(res)
        self.assertTrue(detected)
        self.assertEqual(conf, "MEDIUM")

    def test_empty_body(self):
        res = _mock_response(content_type="application/json", body="")
        detected, types, conf = inspect_sensitive_data(res)
        self.assertFalse(detected)


class TestGenerateOriginMatrix(unittest.TestCase):
    def test_matrix_contains_expected_types(self):
        matrix, hostname = generate_origin_test_matrix("https://example.com")
        types = [m["type"] for m in matrix]
        self.assertIn("arbitrary_origin", types)
        self.assertIn("suffix_bypass", types)
        self.assertIn("prefix_bypass", types)
        self.assertIn("null_origin", types)
        self.assertIn("http_confusion", types)
        self.assertIn("port_variation", types)
        self.assertEqual(hostname, "example.com")

    def test_suffix_bypass_uses_target_domain(self):
        matrix, _ = generate_origin_test_matrix("https://mysite.org")
        suffix_entry = [m for m in matrix if m["type"] == "suffix_bypass"][0]
        self.assertIn("mysite.org", suffix_entry["origin"])
        self.assertIn("evil-attacker-test.com", suffix_entry["origin"])


class TestScanCorsIntegration(unittest.TestCase):
    """
    Full integration tests for scan_cors using mocked HTTP requests.
    Patches both _request_with_origin (for GET) and requests.options (for preflight).
    """

    def _run_scan(self, side_effect_fn, options_response=None):
        """Helper: run scan_cors with mocked network calls."""
        with patch("scanners.cors_scanner._request_with_origin", side_effect=side_effect_fn):
            with patch("scanners.cors_scanner.requests.options") as mock_opts:
                if options_response:
                    mock_opts.return_value = options_response
                else:
                    # Default preflight: no CORS headers
                    resp = MagicMock()
                    resp.status_code = 200
                    resp.headers = {}
                    mock_opts.return_value = resp
                return scan_cors("https://example.com")

    # ------------------------------------------------------------------
    # TEST 1: No CORS headers at all
    # ------------------------------------------------------------------
    def test_no_cors_headers(self):
        """Server returns no CORS headers => INFO, no vulnerability."""
        def side_effect(url, origin, **kwargs):
            return _mock_response(acao=None, acac=None, body="<html>hello</html>")

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertEqual(result["risk_level"], "LOW")
        self.assertTrue(any(f["severity"] == "INFO" for f in result["findings"]))
        self.assertTrue(any("No CORS misconfiguration" in f["issue"] for f in result["findings"]))

    # ------------------------------------------------------------------
    # TEST 2: Wildcard ACAO: *
    # ------------------------------------------------------------------
    def test_wildcard_origin(self):
        """ACAO: * without credentials => LOW."""
        def side_effect(url, origin, **kwargs):
            return _mock_response(acao="*", body="<html>public page</html>")

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        # Wildcard without credentials should be LOW
        self.assertIn(result["risk_level"], ["LOW"])
        self.assertTrue(any(f["severity"] == "LOW" for f in result["findings"]))

    # ------------------------------------------------------------------
    # TEST 3: Arbitrary origin reflection WITHOUT credentials
    # ------------------------------------------------------------------
    def test_arbitrary_reflection_no_credentials(self):
        """Arbitrary origin reflected, no ACAC => MEDIUM."""
        def side_effect(url, origin, **kwargs):
            if origin == DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(acao=DEFAULT_ATTACKER_ORIGIN, acac=None)
            if origin == SECONDARY_ATTACKER_ORIGIN:
                return _mock_response(acao=SECONDARY_ATTACKER_ORIGIN, acac=None)
            # For null, bypass, etc.
            return _mock_response(acao=origin, acac=None)

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertIn(result["risk_level"], ["MEDIUM", "HIGH"])  # bypass tests may escalate
        # Primary finding should be MEDIUM
        primary = [f for f in result["findings"] if f["test_type"] == "Arbitrary Origin Test"]
        self.assertTrue(len(primary) > 0)
        self.assertEqual(primary[0]["severity"], "MEDIUM")

    # ------------------------------------------------------------------
    # TEST 4: Arbitrary origin reflection WITH credentials
    # ------------------------------------------------------------------
    def test_arbitrary_reflection_with_credentials(self):
        """Arbitrary origin reflected + ACAC: true => HIGH."""
        def side_effect(url, origin, **kwargs):
            if origin == DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(acao=DEFAULT_ATTACKER_ORIGIN, acac="true", body="<html>ok</html>")
            if origin == SECONDARY_ATTACKER_ORIGIN:
                return _mock_response(acao=SECONDARY_ATTACKER_ORIGIN, acac="true")
            return _mock_response(acao=origin, acac="true")

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertIn(result["risk_level"], ["HIGH", "CRITICAL"])
        primary = [f for f in result["findings"] if f["test_type"] == "Arbitrary Origin Test"]
        self.assertTrue(len(primary) > 0)
        self.assertIn(primary[0]["severity"], ["HIGH"])

    # ------------------------------------------------------------------
    # TEST 5: Arbitrary origin + credentials + sensitive authenticated JSON
    # ------------------------------------------------------------------
    def test_arbitrary_credentials_sensitive_json(self):
        """Arbitrary + ACAC: true + sensitive JSON => CRITICAL."""
        import json
        sensitive_body = json.dumps({
            "user_id": 123,
            "email": "user@test.com",
            "access_token": "secret-jwt-token-value",
            "profile": {"name": "John"}
        })

        def side_effect(url, origin, **kwargs):
            if origin == DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(
                    acao=DEFAULT_ATTACKER_ORIGIN, acac="true",
                    content_type="application/json", body=sensitive_body
                )
            if origin == SECONDARY_ATTACKER_ORIGIN:
                return _mock_response(
                    acao=SECONDARY_ATTACKER_ORIGIN, acac="true",
                    content_type="application/json", body=sensitive_body
                )
            return _mock_response(acao=origin, acac="true",
                                  content_type="application/json", body=sensitive_body)

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertEqual(result["risk_level"], "CRITICAL")
        critical = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
        self.assertTrue(len(critical) > 0)
        self.assertTrue(critical[0].get("sensitive_data_detected"))

    # ------------------------------------------------------------------
    # TEST 6: Null origin + credentials + sensitive data
    # ------------------------------------------------------------------
    def test_null_origin_credentials_sensitive(self):
        """null origin accepted + ACAC + sensitive data => HIGH/CRITICAL."""
        import json
        sensitive_body = json.dumps({"session_token": "sess-abc123", "user_id": 5})

        def side_effect(url, origin, **kwargs):
            if origin == DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(acao=None, acac=None, body="ok")
            if origin == "null":
                return _mock_response(
                    acao="null", acac="true",
                    content_type="application/json", body=sensitive_body
                )
            if origin is None:
                return _mock_response(acao=None, body="<html></html>")
            return _mock_response(acao=None)

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertIn(result["risk_level"], ["HIGH", "CRITICAL"])
        null_findings = [f for f in result["findings"] if f["test_type"] == "Null Origin Test"]
        self.assertTrue(len(null_findings) > 0)

    # ------------------------------------------------------------------
    # TEST 7: Trusted origin only — no arbitrary origin vulnerability
    # ------------------------------------------------------------------
    def test_trusted_origin_only(self):
        """Server returns only trusted origin (or no ACAO) for untrusted origins."""
        def side_effect(url, origin, **kwargs):
            # Always return no CORS headers for untrusted origins
            return _mock_response(acao=None, acac=None, body="<html>ok</html>")

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertEqual(result["risk_level"], "LOW")
        # Should have only the INFO finding
        self.assertTrue(any("No CORS misconfiguration" in f["issue"] for f in result["findings"]))

    # ------------------------------------------------------------------
    # TEST 8: Origin suffix bypass detected
    # ------------------------------------------------------------------
    def test_origin_suffix_bypass(self):
        """Server reflects suffix-trick origin => validation weakness."""
        def side_effect(url, origin, **kwargs):
            if origin == DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(acao=None, body="<html>ok</html>")
            if origin == SECONDARY_ATTACKER_ORIGIN:
                return _mock_response(acao=None)
            if origin is None:
                return _mock_response(acao=None, body="<html></html>")
            # Reflect suffix bypass origins
            if "evil-attacker-test.com" in (origin or "") and origin != DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(acao=origin, acac=None)
            return _mock_response(acao=None)

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        self.assertIn(result["risk_level"], ["HIGH", "CRITICAL"])
        bypass_findings = [f for f in result["findings"] if "Bypass" in f.get("title", "")]
        self.assertTrue(len(bypass_findings) > 0)

    # ------------------------------------------------------------------
    # TEST 9: Dynamic origin reflection without Vary: Origin
    # ------------------------------------------------------------------
    def test_missing_vary_origin(self):
        """Dynamic reflection without Vary: Origin => MEDIUM warning."""
        def side_effect(url, origin, **kwargs):
            if origin == DEFAULT_ATTACKER_ORIGIN:
                return _mock_response(acao=DEFAULT_ATTACKER_ORIGIN, vary=None, body="ok")
            if origin == SECONDARY_ATTACKER_ORIGIN:
                return _mock_response(acao=SECONDARY_ATTACKER_ORIGIN, vary=None)
            if origin is None:
                return _mock_response(acao=None, body="<html></html>")
            return _mock_response(acao=origin, vary=None)

        result = self._run_scan(side_effect)
        self.assertTrue(result["success"])
        vary_findings = [f for f in result["findings"] if "Vary" in f.get("title", "")]
        self.assertTrue(len(vary_findings) > 0)
        self.assertEqual(vary_findings[0]["severity"], "MEDIUM")

    # ------------------------------------------------------------------
    # TEST 10: Malformed / unreachable target
    # ------------------------------------------------------------------
    def test_unreachable_target(self):
        """Connection error on first request => graceful error, no crash."""
        def side_effect(url, origin, **kwargs):
            return _mock_fail("Connection error")

        result = self._run_scan(side_effect)
        self.assertFalse(result["success"])
        self.assertEqual(result["risk_level"], "LOW")
        self.assertIn("error", result)
        self.assertEqual(len(result["findings"]), 0)


class TestScoringServiceCors(unittest.TestCase):
    """Validate that the scoring service correctly handles CORS dedup."""

    def setUp(self):
        self.mock_headers = {
            "headers": {
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin"
            }
        }
        self.mock_ssl = {"success": True, "ssl_enabled": True}

    def test_dedup_single_high_penalty(self):
        """Multiple HIGH+MEDIUM findings should apply only ONE highest penalty."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from services.scoring_service import calculate_score

        cors_result = {
            "success": True,
            "risk_level": "HIGH",
            "findings": [
                {"severity": "HIGH", "issue": "Arbitrary origin reflected with credentials"},
                {"severity": "MEDIUM", "issue": "Missing Vary: Origin"},
                {"severity": "MEDIUM", "issue": "Null origin accepted"},
            ]
        }
        result = calculate_score(self.mock_headers, self.mock_ssl, {}, cors=cors_result)
        # Only -15 for HIGH (not -15 + -5 + -5 = -25)
        self.assertEqual(result["security_score"], 85)

    def test_critical_penalty(self):
        """A CRITICAL finding should deduct exactly 25."""
        from services.scoring_service import calculate_score

        cors_result = {
            "success": True,
            "risk_level": "CRITICAL",
            "findings": [
                {"severity": "CRITICAL", "issue": "Confirmed exploitable CORS"},
                {"severity": "HIGH", "issue": "Also high"},
            ]
        }
        result = calculate_score(self.mock_headers, self.mock_ssl, {}, cors=cors_result)
        self.assertEqual(result["security_score"], 75)

    def test_no_penalty_for_info(self):
        """INFO-only findings should incur zero penalty."""
        from services.scoring_service import calculate_score

        cors_result = {
            "success": True,
            "risk_level": "LOW",
            "findings": [
                {"severity": "INFO", "issue": "No CORS misconfiguration detected"},
            ]
        }
        result = calculate_score(self.mock_headers, self.mock_ssl, {}, cors=cors_result)
        self.assertEqual(result["security_score"], 100)


if __name__ == "__main__":
    unittest.main()
