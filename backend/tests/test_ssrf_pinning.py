import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.url_validator import (
    validate_public_url,
    PinnedIPAdapter,
    safe_request,
    safe_get,
)
from scanners.headers_scanner import scan_headers
from scanners.ssl_scanner import scan_ssl
from scanners.port_scanner import scan_ports
from scanners.dns_scanner import scan_dns
from scanners.info_scanner import scan_info
from scanners.seo_scanner import scan_seo
from scanners.technology_scanner import scan_technology
from scanners.performance_scanner import scan_performance
from scanners.cors_scanner import scan_cors
from scanners.exposed_paths_scanner import scan_exposed_paths


class TestSSRFIPPinning(unittest.TestCase):

    def test_validate_public_url_returns_ip(self):
        """validate_public_url returns (True, resolved_ip, '') for public hosts."""
        with patch("services.url_validator.socket.gethostbyname", return_value="93.184.216.34"):
            is_valid, resolved_ip, reason = validate_public_url("https://example.com")
            self.assertTrue(is_valid)
            self.assertEqual(resolved_ip, "93.184.216.34")
            self.assertEqual(reason, "")

    def test_pinned_ip_adapter_connection_override(self):
        """PinnedIPAdapter overrides connection pool URL with pinned_ip while setting SNI host."""
        adapter = PinnedIPAdapter("93.184.216.34")
        with patch.object(adapter, "get_connection", wraps=adapter.get_connection) as mock_conn:
            with patch("requests.adapters.HTTPAdapter.get_connection") as super_get_conn:
                mock_pool = MagicMock()
                super_get_conn.return_value = mock_pool
                
                conn = adapter.get_connection("https://example.com/test")
                
                # Super get_connection should be called with pinned_ip in host URL
                super_get_conn.assert_called_once_with("https://93.184.216.34:443", proxies=None)
                self.assertEqual(mock_pool.assert_hostname, "example.com")
                self.assertEqual(mock_pool.server_hostname, "example.com")

    def test_safe_get_uses_pinned_ip_adapter(self):
        """safe_get mounts PinnedIPAdapter when pinned_ip is supplied."""
        with patch("requests.Session.request") as mock_request:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_request.return_value = mock_resp
            
            resp = safe_get("https://example.com", pinned_ip="93.184.216.34", timeout=5)
            self.assertEqual(resp.status_code, 200)
            mock_request.assert_called_once_with("GET", "https://example.com", timeout=5)

    def test_raw_socket_scanners_honor_pinned_ip(self):
        """ssl_scanner and port_scanner use pinned_ip directly without extra DNS resolution."""
        # SSL Scanner
        with patch("socket.create_connection") as mock_conn:
            with patch("ssl.create_default_context") as mock_ctx:
                mock_sock = MagicMock()
                mock_ssock = MagicMock()
                mock_ssock.getpeercert.return_value = {
                    "notAfter": "Nov 17 00:00:00 2026 GMT",
                    "notBefore": "Nov 17 00:00:00 2025 GMT",
                    "issuer": ((("commonName", "Test CA"),),),
                    "subject": ((("commonName", "example.com"),),),
                }
                mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", None)
                mock_ssock.version.return_value = "TLSv1.3"
                
                mock_ctx_inst = MagicMock()
                mock_ctx_inst.wrap_socket.return_value.__enter__.return_value = mock_ssock
                mock_ctx.return_value = mock_ctx_inst
                mock_conn.return_value.__enter__.return_value = mock_sock

                res = scan_ssl("https://example.com", pinned_ip="93.184.216.34")
                self.assertTrue(res["success"])
                # Ensure create_connection connected to the pinned IP
                mock_conn.assert_called_once_with(("93.184.216.34", 443), timeout=5)

        # Port Scanner
        with patch("socket.gethostbyname") as mock_dns:
            with patch("socket.socket") as mock_sock_cls:
                mock_s = MagicMock()
                mock_s.connect_ex.return_value = 1
                mock_sock_cls.return_value = mock_s
                
                res = scan_ports("https://example.com", pinned_ip="93.184.216.34")
                self.assertTrue(res["success"])
                self.assertEqual(res["ip_address"], "93.184.216.34")
                # gethostbyname should NOT be called when pinned_ip is provided
                mock_dns.assert_not_called()

    def test_scanner_signatures_accept_pinned_ip(self):
        """Verify all scanners accept pinned_ip=None without raising TypeError."""
        with patch("scanners.headers_scanner.safe_get") as m_headers:
            m_headers.return_value.headers = {}
            scan_headers("https://example.com", pinned_ip="93.184.216.34")
            m_headers.assert_called_once()
            self.assertEqual(m_headers.call_args[1].get("pinned_ip"), "93.184.216.34")

        with patch("scanners.seo_scanner.safe_get") as m_seo:
            m_seo.return_value.text = "<html><title>Test</title></html>"
            scan_seo("https://example.com", pinned_ip="93.184.216.34")
            m_seo.assert_called_once()
            self.assertEqual(m_seo.call_args[1].get("pinned_ip"), "93.184.216.34")

        with patch("scanners.technology_scanner.builtwith.parse", return_value={}):
            with patch("scanners.technology_scanner.safe_get") as m_tech:
                m_tech.return_value.text = "<html></html>"
                m_tech.return_value.headers = {}
                m_tech.return_value.cookies.keys.return_value = []
                scan_technology("https://example.com", pinned_ip="93.184.216.34")
                m_tech.assert_called_once()
                self.assertEqual(m_tech.call_args[1].get("pinned_ip"), "93.184.216.34")

        with patch("scanners.dns_scanner.dns.resolver.resolve", side_effect=Exception):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                res = scan_dns("https://example.com", pinned_ip="93.184.216.34")
                self.assertTrue(res["success"])

        with patch("scanners.info_scanner.get_rdap_info", return_value={"success": False}):
            with patch("scanners.info_scanner.get_socket_whois_info", return_value={"success": False}):
                with patch("requests.get") as m_geo:
                    res = scan_info("https://example.com", pinned_ip="93.184.216.34")
                    self.assertTrue(res["success"])
                    self.assertEqual(res["ip_address"], "93.184.216.34")


if __name__ == "__main__":
    unittest.main()
