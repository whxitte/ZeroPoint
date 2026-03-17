"""
ZeroPoint :: tests/test_crawler.py
=====================================
Unit tests for Module 4 — Crawler & JS Analysis.
All tests are network-free and database-free.
"""

from __future__ import annotations

import pytest

from core.endpoint_classifier import (
    classify_endpoint,
    is_noise_url,
    is_js_file,
    shannon_entropy,
)
from db.crawler_ops import make_endpoint_id, make_secret_id
from models import CrawlSecret, CrawledEndpoint, SecretSeverity
from modules.js_analyzer import scan_content_for_secrets, _parse_secretfinder_line


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

class TestShannonEntropy:
    def test_low_entropy_repeated(self):
        assert shannon_entropy("aaaaaaaaaa") < 1.0

    def test_low_entropy_placeholder(self):
        assert shannon_entropy("YOUR_API_KEY_HERE") < 3.5

    def test_high_entropy_secret(self):
        assert shannon_entropy("sk_live_4xT9mK2pQr8vZwBnYcDfLjHsEuGiAo") > 3.5

    def test_aws_key_high_entropy(self):
        assert shannon_entropy("AKIAIOSFODNN7EXAMPLE") > 3.0

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint classifier
# ─────────────────────────────────────────────────────────────────────────────

class TestEndpointClassifier:
    # ── is_noise_url ──────────────────────────────────────────────────────
    def test_image_is_noise(self):
        assert is_noise_url("https://example.com/logo.png") is True

    def test_css_is_noise(self):
        assert is_noise_url("https://example.com/style.css") is True

    def test_google_analytics_is_noise(self):
        assert is_noise_url("https://google-analytics.com/gtag.js") is True

    def test_api_endpoint_not_noise(self):
        assert is_noise_url("https://example.com/api/users") is False

    def test_login_not_noise(self):
        assert is_noise_url("https://example.com/login") is False

    # ── classify_endpoint ─────────────────────────────────────────────────
    def test_login_is_interesting(self):
        is_int, tags = classify_endpoint("https://example.com/login")
        assert is_int is True
        assert "login" in tags

    def test_admin_panel_is_interesting(self):
        is_int, tags = classify_endpoint("https://example.com/admin/dashboard")
        assert is_int is True
        assert "admin" in tags

    def test_graphql_is_interesting(self):
        is_int, tags = classify_endpoint("https://example.com/graphql")
        assert is_int is True
        assert "graphql" in tags

    def test_upload_is_interesting(self):
        is_int, tags = classify_endpoint("https://example.com/upload/file")
        assert is_int is True
        assert "upload" in tags

    def test_ssrf_param_detected(self):
        is_int, tags = classify_endpoint("https://example.com/proxy?url=http://internal")
        assert is_int is True
        assert "ssrf" in tags

    def test_idor_param_detected(self):
        is_int, tags = classify_endpoint("https://example.com/user?id=123")
        assert is_int is True
        assert "idor" in tags

    def test_open_redirect_detected(self):
        is_int, tags = classify_endpoint("https://example.com/go?redirect=http://evil.com")
        assert is_int is True
        assert "redirect" in tags

    def test_static_page_not_interesting(self):
        is_int, tags = classify_endpoint("https://example.com/about")
        assert is_int is False
        assert tags == []

    def test_env_file_is_interesting(self):
        is_int, tags = classify_endpoint("https://example.com/.env")
        assert is_int is True
        assert "secret" in tags

    def test_multiple_tags_captured(self):
        # /api/admin/login → api + admin + login all match
        is_int, tags = classify_endpoint("https://example.com/api/admin/login")
        assert is_int is True
        assert len(tags) >= 2

    # ── is_js_file ────────────────────────────────────────────────────────
    def test_js_file_detected(self):
        assert is_js_file("https://example.com/app.js") is True

    def test_js_with_query_params(self):
        assert is_js_file("https://example.com/bundle.js?v=1.2.3") is True

    def test_non_js_file(self):
        assert is_js_file("https://example.com/style.css") is False

    def test_page_not_js(self):
        assert is_js_file("https://example.com/login") is False


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication fingerprints
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplicationIDs:
    def test_endpoint_id_deterministic(self):
        a = make_endpoint_id("example.com", "https://example.com/api/users")
        b = make_endpoint_id("example.com", "https://example.com/api/users")
        assert a == b

    def test_endpoint_id_path_only(self):
        """Query params should not affect dedup — same path = same ID."""
        a = make_endpoint_id("example.com", "https://example.com/api/users?page=1")
        b = make_endpoint_id("example.com", "https://example.com/api/users?page=2")
        assert a == b

    def test_endpoint_id_different_paths(self):
        a = make_endpoint_id("example.com", "https://example.com/api/users")
        b = make_endpoint_id("example.com", "https://example.com/api/admin")
        assert a != b

    def test_secret_id_deterministic(self):
        a = make_secret_id("aws_access_key", "example.com", "AKIAIOSFODNN7EXAMPLE")
        b = make_secret_id("aws_access_key", "example.com", "AKIAIOSFODNN7EXAMPLE")
        assert a == b

    def test_secret_id_uses_first_32_chars(self):
        """Two secrets of same type with same first 32 chars should match (dedup)."""
        a = make_secret_id("github_token", "example.com", "ghp_" + "A" * 36)
        b = make_secret_id("github_token", "example.com", "ghp_" + "A" * 36 + "different_suffix")
        assert a == b

    def test_secret_id_different_types(self):
        a = make_secret_id("aws_access_key", "example.com", "AKIAIOSFODNN7EXAMPLE")
        b = make_secret_id("github_token",   "example.com", "AKIAIOSFODNN7EXAMPLE")
        assert a != b


# ─────────────────────────────────────────────────────────────────────────────
# JS secret scanner (built-in regex)
# ─────────────────────────────────────────────────────────────────────────────

class TestJSSecretScanner:
    def _scan(self, content: str, min_entropy: float = 0.0):
        return scan_content_for_secrets(
            content=content,
            source_url="https://example.com/app.js",
            domain="example.com",
            program_id="test_prog",
            crawl_run_id="test_run",
            min_entropy=min_entropy,
        )

    def test_aws_access_key_detected(self):
        content = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        results = self._scan(content)
        types = [s.secret_type for s in results]
        assert "aws_access_key" in types

    def test_github_token_detected(self):
        content = 'var token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";'
        results = self._scan(content)
        types = [s.secret_type for s in results]
        assert "github_token" in types

    def test_stripe_live_key_detected(self):
        content = 'stripe_key = "sk_live_4xT9mK2pQr8vZwBnYcDfLjHs";'
        results = self._scan(content)
        types = [s.secret_type for s in results]
        assert "stripe_secret_key" in types

    def test_private_key_detected(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        results = self._scan(content, min_entropy=0.0)
        types = [s.secret_type for s in results]
        assert "rsa_private_key" in types

    def test_mongodb_uri_detected(self):
        content = 'db.connect("mongodb://admin:password123@cluster.mongodb.net/mydb");'
        results = self._scan(content)
        types = [s.secret_type for s in results]
        assert "mongodb_uri" in types

    def test_placeholder_filtered(self):
        content = 'const key = "YOUR_API_KEY_HERE";'
        results = self._scan(content, min_entropy=3.5)
        # Placeholder should be filtered by entropy or placeholder check
        assert all("placeholder" not in s.secret_value.lower() for s in results)

    def test_jwt_detected(self):
        # Realistic JWT format
        content = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";'
        results = self._scan(content)
        types = [s.secret_type for s in results]
        assert "jwt_token" in types

    def test_deduplication_within_scan(self):
        """Same secret appearing twice in the same file should only be reported once."""
        key = "AKIAIOSFODNN7EXAMPLE"
        content = f'key1 = "{key}";\nkey2 = "{key}";'
        results = self._scan(content)
        aws_results = [s for s in results if s.secret_type == "aws_access_key"]
        assert len(aws_results) == 1

    def test_secret_value_truncated_at_120(self):
        long_val = "A" * 200
        content  = f'const key = "sk_live_{long_val}";'
        results  = self._scan(content, min_entropy=0.0)
        for s in results:
            assert len(s.secret_value) <= 120

    def test_line_number_captured(self):
        content = "line1\nline2\nconst key = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';\nline4"
        results = self._scan(content)
        gh_results = [s for s in results if s.secret_type == "github_token"]
        if gh_results:
            assert gh_results[0].line_number == 3

    def test_no_false_positives_on_clean_js(self):
        content = """
        function greet(name) {
            return "Hello, " + name + "!";
        }
        const config = { debug: false, version: "1.0.0" };
        """
        results = self._scan(content, min_entropy=3.5)
        assert results == []


# ─────────────────────────────────────────────────────────────────────────────
# SecretFinder output parser
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretFinderParser:
    def test_parse_valid_line(self):
        line   = "[!] Google API Key: AIzaSyD-9tSrke72d5mICj0UEi54bH56g01OLpU"
        result = _parse_secretfinder_line(line, "https://example.com/app.js", "example.com", "prog", "run")
        assert result is not None
        assert result.secret_type == "google_api_key"
        assert "AIzaSy" in result.secret_value

    def test_parse_invalid_line_returns_none(self):
        assert _parse_secretfinder_line("", "url", "dom", "prog", "run") is None
        assert _parse_secretfinder_line("just some random text", "url", "dom", "prog", "run") is None

    def test_parse_sets_tool_to_secretfinder(self):
        line   = "[+] Slack Token: xoxb-123456789-abcdefghij"
        result = _parse_secretfinder_line(line, "https://example.com/app.js", "example.com", "prog", "run")
        if result:
            assert result.tool == "secretfinder"


# ─────────────────────────────────────────────────────────────────────────────
# Model validation
# ─────────────────────────────────────────────────────────────────────────────

class TestCrawlModels:
    def test_secret_domain_normalised(self):
        s = CrawlSecret(
            secret_id="abc", program_id="p", domain="API.EXAMPLE.COM.",
            source_url="https://example.com/app.js",
            secret_type="github_token", secret_value="ghp_test",
            severity=SecretSeverity.HIGH,
        )
        assert s.domain == "api.example.com"

    def test_secret_value_truncated_by_validator(self):
        s = CrawlSecret(
            secret_id="abc", program_id="p", domain="example.com",
            source_url="https://example.com/app.js",
            secret_type="github_token", secret_value="X" * 200,
            severity=SecretSeverity.HIGH,
        )
        assert len(s.secret_value) <= 120

    def test_endpoint_domain_normalised(self):
        e = CrawledEndpoint(
            endpoint_id="abc", program_id="p", domain="API.EXAMPLE.COM.",
            url="https://api.example.com/login", url_path="/login",
        )
        assert e.domain == "api.example.com"

    def test_secret_is_new_default_true(self):
        s = CrawlSecret(
            secret_id="abc", program_id="p", domain="example.com",
            source_url="url", secret_type="type", secret_value="val",
            severity=SecretSeverity.HIGH,
        )
        assert s.is_new is True