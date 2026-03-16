"""
ZeroPoint :: tests/test_prober.py
==================================
Unit tests for Module 2 — Prober & Fingerprint Engine.

All tests are network-free and database-free.
"""

from __future__ import annotations

import json
import pytest

from models import InterestLevel, ProbeResult, ProbeStatus
from modules.prober import HttpxProber, _parse_httpx_line, _parse_response_time
from core.fingerprint import FingerprintClassifier


# ─────────────────────────────────────────────────────────────────────────────
# Response-time parser
# ─────────────────────────────────────────────────────────────────────────────

class TestParseResponseTime:
    def test_milliseconds(self):
        assert _parse_response_time("123ms")   == 123
        assert _parse_response_time("45.6ms")  == 45

    def test_seconds(self):
        assert _parse_response_time("1.5s")    == 1500
        assert _parse_response_time("0.250s")  == 250

    def test_none(self):
        assert _parse_response_time(None) is None
        assert _parse_response_time("")   is None

    def test_malformed(self):
        assert _parse_response_time("fast") is None


# ─────────────────────────────────────────────────────────────────────────────
# httpx JSON line parser
# ─────────────────────────────────────────────────────────────────────────────

class TestParseHttpxLine:
    def _make_line(self, **kwargs) -> str:
        defaults = {
            "host":          "api.example.com",
            "status-code":   200,
            "title":         "API Gateway",
            "webserver":     "nginx",
            "content-type":  "text/html; charset=utf-8",
            "tech":          ["Nginx:1.24", "PHP:8.1"],
            "cdn":           "Cloudflare",
            "content-length": 4096,
            "response-time": "55ms",
            "a":             ["1.2.3.4"],
        }
        defaults.update(kwargs)
        return json.dumps(defaults)

    def test_basic_parse(self):
        result = _parse_httpx_line(self._make_line())
        assert result is not None
        assert result.domain        == "api.example.com"
        assert result.http_status   == 200
        assert result.http_title    == "API Gateway"
        assert result.web_server    == "nginx"
        assert result.probe_status  == ProbeStatus.ALIVE
        assert "Nginx" in result.technologies
        assert "PHP"   in result.technologies
        assert result.response_time_ms == 55
        assert "1.2.3.4" in result.ip_addresses

    def test_tech_version_stripped(self):
        result = _parse_httpx_line(self._make_line(tech=["WordPress:6.4", "MySQL:8.0"]))
        assert result is not None
        assert "WordPress" in result.technologies
        assert "MySQL"     in result.technologies
        # Version numbers should be gone
        assert not any(":" in t for t in result.technologies)

    def test_content_type_stripped(self):
        result = _parse_httpx_line(self._make_line(**{"content-type": "text/html; charset=utf-8"}))
        assert result is not None
        assert result.content_type == "text/html"

    def test_no_status_code_means_dead(self):
        line = json.dumps({"host": "dead.example.com"})
        result = _parse_httpx_line(line)
        assert result is not None
        assert result.probe_status == ProbeStatus.DEAD

    def test_domain_normalised(self):
        result = _parse_httpx_line(self._make_line(host="API.EXAMPLE.COM"))
        assert result is not None
        assert result.domain == "api.example.com"

    def test_url_fallback_when_no_host(self):
        line = json.dumps({"url": "https://fallback.example.com/path", "status-code": 200})
        result = _parse_httpx_line(line)
        assert result is not None
        assert result.domain == "fallback.example.com"

    def test_port_stripped_from_host(self):
        result = _parse_httpx_line(self._make_line(host="api.example.com:8080"))
        assert result is not None
        assert result.domain == "api.example.com"

    def test_invalid_json_returns_none(self):
        assert _parse_httpx_line("not json at all {{") is None

    def test_empty_line_returns_none(self):
        assert _parse_httpx_line("{}") is None  # no host key


# ─────────────────────────────────────────────────────────────────────────────
# Fingerprint Classifier
# ─────────────────────────────────────────────────────────────────────────────

def _make_probe(
    domain:       str = "sub.example.com",
    status:       int = 200,
    technologies: list = None,
    title:        str = "",
    web_server:   str = "",
    probe_status: ProbeStatus = ProbeStatus.ALIVE,
) -> ProbeResult:
    return ProbeResult(
        domain=domain,
        probe_status=probe_status,
        http_status=status,
        http_title=title,
        web_server=web_server,
        technologies=technologies or [],
    )


class TestFingerprintClassifier:
    clf = FingerprintClassifier()

    # ── CRITICAL detections ───────────────────────────────────────────────

    def test_jenkins_in_tech_is_critical(self):
        probe = _make_probe(technologies=["Jenkins"])
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL
        assert any("jenkins" in r.lower() for r in result.interest_reasons)

    def test_admin_subdomain_is_critical(self):
        probe = _make_probe(domain="admin.example.com")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL

    def test_admin_in_title_is_critical(self):
        probe = _make_probe(title="Admin Dashboard — Internal")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL

    def test_grafana_tech_is_critical(self):
        probe = _make_probe(technologies=["Grafana"])
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL

    def test_gitlab_subdomain_is_critical(self):
        probe = _make_probe(domain="gitlab.example.com")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL

    def test_kibana_in_title_is_critical(self):
        probe = _make_probe(title="Kibana")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL

    # ── HIGH detections ───────────────────────────────────────────────────

    def test_wordpress_is_high(self):
        probe = _make_probe(technologies=["WordPress"])
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.HIGH

    def test_401_status_is_high(self):
        probe = _make_probe(status=401)
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.HIGH

    def test_swagger_title_is_high(self):
        probe = _make_probe(title="Swagger UI")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.HIGH

    def test_api_subdomain_is_high(self):
        probe = _make_probe(domain="api.example.com")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.HIGH

    def test_staging_subdomain_is_high(self):
        probe = _make_probe(domain="staging.example.com")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.HIGH

    # ── Highest level wins when multiple rules fire ───────────────────────

    def test_highest_level_wins(self):
        """A domain that triggers both HIGH and CRITICAL rules → CRITICAL wins."""
        probe = _make_probe(
            domain="jenkins.example.com",
            technologies=["Jenkins"],
            title="Jenkins Dashboard",
        )
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.CRITICAL
        assert len(result.interest_reasons) >= 2  # multiple reasons captured

    # ── Dead hosts are always NOISE ───────────────────────────────────────

    def test_dead_host_is_noise(self):
        probe = _make_probe(
            domain="admin.example.com",   # would be CRITICAL if alive
            probe_status=ProbeStatus.DEAD,
        )
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.NOISE

    def test_error_host_is_noise(self):
        probe = _make_probe(probe_status=ProbeStatus.ERROR)
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.NOISE

    # ── Reason deduplication ─────────────────────────────────────────────

    def test_reasons_deduplicated(self):
        probe = _make_probe(
            technologies=["Jenkins", "Jenkins"],  # deliberate duplicate
        )
        result = self.clf.classify(probe)
        jenkins_reasons = [r for r in result.interest_reasons if "jenkins" in r.lower()]
        assert len(jenkins_reasons) == 1

    # ── NOISE cases ───────────────────────────────────────────────────────

    def test_coming_soon_title_is_noise(self):
        probe = _make_probe(title="Coming Soon")
        result = self.clf.classify(probe)
        assert result.interest_level == InterestLevel.NOISE

    def test_low_interest_baseline(self):
        """Plain subdomain with no interesting signals → LOW."""
        probe = _make_probe(domain="cdn-01.example.com", technologies=["Varnish"])
        result = self.clf.classify(probe)
        # cdn. prefix → LOW; Varnish has no special rule → LOW is expected baseline
        assert result.interest_level in (InterestLevel.LOW, InterestLevel.NOISE)

    # ── Immutability — classify returns a new object ─────────────────────

    def test_classify_does_not_mutate_input(self):
        probe = _make_probe()
        original_level = probe.interest_level
        _ = self.clf.classify(probe)
        assert probe.interest_level == original_level


# ─────────────────────────────────────────────────────────────────────────────
# HttpxProber command builder
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpxProberCommandBuilder:
    def test_default_flags_present(self):
        prober = HttpxProber()
        cmd = prober._build_command("/tmp/targets.txt")
        assert "-json"        in cmd
        assert "-silent"      in cmd
        assert "-tech-detect" in cmd
        assert "-status-code" in cmd
        assert "-title"       in cmd
        assert "-random-agent" in cmd
        assert "/tmp/targets.txt" in cmd

    def test_follow_redirects_flag(self):
        prober = HttpxProber(follow_redirects=True)
        cmd = prober._build_command("/tmp/x.txt")
        assert "-follow-redirects" in cmd

    def test_no_follow_redirects(self):
        prober = HttpxProber(follow_redirects=False)
        cmd = prober._build_command("/tmp/x.txt")
        assert "-follow-redirects" not in cmd

    def test_threads_and_rate_in_command(self):
        prober = HttpxProber(threads=75, rate_limit=200)
        cmd = prober._build_command("/tmp/x.txt")
        assert "75"  in cmd
        assert "200" in cmd

    def test_screenshot_disabled_by_default(self):
        prober = HttpxProber(screenshot=False)
        cmd = prober._build_command("/tmp/x.txt")
        assert "-screenshot" not in cmd

    @pytest.mark.asyncio
    async def test_empty_domain_list_yields_nothing(self):
        prober = HttpxProber()
        results = []
        async for r in prober.probe([]):
            results.append(r)
        assert results == []

    @pytest.mark.asyncio
    async def test_missing_binary_yields_nothing(self):
        prober = HttpxProber(binary_path="/nonexistent/httpx")
        from unittest.mock import patch
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            results = []
            async for r in prober.probe(["example.com"]):
                results.append(r)
        assert results == []
