"""
ZeroPoint :: tests/test_scanner.py
=====================================
Unit tests for Module 3 — Scanner & Findings Engine.
All tests are network-free and database-free.
"""

from __future__ import annotations

import json

import pytest

from models import Finding, ScanRun, ScanSeverity
from modules.nuclei import (
    NucleiScanner,
    _parse_nuclei_line,
    build_template_tags,
    make_finding_id,
)


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication fingerprint
# ─────────────────────────────────────────────────────────────────────────────

class TestMakeFindingId:
    def test_same_inputs_same_hash(self):
        a = make_finding_id("CVE-2021-44228", "api.example.com", "https://api.example.com/")
        b = make_finding_id("CVE-2021-44228", "api.example.com", "https://api.example.com/")
        assert a == b

    def test_different_template_different_hash(self):
        a = make_finding_id("CVE-2021-44228", "api.example.com", "https://api.example.com/")
        b = make_finding_id("CVE-2021-45046", "api.example.com", "https://api.example.com/")
        assert a != b

    def test_different_domain_different_hash(self):
        a = make_finding_id("CVE-2021-44228", "api.example.com",  "https://api.example.com/")
        b = make_finding_id("CVE-2021-44228", "app2.example.com", "https://app2.example.com/")
        assert a != b

    def test_case_insensitive(self):
        a = make_finding_id("cve-2021-44228", "api.example.com", "https://api.example.com/")
        b = make_finding_id("CVE-2021-44228", "API.EXAMPLE.COM", "HTTPS://API.EXAMPLE.COM/")
        assert a == b

    def test_hash_is_64_char_hex(self):
        h = make_finding_id("template", "example.com", "https://example.com/")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ─────────────────────────────────────────────────────────────────────────────
# Nuclei JSON line parser
# ─────────────────────────────────────────────────────────────────────────────

def _make_nuclei_line(**kwargs) -> str:
    defaults = {
        "template-id": "CVE-2021-44228",
        "info": {
            "name":        "Log4j RCE",
            "severity":    "critical",
            "description": "Log4Shell RCE vulnerability",
            "reference":   ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "tags":        ["cve", "rce", "log4j", "critical"],
        },
        "host":       "api.example.com",
        "matched-at": "https://api.example.com/login",
        "matcher-name": "jndi-callback",
        "curl-command": "curl -X POST https://api.example.com/login -d '${jndi:...}'",
        "request":    "POST /login HTTP/1.1\nHost: api.example.com\n",
        "response":   "HTTP/1.1 200 OK\n",
        "extracted-results": ["10.0.0.1"],
    }
    defaults.update(kwargs)
    return json.dumps(defaults)


class TestParseNucleiLine:
    def test_basic_parse(self):
        result = _parse_nuclei_line(
            _make_nuclei_line(),
            program_id="test_prog",
            scan_run_id="run_001",
        )
        assert result is not None
        assert result.domain        == "api.example.com"
        assert result.template_id   == "CVE-2021-44228"
        assert result.template_name == "Log4j RCE"
        assert result.severity      == ScanSeverity.CRITICAL
        assert result.matched_at    == "https://api.example.com/login"
        assert result.matcher_name  == "jndi-callback"
        assert "cve" in result.tags
        assert "10.0.0.1" in result.extracted_results
        assert result.program_id    == "test_prog"
        assert result.scan_run_id   == "run_001"

    def test_finding_id_deterministic(self):
        r1 = _parse_nuclei_line(_make_nuclei_line(), "prog", "run1")
        r2 = _parse_nuclei_line(_make_nuclei_line(), "prog", "run2")
        # Same vuln, same endpoint → same dedup hash regardless of run_id
        assert r1.finding_id == r2.finding_id

    def test_severity_mapping_high(self):
        result = _parse_nuclei_line(
            _make_nuclei_line(**{"info": {
                "name": "Test", "severity": "high",
                "reference": [], "tags": [],
            }}),
            "prog", "run",
        )
        assert result.severity == ScanSeverity.HIGH

    def test_severity_mapping_unknown(self):
        result = _parse_nuclei_line(
            _make_nuclei_line(**{"info": {
                "name": "Test", "severity": "bogus_level",
                "reference": [], "tags": [],
            }}),
            "prog", "run",
        )
        assert result.severity == ScanSeverity.UNKNOWN

    def test_request_truncated_at_3000(self):
        long_req = "A" * 5000
        result = _parse_nuclei_line(
            _make_nuclei_line(request=long_req),
            "prog", "run",
        )
        assert result is not None
        assert len(result.request) <= 3000

    def test_response_truncated_at_2000(self):
        long_resp = "B" * 4000
        result = _parse_nuclei_line(
            _make_nuclei_line(response=long_resp),
            "prog", "run",
        )
        assert result is not None
        assert len(result.response) <= 2000

    def test_domain_extracted_from_host(self):
        result = _parse_nuclei_line(
            _make_nuclei_line(host="https://sub.example.com"),
            "prog", "run",
        )
        assert result is not None
        assert result.domain == "sub.example.com"

    def test_domain_normalised_lowercase(self):
        result = _parse_nuclei_line(
            _make_nuclei_line(host="API.EXAMPLE.COM"),
            "prog", "run",
        )
        assert result is not None
        assert result.domain == "api.example.com"

    def test_missing_template_id_returns_none(self):
        line = json.dumps({
            "info": {"name": "X", "severity": "high"},
            "host": "x.example.com",
            "matched-at": "https://x.example.com/",
        })
        result = _parse_nuclei_line(line, "prog", "run")
        assert result is None

    def test_missing_matched_at_returns_none(self):
        line = json.dumps({
            "template-id": "some-template",
            "info":        {"name": "X", "severity": "high"},
            "host":        "x.example.com",
        })
        result = _parse_nuclei_line(line, "prog", "run")
        assert result is None

    def test_invalid_json_returns_none(self):
        assert _parse_nuclei_line("{not valid json!!", "prog", "run") is None

    def test_curl_command_captured(self):
        result = _parse_nuclei_line(_make_nuclei_line(), "prog", "run")
        assert result is not None
        assert "curl" in result.curl_command


# ─────────────────────────────────────────────────────────────────────────────
# Smart Template Tag Builder
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildTemplateTags:
    def test_jenkins_gives_critical_tags(self):
        tags = build_template_tags(["Jenkins"], "critical")
        assert "jenkins" in tags

    def test_wordpress_gives_wp_tags(self):
        tags = build_template_tags(["WordPress"], "high")
        assert "wordpress" in tags or "wp" in tags

    def test_always_includes_defaults(self):
        tags = build_template_tags([], "low")
        # Default tags should always be present
        assert "exposure" in tags or "misconfig" in tags or "takeover" in tags

    def test_unknown_tech_critical_gets_wide_net(self):
        tags = build_template_tags(["SomeBizarreFramework"], "critical")
        # Should fall back to broad auth-bypass tags
        assert any(t in tags for t in ["auth-bypass", "unauth", "panel", "default-login"])

    def test_spring_includes_cve_tags(self):
        tags = build_template_tags(["Spring Boot"], "high")
        # Spring4Shell CVEs should be included
        assert any("CVE" in t for t in tags)

    def test_log4j_includes_log4shell(self):
        tags = build_template_tags(["log4j"], "critical")
        assert any("44228" in t for t in tags)

    def test_case_insensitive_tech_matching(self):
        tags_lower = build_template_tags(["wordpress"], "high")
        tags_upper = build_template_tags(["WordPress"], "high")
        assert tags_lower == tags_upper

    def test_multiple_techs_union(self):
        tags_wp      = build_template_tags(["WordPress"], "high")
        tags_jenkins = build_template_tags(["Jenkins"],   "high")
        tags_both    = build_template_tags(["WordPress", "Jenkins"], "high")
        # Union — both sets should be subsets of combined
        assert tags_wp.issubset(tags_both)
        assert tags_jenkins.issubset(tags_both)


# ─────────────────────────────────────────────────────────────────────────────
# NucleiScanner command builder
# ─────────────────────────────────────────────────────────────────────────────

class TestNucleiScannerCommand:
    def test_required_flags_present(self):
        scanner = NucleiScanner()
        cmd     = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert "-jsonl"       in cmd
        assert "-silent"      in cmd
        assert "-nc"          in cmd
        assert "-include-rr"  in cmd
        assert "-severity"    in cmd
        assert "-rate-limit"  in cmd
        assert "/tmp/in.txt"  in cmd

    def test_passive_flag_never_present(self):
        """-passive must NEVER appear — it disables live HTTP requests."""
        for cfg in [
            NucleiScanner(),
            NucleiScanner(enable_fuzzing=True,  fuzzing_templates_path="/tmp"),
            NucleiScanner(enable_fuzzing=False, fuzzing_templates_path="/tmp"),
        ]:
            cmd = cfg._build_command("/tmp/in.txt", "/tmp/out.jsonl")
            assert "-passive" not in cmd, "-passive found in nuclei command — this breaks scanning"

    def test_all_severities_in_default(self):
        """Default severity must cover info through critical for all-finding alerts."""
        scanner  = NucleiScanner()
        cmd_str  = " ".join(scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl"))
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in cmd_str, f"Severity '{sev}' missing from default command"

    def test_nonexistent_template_path_silently_skipped(self):
        """Placeholder / missing paths must never reach the nuclei command."""
        scanner = NucleiScanner(
            templates_path           = "/path/to/nuclei-templates",   # placeholder
            community_templates_path = "/path/to/community",          # placeholder
            custom_templates         = "/no/such/directory",
        )
        cmd = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert "/path/to/nuclei-templates" not in cmd
        assert "/path/to/community"        not in cmd
        assert "/no/such/directory"        not in cmd
        # No -t flag should appear
        assert "-t" not in cmd

    def test_valid_template_path_included(self, tmp_path):
        real_dir = tmp_path / "my-templates"
        real_dir.mkdir()
        scanner  = NucleiScanner(templates_path=str(real_dir))
        cmd      = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert "-t"          in cmd
        assert str(real_dir) in cmd

    def test_all_three_valid_sources_in_one_command(self, tmp_path):
        """Three existing dirs → three separate -t flags."""
        dirs = [tmp_path / f"src{i}" for i in range(3)]
        for d in dirs:
            d.mkdir()
        scanner = NucleiScanner(
            templates_path           = str(dirs[0]),
            community_templates_path = str(dirs[1]),
            custom_templates         = str(dirs[2]),
        )
        cmd = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        for d in dirs:
            assert str(d) in cmd
        assert cmd.count("-t") == 3

    def test_fuzzing_dir_added_when_exists_and_enabled(self, tmp_path):
        fuzz_dir = tmp_path / "fuzzing"
        fuzz_dir.mkdir()
        scanner  = NucleiScanner(fuzzing_templates_path=str(fuzz_dir), enable_fuzzing=True)
        cmd      = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert str(fuzz_dir) in cmd
        assert "-passive"    not in cmd   # never -passive

    def test_fuzzing_dir_skipped_when_disabled(self, tmp_path):
        fuzz_dir = tmp_path / "fuzzing"
        fuzz_dir.mkdir()
        scanner  = NucleiScanner(fuzzing_templates_path=str(fuzz_dir), enable_fuzzing=False)
        cmd      = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert str(fuzz_dir) not in cmd

    def test_fuzzing_path_empty_no_extra_flags(self):
        scanner = NucleiScanner(enable_fuzzing=True, fuzzing_templates_path="")
        cmd     = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert "-passive" not in cmd
        assert "-t"       not in cmd    # no -t if path empty

    def test_dos_excluded_by_default(self):
        scanner = NucleiScanner()
        cmd     = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        assert "dos" in " ".join(cmd)

    def test_fuzz_not_in_etags(self):
        """User wants fuzzing enabled — 'fuzz' must not be in the etags list."""
        scanner = NucleiScanner()
        cmd     = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl")
        etags_idx = [i for i, x in enumerate(cmd) if x == "-etags"]
        if etags_idx:
            etag_value = cmd[etags_idx[0] + 1]
            assert "fuzz" not in etag_value

    def test_tags_set_included(self):
        scanner = NucleiScanner()
        cmd     = scanner._build_command("/tmp/in.txt", "/tmp/out.jsonl", tags={"jenkins", "gitlab"})
        assert "-tags"    in cmd
        cmd_str = " ".join(cmd)
        assert "jenkins"  in cmd_str
        assert "gitlab"   in cmd_str

    @pytest.mark.asyncio
    async def test_empty_asset_list_yields_nothing(self):
        scanner = NucleiScanner()
        results = []
        async for f in scanner.scan([], program_id="test", scan_run_id="run"):
            results.append(f)
        assert results == []

    @pytest.mark.asyncio
    async def test_missing_binary_yields_nothing(self):
        from unittest.mock import patch
        scanner = NucleiScanner(binary_path="/no/such/nuclei")

        from models import Asset, InterestLevel, ProbeStatus
        fake_asset = Asset(
            domain="example.com",
            program_id="test",
            probe_status=ProbeStatus.ALIVE,
            interest_level=InterestLevel.HIGH,
        )

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            results = []
            async for f in scanner.scan([fake_asset], "test", "run"):
                results.append(f)
        assert results == []




# ─────────────────────────────────────────────────────────────────────────────
# Deduplication: same finding across two runs = no second alert
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingDeduplication:
    """Verify that the SHA-256 fingerprint ensures idempotent dedup."""

    def test_same_finding_same_run_produces_same_id(self):
        r1 = _parse_nuclei_line(_make_nuclei_line(), "prog", "run_A")
        r2 = _parse_nuclei_line(_make_nuclei_line(), "prog", "run_B")
        assert r1 is not None and r2 is not None
        # Different run IDs must NOT affect the dedup fingerprint
        assert r1.finding_id == r2.finding_id

    def test_different_endpoint_different_id(self):
        r1 = _parse_nuclei_line(
            _make_nuclei_line(**{"matched-at": "https://api.example.com/login"}),
            "prog", "run",
        )
        r2 = _parse_nuclei_line(
            _make_nuclei_line(**{"matched-at": "https://api.example.com/admin"}),
            "prog", "run",
        )
        assert r1 is not None and r2 is not None
        assert r1.finding_id != r2.finding_id

    def test_different_template_different_id(self):
        r1 = _parse_nuclei_line(
            _make_nuclei_line(**{"template-id": "CVE-2021-44228"}),
            "prog", "run",
        )
        r2 = _parse_nuclei_line(
            _make_nuclei_line(**{"template-id": "CVE-2021-45046"}),
            "prog", "run",
        )
        assert r1 is not None and r2 is not None
        assert r1.finding_id != r2.finding_id

    def test_all_severity_levels_parsed(self):
        """Every severity level must parse cleanly — all now alert immediately."""
        for sev in ("critical", "high", "medium", "low", "info"):
            line = _make_nuclei_line(**{
                "info": {"name": "Test", "severity": sev, "reference": [], "tags": []}
            })
            result = _parse_nuclei_line(line, "prog", "run")
            assert result is not None, f"Failed to parse severity: {sev}"
            assert result.severity.value == sev


# ─────────────────────────────────────────────────────────────────────────────
# Finding model
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingModel:
    def test_domain_normalised(self):
        f = Finding(
            finding_id="abc123",
            program_id="prog",
            domain="API.EXAMPLE.COM.",
            template_id="cve-test",
            template_name="Test",
            severity=ScanSeverity.HIGH,
            matched_at="https://api.example.com/",
        )
        assert f.domain == "api.example.com"

    def test_is_new_default_true(self):
        f = Finding(
            finding_id="abc123",
            program_id="prog",
            domain="example.com",
            template_id="cve-test",
            template_name="Test",
            severity=ScanSeverity.CRITICAL,
            matched_at="https://example.com/",
        )
        assert f.is_new is True

    def test_severity_enum_values(self):
        assert ScanSeverity.CRITICAL.value == "critical"
        assert ScanSeverity.HIGH.value     == "high"
        assert ScanSeverity.MEDIUM.value   == "medium"
        assert ScanSeverity.LOW.value      == "low"
        assert ScanSeverity.INFO.value     == "info"


# ─────────────────────────────────────────────────────────────────────────────
# ScanRun model
# ─────────────────────────────────────────────────────────────────────────────

class TestScanRun:
    def test_defaults(self):
        run = ScanRun(program_id="test")
        assert run.targets      == 0
        assert run.findings     == 0
        assert run.new_findings == 0
        assert run.success      is True
        assert run.errors       == []
        assert run.run_id is not None

    def test_run_id_unique(self):
        r1 = ScanRun(program_id="test")
        r2 = ScanRun(program_id="test")
        assert r1.run_id != r2.run_id