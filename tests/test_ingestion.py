"""
ZeroPoint — Unit Tests for Module 1 (Ingestion Engine)

Run with: pytest tests/ -v

Tests use mocking to avoid:
  - Real network calls (crt.sh, Shodan)
  - Real subprocess execution (subfinder)
  - Real MongoDB writes
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models import Asset, AssetSource, AssetStatus, DiscoveredSubdomain, UpsertResult
from modules.recon import CrtshWorker, SubfinderWorker


# ─────────────────────────────────────────────
# Model Tests
# ─────────────────────────────────────────────

class TestAssetModel:
    def test_domain_normalisation(self):
        """Leading wildcards and uppercase should be stripped."""
        a = Asset(domain="  *.API.Example.com  ", program_id="test")
        assert a.domain == "api.example.com"

    def test_sources_coercion_from_string(self):
        """A single string source should be coerced to a list."""
        a = Asset(domain="sub.example.com", program_id="test", sources="subfinder")
        assert a.sources == [AssetSource.SUBFINDER.value]

    def test_is_new_default_true(self):
        a = Asset(domain="sub.example.com", program_id="test")
        assert a.is_new is True

    def test_status_default_unknown(self):
        a = Asset(domain="sub.example.com", program_id="test")
        assert a.status == AssetStatus.UNKNOWN.value


class TestDiscoveredSubdomain:
    def test_normalisation(self):
        d = DiscoveredSubdomain(
            domain="*.SUB.EXAMPLE.COM",
            program_id="p1",
            source=AssetSource.CRTSH,
        )
        assert d.domain == "sub.example.com"


class TestUpsertResult:
    def test_total_property(self):
        r = UpsertResult(new=["a.com", "b.com"], updated=["c.com"])
        assert r.total == 3


# ─────────────────────────────────────────────
# CrtshWorker Tests
# ─────────────────────────────────────────────

class TestCrtshWorker:
    def test_parse_crtsh_response_basic(self):
        data = [
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "other.notexample.com"},
        ]
        result = CrtshWorker._parse_crtsh_response(data, "example.com")
        assert "api.example.com" in result
        assert "www.example.com" in result
        assert "example.com" in result  # wildcard stripped to apex
        assert "other.notexample.com" not in result

    def test_parse_crtsh_empty(self):
        result = CrtshWorker._parse_crtsh_response([], "example.com")
        assert result == set()

    @pytest.mark.asyncio
    async def test_run_returns_subdomains_on_200(self):
        mock_data = [{"name_value": "api.example.com\nwww.example.com"}]

        worker = CrtshWorker(timeout=10)
        with patch("aiohttp.ClientSession") as MockSession:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value=json.dumps(mock_data))
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=False)

            mock_get = AsyncMock()
            mock_get.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.__aexit__ = AsyncMock(return_value=False)

            mock_session_instance = AsyncMock()
            mock_session_instance.get = MagicMock(return_value=mock_get)
            mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session_instance.__aexit__ = AsyncMock(return_value=False)

            MockSession.return_value = mock_session_instance

            result = await worker.run("example.com")

        assert "api.example.com" in result
        assert "www.example.com" in result

    @pytest.mark.asyncio
    async def test_run_returns_empty_on_500(self):
        worker = CrtshWorker(timeout=10, max_retries=1)
        with patch("aiohttp.ClientSession") as MockSession:
            mock_response = AsyncMock()
            mock_response.status = 500
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=False)

            mock_get = AsyncMock()
            mock_get.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.__aexit__ = AsyncMock(return_value=False)

            mock_session_instance = AsyncMock()
            mock_session_instance.get = MagicMock(return_value=mock_get)
            mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session_instance.__aexit__ = AsyncMock(return_value=False)

            MockSession.return_value = mock_session_instance

            result = await worker.run("example.com")

        assert result == []


# ─────────────────────────────────────────────
# SubfinderWorker Tests
# ─────────────────────────────────────────────

class TestSubfinderWorker:
    @pytest.mark.asyncio
    async def test_run_parses_json_output(self):
        json_output = (
            '{"host":"api.example.com","input":"example.com","source":"certspotter"}\n'
            '{"host":"www.example.com","input":"example.com","source":"hackertarget"}\n'
        )
        worker = SubfinderWorker(binary_path="subfinder")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(json_output.encode(), b"")
        )

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await worker.run("example.com")

        assert "api.example.com" in result
        assert "www.example.com" in result

    @pytest.mark.asyncio
    async def test_run_returns_empty_on_missing_binary(self):
        worker = SubfinderWorker(binary_path="/nonexistent/subfinder")
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            result = await worker.run("example.com")
        assert result == []

    @pytest.mark.asyncio
    async def test_run_returns_empty_on_timeout(self):
        worker = SubfinderWorker(timeout=1)
        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await worker.run("example.com")

        assert result == []
        mock_proc.kill.assert_called_once()
