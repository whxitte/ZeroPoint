"""
ZeroPoint :: modules/prober.py
==============================
Asynchronous httpx wrapper — the HTTP probe worker for Module 2.

Architecture:
  - Accepts a batch of domain strings.
  - Writes them to a NamedTemporaryFile (httpx -l flag).
  - Streams httpx JSON output line-by-line from stdout.
  - Parses each JSON line into a ProbeResult.
  - The caller (prober.py orchestrator) writes results to MongoDB.

httpx flags used:
  -l           input list
  -json        structured JSON output (one object per line)
  -silent      suppress progress/banners
  -status-code include status code
  -title       extract page title
  -tech-detect wappalyzer-style tech fingerprinting
  -web-server  extract Server header
  -content-type extract Content-Type
  -cdn         detect CDN provider
  -follow-redirects
  -follow-host-redirects (stay on same host)
  -random-agent rotate User-Agent per request
  -timeout     per-host timeout
  -retries     retry count
  -threads     worker threads
  -rate-limit  global req/sec cap
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from typing import AsyncIterator, Dict, List, Optional, Tuple

from loguru import logger

from models import InterestLevel, ProbeResult, ProbeStatus


# ─────────────────────────────────────────────────────────────────────────────
# Response-time parser — httpx emits "123.45ms" or "1.23s"
# ─────────────────────────────────────────────────────────────────────────────

def _parse_response_time(raw: Optional[str]) -> Optional[int]:
    """Convert httpx response-time string to milliseconds integer."""
    if not raw:
        return None
    raw = raw.strip().lower()
    try:
        if raw.endswith("ms"):
            return int(float(raw[:-2]))
        if raw.endswith("s"):
            return int(float(raw[:-1]) * 1000)
    except ValueError:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# httpx JSON → ProbeResult mapper
# ─────────────────────────────────────────────────────────────────────────────

def _parse_httpx_line(raw_json: str) -> Optional[ProbeResult]:
    """
    Parse a single JSON line from httpx -json output into a ProbeResult.

    httpx JSON schema (relevant fields):
      {
        "url":             "https://api.example.com",
        "host":            "api.example.com",
        "status-code":     200,
        "title":           "API Gateway",
        "webserver":       "nginx",
        "content-type":    "text/html; charset=utf-8",
        "tech":            ["Nginx:1.24", "PHP:8.1"],
        "cdn":             "Cloudflare",
        "location":        "https://other.example.com",
        "content-length":  4096,
        "response-time":   "123ms",
        "a":               ["1.2.3.4"],
        "favicon-mmh3":    "123456789",
        "body-preview":    "<!DOCTYPE html>..."
      }
    """
    try:
        data: Dict = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logger.debug(f"[prober] JSON parse error on line: {exc}")
        return None

    # Determine the canonical domain from httpx output
    host  = data.get("host", "").strip().lower()
    url   = data.get("url", "").strip()
    if not host and url:
        # Fallback: extract from URL
        m = re.search(r"https?://([^/]+)", url)
        host = m.group(1).lower() if m else ""
    if not host:
        logger.debug(f"[prober] No host in httpx line, skipping: {raw_json[:80]}")
        return None

    # Strip port from host if present
    host = re.sub(r":\d+$", "", host)

    # Technology list — httpx may emit "Nginx:1.24" or just "Nginx"
    raw_techs: List = data.get("tech", []) or data.get("technologies", []) or []
    technologies = [t.split(":")[0].strip() for t in raw_techs if t]

    # Resolve probe status from HTTP status code presence
    status_code = data.get("status-code") or data.get("status_code")
    if status_code:
        probe_status = ProbeStatus.ALIVE
    else:
        # httpx only emits lines for hosts it successfully reached;
        # lines without a status code indicate a connection-level failure
        probe_status = ProbeStatus.DEAD

    return ProbeResult(
        domain           = host,
        probe_status     = probe_status,
        http_status      = status_code,
        http_title       = (data.get("title") or "").strip() or None,
        web_server       = (data.get("webserver") or data.get("web-server") or "").strip() or None,
        content_type     = (data.get("content-type") or "").split(";")[0].strip() or None,
        technologies     = technologies,
        cdn_provider     = str(data.get("cdn") or "").strip() or None,
        redirect_url     = (data.get("location") or "").strip() or None,
        favicon_hash     = str(data.get("favicon-mmh3", "")).strip() or None,
        body_preview     = (data.get("body-preview") or "")[:300] or None,
        content_length   = data.get("content-length"),
        response_time_ms = _parse_response_time(data.get("response-time")),
        ip_addresses     = [ip for ip in (data.get("a") or []) if ip],
    )


# ─────────────────────────────────────────────────────────────────────────────
# HttpxProber Worker
# ─────────────────────────────────────────────────────────────────────────────

class HttpxProber:
    """
    Asynchronous wrapper around the `httpx` binary from ProjectDiscovery.

    Usage:
        prober = HttpxProber(binary_path="httpx", ...)
        async for result in prober.probe(domain_list):
            await db.update_probe_result(result)
    """

    def __init__(
        self,
        binary_path:      str  = "httpx",
        threads:          int  = 50,
        rate_limit:       int  = 150,
        timeout:          int  = 10,
        retries:          int  = 2,
        follow_redirects: bool = True,
        screenshot:       bool = False,
        screenshot_dir:   str  = "data/screenshots",
    ) -> None:
        self.binary_path      = binary_path
        self.threads          = threads
        self.rate_limit       = rate_limit
        self.timeout          = timeout
        self.retries          = retries
        self.follow_redirects = follow_redirects
        self.screenshot       = screenshot
        self.screenshot_dir   = screenshot_dir

    def _build_command(self, input_file: str) -> List[str]:
        """Build the httpx command array."""
        cmd = [
            self.binary_path,
            "-l",             input_file,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-content-type",
            "-cdn",
            "-content-length",
            "-response-time",
            "-ip",
            "-random-agent",
            "-threads",       str(self.threads),
            "-rate-limit",    str(self.rate_limit),
            "-timeout",       str(self.timeout),
            "-retries",       str(self.retries),
        ]

        if self.follow_redirects:
            cmd += ["-follow-redirects", "-follow-host-redirects"]

        if self.screenshot:
            if not os.path.isdir(self.screenshot_dir):
                os.makedirs(self.screenshot_dir, exist_ok=True)
            cmd += ["-screenshot", "-srd", self.screenshot_dir]

        return cmd

    async def probe(
        self,
        domains: List[str],
    ) -> AsyncIterator[ProbeResult]:
        """
        Probe a batch of domains and yield ProbeResult objects as they arrive.
        Designed as an async generator so the caller can process results
        incrementally without waiting for the full batch to complete.
        """
        if not domains:
            return

        # Deduplicate within batch
        unique_domains = list(dict.fromkeys(d.strip().lower() for d in domains if d.strip()))
        logger.info(f"[prober] Starting probe batch: {len(unique_domains)} domains")

        # Write domains to a temp file (httpx -l flag)
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="zeropoint_probe_",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write("\n".join(unique_domains))
            tmp_path = tmp.name

        cmd = self._build_command(tmp_path)
        logger.debug(f"[prober] Command: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # ── Stream stdout line-by-line ────────────────────────────────
            hit_count = 0
            assert proc.stdout is not None  # guaranteed by PIPE

            async for raw_line in proc.stdout:
                line = raw_line.decode(errors="replace").strip()
                if not line:
                    continue

                result = _parse_httpx_line(line)
                if result is not None:
                    hit_count += 1
                    yield result

            # Wait for process to finish and collect stderr
            _, stderr_bytes = await proc.communicate()
            stderr_text = stderr_bytes.decode(errors="replace").strip()

            if proc.returncode not in (0, None) and stderr_text:
                logger.warning(
                    f"[prober] httpx exited {proc.returncode}: "
                    f"{stderr_text[:300]}"
                )

            logger.success(
                f"[prober] Batch complete | "
                f"submitted={len(unique_domains)} | alive={hit_count}"
            )

        except FileNotFoundError:
            logger.error(
                f"[prober] httpx binary not found at '{self.binary_path}'. "
                "Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            )
        except PermissionError:
            logger.error(f"[prober] No execute permission on '{self.binary_path}'")
        except asyncio.CancelledError:
            logger.warning("[prober] Probe batch cancelled")
            raise
        except Exception as exc:
            logger.exception(f"[prober] Unexpected error during probe batch: {exc}")
        finally:
            # Always clean up the temp file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    async def probe_single(self, domain: str) -> Optional[ProbeResult]:
        """Convenience method for probing a single domain."""
        async for result in self.probe([domain]):
            return result
        return None
