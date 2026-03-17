"""
ZeroPoint :: modules/crawler.py
================================
Asynchronous wrappers for URL discovery tools.

Workers:
  KatanaWorker      — Active crawl via Katana (JS-aware, headless-capable)
  WaybackWorker     — Historical URLs via waybackurls
  GauWorker         — Historical URLs via gau (GetAllUrls — hits AlienVault, Wayback, CommonCrawl)

All workers share the same interface:
    async for url in worker.crawl(domain):
        process(url)
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator, Optional
from urllib.parse import urljoin, urlparse

from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Shared safe line reader — same fix as nuclei.py
# Katana/waybackurls/gau can emit lines > 1MB (sitemaps, large JS paths)
# ─────────────────────────────────────────────────────────────────────────────

async def _read_lines_safe(stream: asyncio.StreamReader):
    """
    Yield decoded lines from a StreamReader without crashing on oversized lines.
    Handles the ValueError/LimitOverrunError asyncio raises when a single line
    exceeds the buffer limit (e.g. Katana embedding a large sitemap XML in JSONL).
    """
    buffer = b""
    while True:
        try:
            chunk = await stream.readline()
            if not chunk:
                if buffer:
                    yield buffer.decode(errors="replace")
                break
            yield (buffer + chunk).decode(errors="replace")
            buffer = b""
        except ValueError:
            # LimitOverrunError converted to ValueError — read in raw chunks
            try:
                chunk = await stream.read(4 * 2 ** 20)  # 4MB chunk
                buffer += chunk
                if buffer.endswith(b"\n"):
                    yield buffer.decode(errors="replace")
                    buffer = b""
            except Exception as inner:
                logger.debug(f"[crawler] Chunked read error (oversized line skipped): {inner}")
                buffer = b""
        except Exception as exc:
            logger.debug(f"[crawler] Stream read error: {exc}")
            break


# ─────────────────────────────────────────────────────────────────────────────
# Katana Worker — active crawler
# ─────────────────────────────────────────────────────────────────────────────

class KatanaWorker:
    """
    Wraps the ProjectDiscovery `katana` binary.
    Performs active JS-aware crawling of a single target.
    Streams discovered URLs via async generator.
    """

    def __init__(
        self,
        binary_path:  str  = "katana",
        depth:        int  = 3,
        parallelism:  int  = 10,
        rate_limit:   int  = 50,
        timeout:      int  = 120,
        js_crawl:     bool = True,
        form_fill:    bool = True,
    ) -> None:
        self.binary_path = binary_path
        self.depth       = depth
        self.parallelism = parallelism
        self.rate_limit  = rate_limit
        self.timeout     = timeout
        self.js_crawl    = js_crawl
        self.form_fill   = form_fill

    def _build_cmd(self, url: str) -> list:
        cmd = [
            self.binary_path,
            "-u",        url,
            "-d",        str(self.depth),
            "-c",        str(self.parallelism),
            "-rl",       str(self.rate_limit),
            "-timeout",  str(self.timeout),
            "-silent",
            "-jsonl",
            "-kf", "all",
        ]
        if self.js_crawl:
            cmd.append("-jc")
        if self.form_fill:
            cmd.append("-aff")
        return cmd

    async def crawl(self, domain: str) -> AsyncIterator[str]:
        """Crawl a domain and yield discovered URLs."""
        target = f"https://{domain}"
        cmd    = self._build_cmd(target)
        logger.debug(f"[katana] CMD: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=4 * 2 ** 20,  # 4MB — Katana embeds full responses in JSONL
            )
            count = 0
            assert proc.stdout is not None

            async for line in _read_lines_safe(proc.stdout):
                line = line.strip()
                if not line:
                    continue
                url = self._parse_katana_line(line)
                if url:
                    count += 1
                    yield url

            _, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout + 30
            )
            stderr = stderr_bytes.decode(errors="replace").strip()
            if stderr and "error" in stderr.lower():
                logger.debug(f"[katana] stderr: {stderr[-300:]}")

            logger.success(f"[katana] {count} URLs crawled from {domain}")

        except FileNotFoundError:
            logger.error(
                f"[katana] Binary not found at '{self.binary_path}'. "
                "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )
        except asyncio.TimeoutError:
            logger.warning(f"[katana] Timed out crawling {domain}")
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as exc:
            logger.exception(f"[katana] Unexpected error crawling {domain}: {exc}")

    @staticmethod
    def _parse_katana_line(line: str) -> Optional[str]:
        """Parse a Katana JSONL line and extract the URL."""
        try:
            data = json.loads(line)
            endpoint = (
                data.get("request", {}).get("endpoint")
                or data.get("endpoint")
                or data.get("url")
                or ""
            ).strip()
            return endpoint if endpoint.startswith("http") else None
        except (json.JSONDecodeError, AttributeError):
            line = line.strip()
            return line if line.startswith("http") else None


# ─────────────────────────────────────────────────────────────────────────────
# Waybackurls Worker — historical URLs
# ─────────────────────────────────────────────────────────────────────────────

class WaybackWorker:
    """
    Wraps `waybackurls` (tomnomnom) to fetch archived URLs from the Wayback Machine.
    """

    def __init__(
        self,
        binary_path: str = "waybackurls",
        timeout:     int = 120,
    ) -> None:
        self.binary_path = binary_path
        self.timeout     = timeout

    async def crawl(self, domain: str) -> AsyncIterator[str]:
        """Fetch all archived URLs for a domain from the Wayback Machine."""
        cmd = [self.binary_path, domain]
        logger.debug(f"[wayback] Fetching archived URLs for {domain}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=4 * 2 ** 20,
            )
            count = 0
            assert proc.stdout is not None

            async for line in _read_lines_safe(proc.stdout):
                url = line.strip()
                if url.startswith("http"):
                    count += 1
                    yield url

            await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            logger.success(f"[wayback] {count} archived URLs found for {domain}")

        except FileNotFoundError:
            logger.error(
                f"[wayback] Binary not found at '{self.binary_path}'. "
                "Install: go install github.com/tomnomnom/waybackurls@latest"
            )
        except asyncio.TimeoutError:
            logger.warning(f"[wayback] Timed out for {domain}")
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as exc:
            logger.exception(f"[wayback] Unexpected error for {domain}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# GAU Worker — multi-source URL aggregator
# ─────────────────────────────────────────────────────────────────────────────

class GauWorker:
    """
    Wraps `gau` (lc/gau) — GetAllUrls.
    Aggregates URLs from AlienVault OTX, Wayback Machine, and CommonCrawl.
    """

    def __init__(
        self,
        binary_path:    str  = "gau",
        timeout:        int  = 120,
        include_subs:   bool = True,
        blacklist_exts: str  = "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css",
    ) -> None:
        self.binary_path    = binary_path
        self.timeout        = timeout
        self.include_subs   = include_subs
        self.blacklist_exts = blacklist_exts

    def _build_cmd(self, domain: str) -> list:
        cmd = [self.binary_path, "--blacklist", self.blacklist_exts]
        if self.include_subs:
            cmd.append("--subs")
        cmd.append(domain)
        return cmd

    async def crawl(self, domain: str) -> AsyncIterator[str]:
        """Fetch URLs from AlienVault OTX, Wayback, and CommonCrawl."""
        cmd = self._build_cmd(domain)
        logger.debug(f"[gau] Fetching URLs for {domain}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=4 * 2 ** 20,
            )
            count = 0
            assert proc.stdout is not None

            async for line in _read_lines_safe(proc.stdout):
                url = line.strip()
                if url.startswith("http"):
                    count += 1
                    yield url

            await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            logger.success(f"[gau] {count} URLs found for {domain}")

        except FileNotFoundError:
            logger.error(
                f"[gau] Binary not found at '{self.binary_path}'. "
                "Install: go install github.com/lc/gau/v2/cmd/gau@latest"
            )
        except asyncio.TimeoutError:
            logger.warning(f"[gau] Timed out for {domain}")
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as exc:
            logger.exception(f"[gau] Unexpected error for {domain}: {exc}")