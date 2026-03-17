"""
ZeroPoint :: modules/recon.py
==============================
Async wrappers for every subdomain discovery tool.

Engineering contract:
  - Every worker function is async and returns a ReconResult.
  - Tools must NEVER raise — all exceptions are caught, logged, and packaged
    into ReconResult.errors so the orchestrator can continue without stalling.
  - Jitter is applied on all network requests to avoid WAF / rate-limit bans.
  - Binary tool wrappers (Subfinder) use asyncio.create_subprocess_exec for
    true non-blocking execution.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import shutil
import time
from typing import Any, Dict, List, Optional

import aiohttp
import shodan
from loguru import logger
from pydantic import ValidationError

from config import settings
from models import ReconResult, ReconSource


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def _is_valid_domain(domain: str) -> bool:
    """Basic domain format validation."""
    return bool(DOMAIN_RE.match(domain.strip()))


def _deduplicate(domains: List[str]) -> List[str]:
    """Lower-case, strip, deduplicate, validate."""
    seen: set[str] = set()
    out: List[str] = []
    for d in domains:
        d = d.lower().strip().rstrip(".")
        if d and d not in seen and _is_valid_domain(d):
            seen.add(d)
            out.append(d)
    return out


async def _jitter() -> None:
    """Random async sleep — prevents uniform timing patterns detectable by WAFs."""
    delay = random.uniform(
        settings.RATE_LIMIT_MIN_JITTER,
        settings.RATE_LIMIT_MAX_JITTER,
    )
    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Worker 1 — Subfinder
# ---------------------------------------------------------------------------

async def run_subfinder(root_domain: str) -> ReconResult:
    """
    Execute Subfinder as a subprocess and parse its JSON-line output.

    Uses asyncio.create_subprocess_exec for fully non-blocking I/O.
    Automatically picks up API keys from ~/.config/subfinder/provider-config.yaml
    if they exist.
    """
    source = ReconSource.SUBFINDER
    errors: List[str] = []
    domains: List[str] = []

    binary = settings.SUBFINDER_PATH
    if not shutil.which(binary):
        msg = (
            f"Subfinder binary not found at '{binary}'. "
            "Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )
        logger.error(msg)
        return ReconResult(source=source, domains=[], errors=[msg])

    cmd = [
        binary,
        "-d", root_domain,
        "-all",          # use all available sources
        "-recursive",    # recurse into discovered subdomains
        "-silent",       # suppress banner output
        "-oJ",           # output as JSON lines
        "-timeout", "30",
    ]

    logger.info(f"[Subfinder] Starting scan for {root_domain}")
    start = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.SUBFINDER_TIMEOUT,
            )
        except asyncio.TimeoutError:
            proc.kill()
            msg = f"Subfinder timed out after {settings.SUBFINDER_TIMEOUT}s for {root_domain}"
            logger.warning(msg)
            return ReconResult(source=source, domains=[], errors=[msg])

        if proc.returncode != 0:
            err_txt = stderr_bytes.decode(errors="replace").strip()
            msg = f"Subfinder exited with code {proc.returncode}: {err_txt}"
            logger.error(msg)
            errors.append(msg)

        # Parse JSON-line output: each line is {"host": "sub.example.com", ...}
        for line in stdout_bytes.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                host = obj.get("host", "").strip()
                if host:
                    domains.append(host)
            except json.JSONDecodeError:
                # Subfinder sometimes emits plain text in --silent mode; handle both
                if line and not line.startswith("["):
                    domains.append(line)

    except (OSError, ValueError) as exc:
        msg = f"Failed to launch Subfinder process: {exc}"
        logger.error(msg)
        errors.append(msg)

    elapsed = time.monotonic() - start
    domains = _deduplicate(domains)

    logger.info(
        f"[Subfinder] Finished {root_domain} — "
        f"found {len(domains)} unique subdomains in {elapsed:.1f}s"
    )
    return ReconResult(source=source, domains=domains, errors=errors)


# ---------------------------------------------------------------------------
# Worker 2 — crt.sh (Certificate Transparency)
# ---------------------------------------------------------------------------

_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_CRTSH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0 Safari/537.36"
    ),
    "Accept": "application/json",
}


async def run_crtsh(root_domain: str) -> ReconResult:
    """
    Query crt.sh (Certificate Transparency logs) via HTTPS JSON API.
    Uses aiohttp with retry logic and exponential back-off.
    """
    source = ReconSource.CRTSH
    errors: List[str] = []
    domains: List[str] = []
    url = _CRTSH_URL.format(domain=root_domain)

    timeout = aiohttp.ClientTimeout(total=settings.CRTSH_TIMEOUT)

    for attempt in range(1, settings.CRTSH_RETRIES + 1):
        # Create connector inside the loop to ensure a fresh one for each attempt
        connector = aiohttp.TCPConnector(ssl=True, limit=5)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                headers=_CRTSH_HEADERS,
                timeout=timeout,
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 429 or resp.status == 404 or resp.status == 503: # Added 503
                        wait = 2 ** attempt
                        logger.warning(
                            f"[crt.sh] Rate limited, 404, or 503 error (attempt {attempt}), "
                            f"backing off {wait}s …"
                        )
                        await asyncio.sleep(wait)
                        continue

                    if resp.status != 200:
                        msg = f"crt.sh returned HTTP {resp.status}"
                        logger.error(msg)
                        errors.append(msg)
                        break

                    data: List[Dict[str, Any]] = await resp.json(
                        content_type=None  # crt.sh sometimes omits content-type
                    )

            # Parse the name_value field which contains newline-separated SANs
            for entry in data:
                name_val: str = entry.get("name_value", "")
                for candidate in name_val.splitlines():
                    candidate = candidate.strip().lstrip("*.")
                    if candidate:
                        domains.append(candidate)

            break  # success — exit retry loop

        except (aiohttp.ClientError, asyncio.TimeoutError, TimeoutError) as exc:
            msg = f"[crt.sh] Network error or timeout (attempt {attempt}): {repr(exc)}"
            logger.warning(msg)
            errors.append(msg)
            await asyncio.sleep(2 ** attempt)

        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"[crt.sh] Failed to parse JSON response: {exc}"
            logger.error(msg)
            errors.append(msg)
            break
        finally:
            # Ensure connector is always closed
            await connector.close()

    domains = _deduplicate(domains)
    # Filter to only subdomains of the root domain
    domains = [d for d in domains if d.endswith(f".{root_domain}") or d == root_domain]

    logger.info(f"[crt.sh] Found {len(domains)} unique subdomains for {root_domain}")
    return ReconResult(source=source, domains=domains, errors=errors)


# ---------------------------------------------------------------------------
# Worker 3 — Shodan
# ---------------------------------------------------------------------------

async def run_shodan(root_domain: str) -> ReconResult:
    """
    Query Shodan for subdomains and related host metadata.
    Runs Shodan's synchronous SDK in a thread executor to avoid blocking the
    event loop — this is the correct async pattern for blocking I/O libraries.
    """
    source = ReconSource.SHODAN
    errors: List[str] = []
    domains: List[str] = []
    metadata: Dict[str, Any] = {}

    if not settings.SHODAN_API_KEY:
        msg = "SHODAN_API_KEY is not configured — skipping Shodan module."
        logger.warning(msg)
        return ReconResult(source=source, domains=[], errors=[msg])

    logger.info(f"[Shodan] Querying DNS data for {root_domain}")

    def _blocking_shodan_query() -> Dict[str, Any]:
        """
        Synchronous Shodan API call — runs in a thread so it doesn't block.
        Returns raw Shodan DNS result dict.
        """
        api = shodan.Shodan(settings.SHODAN_API_KEY)
        return api.dns.domain_info(root_domain, history=False, type="A", page=1)

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _blocking_shodan_query)

        subdomains: List[str] = result.get("subdomains", [])
        domain_data: List[Dict] = result.get("data", [])

        # Reconstruct FQDNs from bare subdomain labels
        for sub in subdomains:
            fqdn = f"{sub}.{root_domain}" if not sub.endswith(root_domain) else sub
            domains.append(fqdn)

        # Extract IPs and hostnames from the rich data records
        for record in domain_data:
            subdomain_label: str = record.get("subdomain", "")
            if subdomain_label:
                fqdn = f"{subdomain_label}.{root_domain}"
                domains.append(fqdn)

            value: str = record.get("value", "")
            rec_type: str = record.get("type", "")
            if rec_type == "A" and value and subdomain_label:
                fqdn = f"{subdomain_label}.{root_domain}"
                if fqdn not in metadata:
                    metadata[fqdn] = {"ip_addresses": []}
                metadata[fqdn]["ip_addresses"].append(value)

        await _jitter()  # be polite to Shodan's API

    except shodan.APIError as exc:
        msg = f"[Shodan] API error for {root_domain}: {exc}"
        logger.error(msg)
        errors.append(msg)

    except Exception as exc:
        msg = f"[Shodan] Unexpected error: {exc}"
        logger.error(msg)
        errors.append(msg)

    domains = _deduplicate(domains)
    logger.info(f"[Shodan] Found {len(domains)} unique subdomains for {root_domain}")
    return ReconResult(source=source, domains=domains, metadata=metadata, errors=errors)


# ---------------------------------------------------------------------------
# Aggregator — run all tools in parallel for a single root domain
# ---------------------------------------------------------------------------

async def discover_subdomains(root_domain: str) -> List[ReconResult]:
    """
    Fire all recon workers concurrently via asyncio.gather.
    Even if one worker crashes, the others continue — errors are in the result.

    Returns a list of ReconResult, one per tool.
    """
    logger.info(f"[Recon] Starting full discovery for: {root_domain}")
    start = time.monotonic()

    results = await asyncio.gather(
        run_subfinder(root_domain),
        run_crtsh(root_domain),
        run_shodan(root_domain),
        return_exceptions=True,  # Return exceptions as results for graceful handling
    )

    processed_results: List[ReconResult] = []
    for result in results:
        if isinstance(result, Exception):
            err_msg = repr(result)
            logger.error(f"[Recon] Tool failed for {root_domain}: {err_msg}")
            # Create a placeholder ReconResult to represent the failed tool
            # The specific source is unknown here, so we might need a more
            # sophisticated way to map exceptions back to their origin.
            # For now, we'll log it as a generic recon error.
            processed_results.append(ReconResult(source=ReconSource.UNKNOWN, domains=[], errors=[err_msg]))
        else:
            processed_results.append(result)
    
    total = sum(len(r.domains) for r in processed_results)
    elapsed = time.monotonic() - start
    logger.info(
        f"[Recon] Discovery complete for {root_domain} — "
        f"{total} total raw subdomains across all sources in {elapsed:.1f}s"
    )
    return processed_results
