"""
ZeroPoint :: modules/js_analyzer.py
=====================================
JavaScript secret and sensitive data scanner.

Two-layer approach:
  Layer 1 — Built-in regex patterns (no dependencies, runs always)
             Covers: AWS keys, GitHub tokens, Slack webhooks, JWT, private keys,
             Google API keys, Stripe keys, generic high-entropy strings, etc.

  Layer 2 — SecretFinder.py (optional, runs if SECRETFINDER_PATH is set)
             A comprehensive Python-based JS secret scanner with 100+ patterns.
             Repo: https://github.com/m4ll0k/SecretFinder

Design:
  - Downloads JS file content via aiohttp (async, no extra binaries)
  - Runs all regex patterns against the content
  - Shannon entropy filter eliminates low-entropy false positives
  - Returns CrawlSecret objects ready for DB upsert
"""

from __future__ import annotations

import asyncio
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from loguru import logger

from core.endpoint_classifier import shannon_entropy
from db.crawler_ops import make_secret_id
from models import CrawlSecret, SecretSeverity


# ─────────────────────────────────────────────────────────────────────────────
# Built-in secret patterns
# (pattern_name, regex, min_entropy, severity)
# ─────────────────────────────────────────────────────────────────────────────

SECRET_PATTERNS: List[Tuple[str, str, float, SecretSeverity]] = [
    # ── Cloud Provider Keys ───────────────────────────────────────────────
    ("aws_access_key",
     r"(?:ASIA|AKIA|AROA|AIDA)[A-Z0-9]{16}",
     3.5, SecretSeverity.CRITICAL),

    ("aws_secret_key",
     r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
     4.0, SecretSeverity.CRITICAL),

    ("google_api_key",
     r"AIza[0-9A-Za-z\-_]{35}",
     3.5, SecretSeverity.CRITICAL),

    ("google_oauth",
     r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
     3.5, SecretSeverity.HIGH),

    ("azure_storage",
     r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{88}==",
     4.0, SecretSeverity.CRITICAL),

    # ── Source Control ────────────────────────────────────────────────────
    ("github_token",
     r"ghp_[A-Za-z0-9]{36}",
     4.0, SecretSeverity.CRITICAL),

    ("github_fine_grained",
     r"github_pat_[A-Za-z0-9_]{82}",
     4.5, SecretSeverity.CRITICAL),

    ("gitlab_token",
     r"glpat-[A-Za-z0-9\-_]{20}",
     4.0, SecretSeverity.CRITICAL),

    # ── Payment ───────────────────────────────────────────────────────────
    ("stripe_secret_key",
     r"sk_live_[0-9a-zA-Z]{24,}",
     4.0, SecretSeverity.CRITICAL),

    ("stripe_publishable_key",
     r"pk_live_[0-9a-zA-Z]{24,}",
     3.5, SecretSeverity.HIGH),

    ("stripe_test_key",
     r"sk_test_[0-9a-zA-Z]{24,}",
     4.0, SecretSeverity.MEDIUM),

    # ── Communication & Infra ─────────────────────────────────────────────
    ("slack_webhook",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
     3.5, SecretSeverity.HIGH),

    ("slack_token",
     r"xox[baprs]-[0-9A-Za-z\-]+",
     3.5, SecretSeverity.HIGH),

    ("discord_webhook",
     r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
     3.5, SecretSeverity.HIGH),

    ("telegram_bot_token",
     r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
     3.5, SecretSeverity.HIGH),

    # ── Tokens & JWTs ─────────────────────────────────────────────────────
    ("jwt_token",
     r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     3.5, SecretSeverity.HIGH),

    ("bearer_token",
     r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}",
     3.5, SecretSeverity.HIGH),

    # ── Private Keys ──────────────────────────────────────────────────────
    ("rsa_private_key",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     0.0, SecretSeverity.CRITICAL),   # No entropy check — always critical

    ("pgp_private_key",
     r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     0.0, SecretSeverity.CRITICAL),

    # ── Database & Infrastructure ─────────────────────────────────────────
    ("mongodb_uri",
     r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+",
     3.5, SecretSeverity.CRITICAL),

    ("postgres_uri",
     r"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"']+",
     3.5, SecretSeverity.CRITICAL),

    ("mysql_uri",
     r"mysql://[^:]+:[^@]+@[^\s\"']+",
     3.5, SecretSeverity.CRITICAL),

    ("redis_uri",
     r"redis://(?:[^:]+:[^@]+@)?[^\s\"']+",
     3.0, SecretSeverity.HIGH),

    # ── Generic High-Entropy Secrets ──────────────────────────────────────
    ("generic_api_key",
     r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key)['\"\s:=]+([A-Za-z0-9_\-+/]{20,})",
     4.0, SecretSeverity.HIGH),

    ("generic_secret",
     r"(?i)(?:secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)['\"\s:=]+([A-Za-z0-9_\-+/]{20,})",
     4.0, SecretSeverity.HIGH),

    ("generic_password",
     r"(?i)(?:password|passwd|pwd)['\"\s:=]+['\"]([^'\"]{8,})['\"]",
     3.0, SecretSeverity.MEDIUM),

    # ── Internal URLs & Endpoints ─────────────────────────────────────────
    ("internal_ip",
     r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]+)?",
     0.0, SecretSeverity.MEDIUM),

    ("aws_s3_bucket",
     r"(?:s3\.amazonaws\.com/|s3://)[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]",
     0.0, SecretSeverity.MEDIUM),

    # ── Hardcoded Credentials ─────────────────────────────────────────────
    ("hardcoded_basic_auth",
     r"https?://[A-Za-z0-9_\-.]+:[A-Za-z0-9_\-.@!$%^&*]{4,}@[A-Za-z0-9\-.]",
     3.0, SecretSeverity.CRITICAL),
]

# Pre-compile all patterns for performance
_COMPILED_PATTERNS = [
    (name, re.compile(pattern, re.MULTILINE), min_entropy, severity)
    for name, pattern, min_entropy, severity in SECRET_PATTERNS
]


# ─────────────────────────────────────────────────────────────────────────────
# JS File Fetcher
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_js_content(url: str, timeout: int = 15) -> Optional[str]:
    """
    Fetch the raw content of a JS file via HTTP.
    Returns None on error — never raises.
    """
    try:
        async with aiohttp.ClientSession(
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; ZeroPoint/1.0)",
                "Accept":     "*/*",
            },
            connector=aiohttp.TCPConnector(ssl=False),  # some JS served over HTTP
        ) as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    return None
                # Only process if content type is JS or text
                ct = resp.headers.get("content-type", "")
                if "javascript" in ct or "text" in ct or not ct:
                    content = await resp.text(errors="replace")
                    return content[:500_000]  # cap at 500KB per file
                return None
    except Exception as exc:
        logger.debug(f"[js_analyzer] Failed to fetch {url}: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Pattern Matcher
# ─────────────────────────────────────────────────────────────────────────────

def scan_content_for_secrets(
    content:     str,
    source_url:  str,
    domain:      str,
    program_id:  str,
    crawl_run_id: str,
    min_entropy: float = 3.5,
) -> List[CrawlSecret]:
    """
    Run all secret patterns against JS/page content.
    Returns a list of CrawlSecret objects (pre-filtered by entropy).
    """
    secrets: List[CrawlSecret] = []
    lines   = content.split("\n")

    for name, compiled, pattern_min_entropy, severity in _COMPILED_PATTERNS:
        for match in compiled.finditer(content):
            # Extract the matched value — use group(1) if available (capturing group)
            try:
                value = match.group(1)
            except IndexError:
                value = match.group(0)

            value = value.strip()
            if not value or len(value) < 4:
                continue

            # Skip values that are plain URLs — a URL is not a secret.
            # Patterns like generic_api_key can match JS variables whose
            # *value* happens to be a URL (e.g. apiUrl = "https://...").
            if value.startswith(("http://", "https://", "//", "ws://", "wss://")):
                continue

            # Apply entropy filter — skip obviously low-entropy placeholders
            effective_min = max(pattern_min_entropy, min_entropy) if pattern_min_entropy > 0 else 0
            if effective_min > 0 and shannon_entropy(value) < effective_min:
                continue

            # Skip obvious placeholders
            placeholder_markers = [
                "your_", "yourkey", "placeholder", "example", "xxxx",
                "change_me", "replace_me", "insert_", "dummy", "test_key",
                "aaaa", "1234", "abcd",
            ]
            if any(m in value.lower() for m in placeholder_markers):
                continue

            # Find line number for context
            match_pos   = match.start()
            line_number = content[:match_pos].count("\n") + 1

            # Extract context (surrounding line)
            context_lines = lines[max(0, line_number - 2): line_number + 1]
            context       = " | ".join(l.strip() for l in context_lines)[:300]

            secret_id = make_secret_id(name, domain, value)

            secret = CrawlSecret(
                secret_id    = secret_id,
                program_id   = program_id,
                domain       = domain,
                source_url   = source_url,
                secret_type  = name,
                secret_value = value[:120],
                severity     = severity,
                line_number  = line_number,
                context      = context,
                tool         = "zeropoint-regex",
                crawl_run_id = crawl_run_id,
            )
            secrets.append(secret)

    # Deduplicate by secret_id within this batch
    seen: set[str] = set()
    unique = []
    for s in secrets:
        if s.secret_id not in seen:
            seen.add(s.secret_id)
            unique.append(s)

    return unique


# ─────────────────────────────────────────────────────────────────────────────
# SecretFinder.py wrapper (optional, external tool)
# ─────────────────────────────────────────────────────────────────────────────

async def run_secretfinder(
    url:         str,
    domain:      str,
    program_id:  str,
    crawl_run_id: str,
    secretfinder_path: str,
    python_bin:  str = "python3",
) -> List[CrawlSecret]:
    """
    Run SecretFinder.py against a JS URL.
    SecretFinder outputs JSON with regex matches.

    Only invoked if SECRETFINDER_PATH is set in .env and the file exists.
    Falls back gracefully (returns []) if unavailable.
    """
    import os
    if not os.path.isfile(secretfinder_path):
        return []

    cmd = [
        python_bin, secretfinder_path,
        "-i", url,
        "-o", "cli",       # Output to stdout as text
    ]

    secrets: List[CrawlSecret] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=2 ** 20,
        )

        assert proc.stdout is not None
        async for raw_line in proc.stdout:
            line = raw_line.decode(errors="replace").strip()
            if not line or line.startswith("["):
                # SecretFinder outputs like: [!] Found API Key: sk-... at line 42
                parsed = _parse_secretfinder_line(line, url, domain, program_id, crawl_run_id)
                if parsed:
                    secrets.append(parsed)

        await asyncio.wait_for(proc.communicate(), timeout=60)

    except FileNotFoundError:
        logger.warning(f"[secretfinder] python3 not found or SecretFinder path wrong")
    except asyncio.TimeoutError:
        logger.warning(f"[secretfinder] Timed out on {url}")
        try:
            proc.kill()
        except Exception:
            pass
    except Exception as exc:
        logger.debug(f"[secretfinder] Error on {url}: {exc}")

    return secrets


def _parse_secretfinder_line(
    line: str,
    source_url: str,
    domain: str,
    program_id: str,
    crawl_run_id: str,
) -> Optional[CrawlSecret]:
    """Parse a SecretFinder output line into a CrawlSecret."""
    # SecretFinder format: [!] {key_type}: {value}
    match = re.match(r"\[.+?\]\s+(.+?):\s+(.+)", line)
    if not match:
        return None

    secret_type  = match.group(1).strip().lower().replace(" ", "_")
    secret_value = match.group(2).strip()

    if not secret_value or len(secret_value) < 4:
        return None

    return CrawlSecret(
        secret_id    = make_secret_id(secret_type, domain, secret_value),
        program_id   = program_id,
        domain       = domain,
        source_url   = source_url,
        secret_type  = secret_type,
        secret_value = secret_value[:120],
        severity     = SecretSeverity.HIGH,
        tool         = "secretfinder",
        crawl_run_id = crawl_run_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Async JS analyzer — orchestrates fetch + scan for a single JS URL
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_js_url(
    url:               str,
    domain:            str,
    program_id:        str,
    crawl_run_id:      str,
    min_entropy:       float = 3.5,
    secretfinder_path: str   = "",
) -> List[CrawlSecret]:
    """
    Fetch a JS URL and scan it for secrets.
    Runs built-in regex scanner + optional SecretFinder in parallel.
    Returns deduplicated list of CrawlSecret objects.
    """
    # Fetch content
    content = await fetch_js_content(url)
    if not content:
        return []

    logger.debug(f"[js_analyzer] Scanning {url} ({len(content):,} bytes)")

    # Layer 1: built-in regex scanner (always runs)
    regex_secrets = scan_content_for_secrets(
        content=content,
        source_url=url,
        domain=domain,
        program_id=program_id,
        crawl_run_id=crawl_run_id,
        min_entropy=min_entropy,
    )

    # Layer 2: SecretFinder (optional)
    sf_secrets: List[CrawlSecret] = []
    if secretfinder_path:
        sf_secrets = await run_secretfinder(
            url=url,
            domain=domain,
            program_id=program_id,
            crawl_run_id=crawl_run_id,
            secretfinder_path=secretfinder_path,
        )

    # Merge and deduplicate by secret_id
    all_secrets = regex_secrets + sf_secrets
    seen: set[str] = set()
    unique: List[CrawlSecret] = []
    for s in all_secrets:
        if s.secret_id not in seen:
            seen.add(s.secret_id)
            unique.append(s)

    if unique:
        logger.success(
            f"[js_analyzer] {len(unique)} secret(s) found in {url}"
        )

    return unique