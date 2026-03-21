"""
ZeroPoint :: modules/github_osint.py
======================================
GitHub OSINT engine — finds leaked credentials and sensitive references
on public GitHub repositories by searching for domain-specific patterns.

How it works:
  1. For each target domain, generate search queries using the GitHub Search API
  2. Each query searches code across all public repos for sensitive patterns
  3. Each result is fetched, the matched line extracted, and classified
  4. High-confidence matches are stored as GitHubLeak documents

GitHub Search API:
  - Endpoint: https://api.github.com/search/code?q={query}
  - Rate limits: 30 requests/minute (authenticated), 10/minute (unauthenticated)
  - GITHUB_TOKEN required for meaningful coverage
  - Results: up to 100 per query, we use 30 (configurable)

Query categories:
  ── Credentials ──────────────── domain password, domain api_key, etc.
  ── Infrastructure ───────────── domain mongodb://, domain postgresql://, etc.
  ── Private keys ─────────────── domain BEGIN RSA PRIVATE KEY
  ── Cloud ────────────────────── domain AKIA (AWS access keys)
  ── Config files ─────────────── filename:.env domain, filename:config.py domain
  ── Tokens ───────────────────── domain github_token, domain bearer
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import AsyncIterator, Dict, List, Optional, Tuple

import aiohttp
from loguru import logger

from db.github_ops import make_leak_id
from models import GitHubLeak, GitHubLeakSeverity


# ─────────────────────────────────────────────────────────────────────────────
# Search query templates
# (query_template, match_type, severity, description)
#
# {domain} is replaced with the target domain at runtime.
# {org}    is replaced with the org name derived from the domain.
# ─────────────────────────────────────────────────────────────────────────────

DORK_TEMPLATES: List[Tuple[str, str, GitHubLeakSeverity, str]] = [
    # ── Direct credential exposure ────────────────────────────────────────
    ('"{domain}" password',               "password",       GitHubLeakSeverity.HIGH,     "Password for domain"),
    ('"{domain}" passwd',                 "password",       GitHubLeakSeverity.HIGH,     "Password for domain"),
    ('"{domain}" secret',                 "secret",         GitHubLeakSeverity.HIGH,     "Secret for domain"),
    ('"{domain}" api_key',                "api_key",        GitHubLeakSeverity.HIGH,     "API key for domain"),
    ('"{domain}" apikey',                 "api_key",        GitHubLeakSeverity.HIGH,     "API key for domain"),
    ('"{domain}" api_secret',             "api_secret",     GitHubLeakSeverity.HIGH,     "API secret for domain"),
    ('"{domain}" access_token',           "access_token",   GitHubLeakSeverity.HIGH,     "Access token for domain"),
    ('"{domain}" auth_token',             "auth_token",     GitHubLeakSeverity.HIGH,     "Auth token for domain"),
    ('"{domain}" SECRET_KEY',             "secret_key",     GitHubLeakSeverity.CRITICAL, "Secret key for domain"),
    ('"{domain}" PRIVATE_KEY',            "private_key",    GitHubLeakSeverity.CRITICAL, "Private key for domain"),
    ('"{domain}" client_secret',          "client_secret",  GitHubLeakSeverity.HIGH,     "OAuth client secret"),

    # ── Database connection strings ───────────────────────────────────────
    ('"{domain}" mongodb://',             "mongodb_uri",    GitHubLeakSeverity.CRITICAL, "MongoDB URI with credentials"),
    ('"{domain}" postgresql://',          "postgres_uri",   GitHubLeakSeverity.CRITICAL, "PostgreSQL connection string"),
    ('"{domain}" mysql://',               "mysql_uri",      GitHubLeakSeverity.CRITICAL, "MySQL connection string"),
    ('"{domain}" redis://',               "redis_uri",      GitHubLeakSeverity.HIGH,     "Redis connection string"),

    # ── Cloud provider keys ───────────────────────────────────────────────
    ('"{domain}" AKIA',                   "aws_access_key", GitHubLeakSeverity.CRITICAL, "AWS access key near domain"),
    ('"{domain}" AWS_SECRET',             "aws_secret",     GitHubLeakSeverity.CRITICAL, "AWS secret near domain"),
    ('"{domain}" AWS_ACCESS_KEY_ID',      "aws_key_id",     GitHubLeakSeverity.CRITICAL, "AWS key ID near domain"),

    # ── Private keys ──────────────────────────────────────────────────────
    ('"{domain}" BEGIN RSA PRIVATE KEY',  "rsa_key",        GitHubLeakSeverity.CRITICAL, "RSA private key near domain"),
    ('"{domain}" BEGIN PRIVATE KEY',      "private_key",    GitHubLeakSeverity.CRITICAL, "Private key near domain"),
    ('"{domain}" BEGIN EC PRIVATE KEY',   "ec_key",         GitHubLeakSeverity.CRITICAL, "EC private key near domain"),

    # ── Config files containing domain ────────────────────────────────────
    ('filename:.env "{domain}"',          "env_file",       GitHubLeakSeverity.CRITICAL, ".env file containing domain"),
    ('filename:config.py "{domain}" password', "config_py", GitHubLeakSeverity.HIGH,     "Python config with credentials"),
    ('filename:config.php "{domain}" password', "config_php", GitHubLeakSeverity.HIGH,   "PHP config with credentials"),
    ('filename:database.yml "{domain}"',  "db_config",      GitHubLeakSeverity.HIGH,     "Database YAML config"),
    ('filename:settings.py "{domain}" SECRET', "settings_py", GitHubLeakSeverity.HIGH,   "Django/Flask settings"),
    ('filename:application.yml "{domain}" password', "app_yml", GitHubLeakSeverity.HIGH, "Spring/app YAML config"),
    ('filename:docker-compose.yml "{domain}" password', "docker_compose", GitHubLeakSeverity.HIGH, "Docker credentials"),
    ('filename:credentials "{domain}"',   "credentials_file", GitHubLeakSeverity.HIGH,   "Credentials file"),
    ('filename:.npmrc "{domain}"',        "npmrc",          GitHubLeakSeverity.HIGH,     ".npmrc with auth token"),

    # ── Org-level searches (high value) ───────────────────────────────────
    ('org:"{org}" filename:.env',         "org_env_file",   GitHubLeakSeverity.CRITICAL, ".env in org repo"),
    ('org:"{org}" password filename:*.py', "org_py_password", GitHubLeakSeverity.HIGH,   "Python file with password in org"),
    ('org:"{org}" SECRET_KEY',            "org_secret_key", GitHubLeakSeverity.CRITICAL, "Secret key in org"),
    ('org:"{org}" AWS_ACCESS_KEY_ID',     "org_aws_key",    GitHubLeakSeverity.CRITICAL, "AWS key in org repo"),
    ('org:"{org}" PRIVATE KEY',           "org_private_key", GitHubLeakSeverity.CRITICAL, "Private key in org repo"),
    ('org:"{org}" mongodb:// password',   "org_mongodb",    GitHubLeakSeverity.CRITICAL, "MongoDB URI in org repo"),
    ('org:"{org}" "DB_PASSWORD"',         "org_db_password", GitHubLeakSeverity.HIGH,    "DB password in org repo"),
    ('org:"{org}" "DATABASE_URL"',        "org_db_url",     GitHubLeakSeverity.HIGH,     "Database URL in org repo"),

    # ── Token patterns ────────────────────────────────────────────────────
    ('"{domain}" "Bearer " token',        "bearer_token",   GitHubLeakSeverity.HIGH,     "Bearer token for domain"),
    ('"{domain}" "Authorization:"',       "auth_header",    GitHubLeakSeverity.HIGH,     "Auth header for domain"),

    # ── Interesting exposures (INFO level) ────────────────────────────────
    ('"{domain}" internal',               "internal_ref",   GitHubLeakSeverity.INFO,     "Internal reference to domain"),
    ('"{domain}" staging',                "staging_ref",    GitHubLeakSeverity.INFO,     "Staging environment reference"),
    ('"{domain}" vpn',                    "vpn_ref",        GitHubLeakSeverity.INFO,     "VPN reference for domain"),
]

# Patterns used to extract and score matched values from file content
# (pattern_name, regex, severity_override_if_matched)
MATCH_PATTERNS: List[Tuple[str, str, Optional[GitHubLeakSeverity]]] = [
    ("aws_access_key",   r"(?:ASIA|AKIA|AROA|AIDA)[A-Z0-9]{16}",              GitHubLeakSeverity.CRITICAL),
    ("github_token",     r"ghp_[A-Za-z0-9]{36}",                               GitHubLeakSeverity.CRITICAL),
    ("github_token",     r"github_pat_[A-Za-z0-9_]{82}",                       GitHubLeakSeverity.CRITICAL),
    ("stripe_key",       r"sk_live_[0-9a-zA-Z]{24,}",                          GitHubLeakSeverity.CRITICAL),
    ("google_api_key",   r"AIza[0-9A-Za-z\-_]{35}",                            GitHubLeakSeverity.CRITICAL),
    ("jwt_token",        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.",     GitHubLeakSeverity.HIGH),
    ("rsa_private_key",  r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY", GitHubLeakSeverity.CRITICAL),
    ("mongodb_uri",      r"mongodb(?:\+srv)?://[^:]+:[^@]+@",                  GitHubLeakSeverity.CRITICAL),
    ("postgres_uri",     r"postgres(?:ql)?://[^:]+:[^@]+@",                    GitHubLeakSeverity.CRITICAL),
    ("password_assign",  r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]",        GitHubLeakSeverity.HIGH),
    ("secret_assign",    r"(?i)secret\s*[=:]\s*['\"][^'\"]{8,}['\"]",          GitHubLeakSeverity.HIGH),
]

_COMPILED_MATCH = [(n, re.compile(p, re.MULTILINE), s) for n, p, s in MATCH_PATTERNS]


def _extract_match(text: str) -> Tuple[Optional[str], Optional[GitHubLeakSeverity]]:
    """Scan text for known secret patterns. Returns (match_value, severity) or (None, None)."""
    for name, compiled, severity in _COMPILED_MATCH:
        m = compiled.search(text)
        if m:
            return m.group(0)[:80], severity
    return None, None


def _derive_org(domain: str) -> str:
    """Extract likely GitHub org name from a domain. shopify.com → shopify"""
    parts = domain.lower().rstrip(".").split(".")
    # Take the second-to-last part (before the TLD)
    return parts[-2] if len(parts) >= 2 else parts[0]


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Search API client
# ─────────────────────────────────────────────────────────────────────────────

class GitHubOSINTScanner:
    """
    Searches GitHub for leaked credentials and sensitive references
    belonging to a target domain.

    Yields GitHubLeak objects as they are found.
    Respects GitHub's rate limits — 30 requests/minute authenticated.
    """

    API_BASE = "https://api.github.com"

    def __init__(
        self,
        github_token:   Optional[str] = None,
        max_results:    int           = 30,
        rate_delay:     float         = 2.5,   # seconds between requests
    ) -> None:
        self.github_token = github_token
        self.max_results  = min(max(1, max_results), 100)
        self.rate_delay   = rate_delay

        if not github_token:
            logger.warning(
                "[github] GITHUB_TOKEN not set — searches will be rate-limited to 10/min "
                "and may return incomplete results. Set GITHUB_TOKEN in .env for full coverage."
            )

    def _headers(self) -> dict:
        headers = {
            "Accept":     "application/vnd.github.v3.text-match+json",
            "User-Agent": "ZeroPoint-OSINT/1.0",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    async def _search(
        self,
        session:  aiohttp.ClientSession,
        query:    str,
    ) -> List[dict]:
        """Execute one GitHub code search. Returns list of items."""
        url    = f"{self.API_BASE}/search/code"
        params = {"q": query, "per_page": self.max_results}

        try:
            async with session.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [])

                if resp.status == 403:
                    # Rate limited or token invalid
                    reset_ts = resp.headers.get("X-RateLimit-Reset")
                    logger.warning(
                        f"[github] 403 on query '{query[:60]}' — "
                        f"rate limited or bad token. Reset: {reset_ts}"
                    )
                    await asyncio.sleep(10)
                    return []

                if resp.status == 422:
                    # Unprocessable query (too short, etc.)
                    logger.debug(f"[github] 422 unprocessable query: {query[:60]}")
                    return []

                logger.debug(f"[github] HTTP {resp.status} for query: {query[:60]}")
                return []

        except asyncio.TimeoutError:
            logger.debug(f"[github] Timeout on query: {query[:60]}")
            return []
        except Exception as exc:
            logger.debug(f"[github] Error on query '{query[:60]}': {exc}")
            return []

    async def _fetch_file_content(
        self,
        session:  aiohttp.ClientSession,
        raw_url:  str,
    ) -> Optional[str]:
        """Fetch raw file content for a GitHub file URL."""
        try:
            async with session.get(
                raw_url,
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    return text[:50_000]  # cap at 50KB
                return None
        except Exception:
            return None

    async def scan(
        self,
        domain:     str,
        program_id: str,
        run_id:     str,
        tenant_id:  str = "default",
    ) -> AsyncIterator[GitHubLeak]:
        """
        Run all dork queries for a domain and yield GitHubLeak objects.
        Respects rate limits between requests.
        """
        org = _derive_org(domain)

        logger.info(
            f"[github] Scanning domain={domain} org={org} | "
            f"{len(DORK_TEMPLATES)} queries | max_results={self.max_results}"
        )

        connector = aiohttp.TCPConnector(ssl=True, limit=3)
        async with aiohttp.ClientSession(connector=connector) as session:
            for query_template, match_type, base_severity, description in DORK_TEMPLATES:
                if not self.github_token and "org:" in query_template:
                    # Org searches require auth for meaningful results
                    continue

                # Substitute domain/org into the query template
                query = query_template.replace("{domain}", domain).replace("{org}", org)

                await asyncio.sleep(self.rate_delay)  # respect rate limit

                items = await self._search(session, query)
                if not items:
                    continue

                logger.debug(f"[github] {len(items)} result(s) for: {query[:70]}")

                for item in items:
                    try:
                        repo     = item.get("repository", {})
                        repo_name = repo.get("full_name", "")
                        repo_url  = repo.get("html_url", "")
                        file_path = item.get("path", "")
                        file_url  = item.get("html_url", "")

                        if not repo_name or not file_path:
                            continue

                        # Build raw content URL for fetching
                        raw_url = (
                            f"https://raw.githubusercontent.com/"
                            f"{repo_name}/HEAD/{file_path}"
                        )

                        # Try to get file content for better match extraction
                        content = await self._fetch_file_content(session, raw_url)
                        await asyncio.sleep(self.rate_delay * 0.5)

                        # Use text_matches from GitHub if available
                        match_value   = ""
                        match_context = ""
                        line_number   = None
                        severity      = base_severity

                        text_matches = item.get("text_matches", [])
                        if text_matches:
                            fragment    = text_matches[0].get("fragment", "")
                            match_value = fragment[:80]
                            match_context = fragment[:300]

                        # Try to find a higher-confidence match in file content
                        if content:
                            extracted_val, extracted_sev = _extract_match(content)
                            if extracted_val:
                                match_value = extracted_val
                                severity    = extracted_sev or severity
                                # Find line number
                                for i, line in enumerate(content.split("\n"), 1):
                                    if extracted_val[:20] in line:
                                        line_number   = i
                                        match_context = line.strip()[:300]
                                        break

                        if not match_value:
                            match_value = description[:80]

                        leak_id = make_leak_id(repo_name, file_path, match_type, match_value)

                        leak = GitHubLeak(
                            tenant_id      = tenant_id,
                            leak_id        = leak_id,
                            program_id     = program_id,
                            domain         = domain,
                            repo_full_name = repo_name,
                            repo_url       = repo_url,
                            file_path      = file_path,
                            file_url       = file_url,
                            match_type     = match_type,
                            match_value    = match_value,
                            match_context  = match_context or None,
                            line_number    = line_number,
                            dork_query     = query,
                            severity       = severity,
                        )
                        yield leak

                    except Exception as exc:
                        logger.debug(f"[github] Error processing result: {exc}")
                        continue