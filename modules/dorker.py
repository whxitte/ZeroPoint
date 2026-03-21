"""
ZeroPoint :: modules/dorker.py
================================
Google Dork Engine — finds publicly indexed sensitive exposures.

Uses the Google Custom Search JSON API to execute targeted dork queries.
Finds things no scanner discovers because they require Google's index:
  - Exposed .env files (site:target.com filetype:env)
  - Database dumps (site:target.com filetype:sql)
  - Config files with credentials (site:target.com "DB_PASSWORD")
  - Admin panels indexed by Google (site:target.com inurl:admin)
  - Backup files (site:target.com ext:bak OR ext:backup)
  - Error pages leaking stack traces (site:target.com "mysql error")
  - Open directory listings (site:target.com "Index of /")
  - API keys in public code (site:target.com "api_key")

Google Custom Search API:
  Free tier: 100 queries/day
  Paid tier: $5/1000 queries (very cheap for the signal)

  Setup (5 minutes):
  1. Go to https://console.cloud.google.com
  2. Create a project → enable "Custom Search API"
  3. Create credentials → API key
  4. Go to https://cse.google.com/cse/
  5. Create a Custom Search Engine
     - In "Sites to search", enter: *.* (search entire web)
     - After creation, note the Search Engine ID (cx)
  6. Add to .env:
       GOOGLE_API_KEY=AIza...
       GOOGLE_CSE_ID=abc123...

Rate limiting:
  The free tier caps at 100 queries/day and ~10 requests/second.
  We sleep between requests and track daily quota usage.
  With 100 free queries, scan one high-value target per day.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import AsyncIterator, List, Optional, Tuple

import aiohttp
from loguru import logger

from db.dork_ops import make_dork_result_id
from models import DorkResult, DorkSeverity


# ─────────────────────────────────────────────────────────────────────────────
# Dork template library
# (query_template, category, severity, reason)
# {domain} is replaced with the target at runtime
# ─────────────────────────────────────────────────────────────────────────────

DORK_TEMPLATES: List[Tuple[str, str, DorkSeverity, str]] = [
    # ── CRITICAL: Direct file exposures ──────────────────────────────────────
    ('site:{domain} filetype:env',
     "exposed_files", DorkSeverity.CRITICAL,
     ".env file indexed by Google — often contains DB credentials and API keys"),

    ('site:{domain} filetype:sql',
     "exposed_files", DorkSeverity.CRITICAL,
     "SQL dump file publicly accessible — full database exposure"),

    ('site:{domain} ext:bak',
     "exposed_files", DorkSeverity.CRITICAL,
     "Backup file publicly accessible — may contain source code or credentials"),

    ('site:{domain} ext:backup',
     "exposed_files", DorkSeverity.CRITICAL,
     "Backup file publicly accessible"),

    ('site:{domain} filetype:log',
     "exposed_files", DorkSeverity.HIGH,
     "Log file indexed — may contain credentials or internal paths"),

    ('site:{domain} filetype:conf OR filetype:config',
     "exposed_files", DorkSeverity.HIGH,
     "Configuration file exposed — may contain credentials"),

    ('site:{domain} filetype:yml "password"',
     "exposed_files", DorkSeverity.CRITICAL,
     "YAML config with password field indexed by Google"),

    ('site:{domain} filetype:json "api_key" OR "apikey" OR "secret"',
     "exposed_files", DorkSeverity.HIGH,
     "JSON file with potential API key or secret"),

    ('site:{domain} ext:pem OR ext:key',
     "exposed_files", DorkSeverity.CRITICAL,
     "Private key or certificate file exposed"),

    ('site:{domain} filetype:php "DB_PASSWORD" OR "database_password"',
     "exposed_files", DorkSeverity.CRITICAL,
     "PHP file with hardcoded database password"),

    # ── CRITICAL: Credential exposure patterns ────────────────────────────────
    ('site:{domain} "DB_PASSWORD" OR "DATABASE_PASSWORD"',
     "credentials", DorkSeverity.CRITICAL,
     "Database password string indexed publicly"),

    ('site:{domain} "api_secret" OR "api_key" OR "apikey"',
     "credentials", DorkSeverity.HIGH,
     "API key or secret string found in indexed page"),

    ('site:{domain} "AWS_ACCESS_KEY_ID" OR "AWS_SECRET_ACCESS_KEY"',
     "credentials", DorkSeverity.CRITICAL,
     "AWS credentials indexed publicly — immediate rotation required"),

    ('site:{domain} "BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"',
     "credentials", DorkSeverity.CRITICAL,
     "Private key exposed in indexed content"),

    ('site:{domain} "password=" OR "passwd=" OR "pwd="',
     "credentials", DorkSeverity.HIGH,
     "Password assignment in publicly indexed page"),

    ('site:{domain} "mongodb://" OR "postgresql://" OR "mysql://"',
     "credentials", DorkSeverity.CRITICAL,
     "Database connection string with credentials indexed publicly"),

    # ── HIGH: Admin panels and login pages ────────────────────────────────────
    ('site:{domain} inurl:admin',
     "admin_panels", DorkSeverity.HIGH,
     "Admin panel URL indexed by Google"),

    ('site:{domain} inurl:login OR inurl:signin',
     "admin_panels", DorkSeverity.HIGH,
     "Login page indexed"),

    ('site:{domain} inurl:dashboard',
     "admin_panels", DorkSeverity.HIGH,
     "Dashboard URL indexed"),

    ('site:{domain} inurl:wp-admin',
     "admin_panels", DorkSeverity.HIGH,
     "WordPress admin panel indexed"),

    ('site:{domain} inurl:phpmyadmin',
     "admin_panels", DorkSeverity.CRITICAL,
     "phpMyAdmin panel indexed — database admin access"),

    ('site:{domain} inurl:grafana',
     "admin_panels", DorkSeverity.HIGH,
     "Grafana dashboard indexed"),

    ('site:{domain} inurl:kibana',
     "admin_panels", DorkSeverity.HIGH,
     "Kibana dashboard indexed"),

    ('site:{domain} inurl:jenkins',
     "admin_panels", DorkSeverity.HIGH,
     "Jenkins CI/CD panel indexed"),

    # ── HIGH: Sensitive directories ───────────────────────────────────────────
    ('site:{domain} intitle:"Index of /"',
     "directory_listing", DorkSeverity.HIGH,
     "Open directory listing — browse server filesystem"),

    ('site:{domain} intitle:"Index of" "Parent Directory"',
     "directory_listing", DorkSeverity.HIGH,
     "Open directory listing"),

    ('site:{domain} inurl:.git',
     "sensitive_dirs", DorkSeverity.CRITICAL,
     ".git directory exposed — full source code and history accessible"),

    ('site:{domain} inurl:.svn',
     "sensitive_dirs", DorkSeverity.HIGH,
     ".svn directory exposed — source code accessible"),

    ('site:{domain} inurl:/.env',
     "sensitive_dirs", DorkSeverity.CRITICAL,
     ".env file URL indexed directly"),

    # ── MEDIUM: Error pages and info leaks ────────────────────────────────────
    ('site:{domain} "mysql error" OR "sql syntax" OR "mysql_fetch"',
     "error_pages", DorkSeverity.MEDIUM,
     "MySQL error message in indexed page — SQL injection possible"),

    ('site:{domain} "Stack Trace" OR "at java.lang" OR "Traceback (most recent"',
     "error_pages", DorkSeverity.MEDIUM,
     "Stack trace exposed — reveals internal code paths"),

    ('site:{domain} "Warning: mysql" OR "ORA-" OR "Microsoft OLE DB"',
     "error_pages", DorkSeverity.MEDIUM,
     "Database error message exposed"),

    ('site:{domain} "Internal Server Error" OR "500 Internal"',
     "error_pages", DorkSeverity.MEDIUM,
     "Server error pages indexed — internal path disclosure"),

    ('site:{domain} "PHPInfo()" OR intitle:"phpinfo"',
     "error_pages", DorkSeverity.HIGH,
     "PHP info page indexed — full server configuration exposed"),

    # ── HIGH: API and documentation exposure ──────────────────────────────────
    ('site:{domain} inurl:swagger OR intitle:"Swagger UI"',
     "api_exposure", DorkSeverity.HIGH,
     "Swagger API documentation indexed — full API schema exposed"),

    ('site:{domain} inurl:api-docs OR inurl:openapi',
     "api_exposure", DorkSeverity.HIGH,
     "API documentation indexed publicly"),

    ('site:{domain} inurl:graphql',
     "api_exposure", DorkSeverity.HIGH,
     "GraphQL endpoint indexed — introspection may be enabled"),

    # ── INFO: Staging and development ─────────────────────────────────────────
    ('site:{domain} inurl:staging OR inurl:dev OR inurl:test',
     "staging", DorkSeverity.INFO,
     "Staging or development environment indexed"),

    ('site:{domain} inurl:beta',
     "staging", DorkSeverity.INFO,
     "Beta environment indexed"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Google Custom Search API client
# ─────────────────────────────────────────────────────────────────────────────

class GoogleDorker:
    """
    Executes Google dork queries via the Custom Search JSON API.
    Yields DorkResult objects for each unique URL found.

    API reference: https://developers.google.com/custom-search/v1/reference/rest/v1/cse/list

    Usage:
        dorker = GoogleDorker(api_key="AIza...", cse_id="abc123...")
        async for result in dorker.dork(domain, program_id, run_id):
            await db.upsert_dork_result(result)
    """

    API_BASE = "https://www.googleapis.com/customsearch/v1"

    def __init__(
        self,
        api_key:     str,
        cse_id:      str,
        max_results: int   = 10,    # per query (max 10 for free tier)
        rate_delay:  float = 1.1,   # seconds between requests (≤10 req/s)
    ) -> None:
        self.api_key     = api_key
        self.cse_id      = cse_id
        self.max_results = min(max(1, max_results), 10)
        self.rate_delay  = rate_delay

    async def _search(
        self,
        session: aiohttp.ClientSession,
        query:   str,
    ) -> List[dict]:
        """Execute one Google Custom Search query. Returns list of result items."""
        params = {
            "key": self.api_key,
            "cx":  self.cse_id,
            "q":   query,
            "num": self.max_results,
        }

        try:
            async with session.get(
                self.API_BASE,
                params=params,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [])

                if resp.status == 429:
                    logger.warning(
                        f"[dork] Google API rate limited (429) on query: {query[:60]}\n"
                        "  You may have exceeded the daily quota (100 free queries/day)."
                    )
                    await asyncio.sleep(30)
                    return []

                if resp.status == 403:
                    body = await resp.json()
                    err  = body.get("error", {}).get("message", "unknown")
                    logger.warning(f"[dork] Google API 403: {err}")
                    return []

                logger.debug(f"[dork] HTTP {resp.status} for query: {query[:60]}")
                return []

        except asyncio.TimeoutError:
            logger.debug(f"[dork] Timeout on query: {query[:60]}")
            return []
        except Exception as exc:
            logger.debug(f"[dork] Error on query '{query[:60]}': {exc}")
            return []

    async def dork(
        self,
        domain:     str,
        program_id: str,
        run_id:     str,
        tenant_id:  str = "default",
    ) -> AsyncIterator[DorkResult]:
        """
        Run all dork templates for a domain and yield DorkResult objects.
        """
        logger.info(
            f"[dork] Scanning domain={domain} | "
            f"{len(DORK_TEMPLATES)} queries | max_results={self.max_results}/query"
        )

        connector = aiohttp.TCPConnector(ssl=True, limit=3)
        async with aiohttp.ClientSession(connector=connector) as session:
            for query_template, category, severity, reason in DORK_TEMPLATES:
                query = query_template.replace("{domain}", domain)

                await asyncio.sleep(self.rate_delay)

                items = await self._search(session, query)
                if not items:
                    continue

                logger.debug(
                    f"[dork] {len(items)} result(s) | "
                    f"cat={category} | q={query[:60]}"
                )

                for item in items:
                    try:
                        url     = item.get("link", "").strip()
                        title   = item.get("title", "").strip() or None
                        snippet = item.get("snippet", "").strip() or None

                        if not url:
                            continue

                        result_id = make_dork_result_id(domain, category, url)

                        yield DorkResult(
                            tenant_id      = tenant_id,
                            result_id      = result_id,
                            program_id     = program_id,
                            domain         = domain,
                            url            = url,
                            title          = title,
                            snippet        = snippet[:300] if snippet else None,
                            dork_query     = query,
                            dork_category  = category,
                            severity       = severity,
                            reason         = reason,
                            scan_run_id    = run_id,
                        )

                    except Exception as exc:
                        logger.debug(f"[dork] Error processing result: {exc}")
                        continue