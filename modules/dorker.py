"""
ZeroPoint :: modules/dorker.py
================================
Dork Engine — finds publicly indexed sensitive exposures via search APIs.

Supported backends (auto-selected by which key is present in .env):
  1. Brave Search API  (preferred — simpler setup, 2,000 free queries/month)
  2. Google Custom Search JSON API (fallback — 100 free queries/day)

Brave setup (2 minutes, recommended):
  1. Go to https://api.search.brave.com/app/dashboard
  2. Create a free account → "Add Subscription" → pick Free tier
  3. Copy the API key shown
  4. Add to .env:  BRAVE_SEARCH_API_KEY=BSA...

Google CSE setup (if you prefer Google):
  1. console.cloud.google.com → enable "Custom Search API"
  2. Create an API key → IMPORTANT: set NO restrictions on the key
     (Application restrictions = None, API restrictions = Don't restrict)
  3. cse.google.com/cse → create engine → add *.com/* as a site
  4. Add to .env:  GOOGLE_API_KEY=AIza...  GOOGLE_CSE_ID=abc123...

  Common Google 403 "does not have access" cause: API key has restrictions.
  Fix: Cloud Console → Credentials → your key → set both restrictions to None.

The dork engine works identically regardless of backend — same 39 templates,
same output format, same dedup fingerprints, same alerts.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, List, Optional, Tuple

import aiohttp
from loguru import logger

from db.dork_ops import make_dork_result_id
from models import DorkResult, DorkSeverity


# ─────────────────────────────────────────────────────────────────────────────
# Dork template library — shared by all backends
# (query_template, category, severity, reason)
# {domain} is replaced with the target at runtime
# ─────────────────────────────────────────────────────────────────────────────

DORK_TEMPLATES: List[Tuple[str, str, DorkSeverity, str]] = [
    # ── CRITICAL: Direct file exposures ──────────────────────────────────────
    ('site:{domain} filetype:env',
     "exposed_files", DorkSeverity.CRITICAL,
     ".env file indexed — often contains DB credentials and API keys"),

    ('site:{domain} filetype:sql',
     "exposed_files", DorkSeverity.CRITICAL,
     "SQL dump file publicly accessible — full database exposure"),

    ('site:{domain} ext:bak',
     "exposed_files", DorkSeverity.HIGH,
     "Backup file accessible — verify it is a real file, not a docs page"),

    ('site:{domain} filetype:log',
     "exposed_files", DorkSeverity.HIGH,
     "Log file indexed — may contain credentials or internal paths"),

    ('site:{domain} filetype:conf OR filetype:config',
     "exposed_files", DorkSeverity.HIGH,
     "Configuration file exposed — may contain credentials"),

    ('site:{domain} filetype:yml "password"',
     "exposed_files", DorkSeverity.CRITICAL,
     "YAML config with password field indexed"),

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
     "Admin panel URL indexed"),

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
     ".git directory exposed — source code and history accessible"),

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
# Shared result builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_result(
    domain:     str,
    category:   str,
    severity:   DorkSeverity,
    reason:     str,
    query:      str,
    url:        str,
    title:      Optional[str],
    snippet:    Optional[str],
    program_id: str,
    run_id:     str,
    tenant_id:  str,
) -> Optional[DorkResult]:
    url = (url or "").strip()
    if not url:
        return None

    # Drop obvious false positives before they reach the DB or alerts
    if _is_false_positive(url, title or "", snippet or "", category):
        logger.debug(f"[dork] FP filtered: {url[:80]}")
        return None

    return DorkResult(
        tenant_id      = tenant_id,
        result_id      = make_dork_result_id(domain, category, url),
        program_id     = program_id,
        domain         = domain,
        url            = url,
        title          = (title or "").strip() or None,
        snippet        = (snippet or "")[:300].strip() or None,
        dork_query     = query,
        dork_category  = category,
        severity       = severity,
        reason         = reason,
        scan_run_id    = run_id,
    )



# ─────────────────────────────────────────────────────────────────────────────
# False positive filter
# ─────────────────────────────────────────────────────────────────────────────

# URL path segments that indicate a documentation/forum/marketing page.
# Applied to ALL categories.
_FP_PATH_SEGMENTS = {
    "/docs/", "/documentation/", "/wiki/", "/help/", "/support/",
    "/forum/", "/forums/", "/community/", "/discuss/",
    "/blog/", "/news/", "/press/", "/about/",
    "/faq/", "/howto/", "/tutorial/", "/guide/", "/learn/",
    "/pricing/", "/plans/", "/signup/", "/register/", "/download/",
    "/t/",           # Discourse forum topic path (gitlab forum, etc.)
    "/questions/",   # Stack Overflow / Q&A sites
    "/answers/",
    "/post/",        # Blog post paths
    "/article/",
    "/tag/",
    "/category/",
    "/search?",      # Search results pages, not actual files
}

# Subdomains that never produce real findings.
_FP_SUBDOMAINS = {
    "docs.", "doc.", "forum.", "forums.", "community.", "support.",
    "help.", "learn.", "blog.", "news.", "status.", "www.",
    "developer.", "developers.", "about.", "university.",
    "discuss.", "answers.", "ask.", "knowledge.",
}

# For file-exposure categories, the URL must contain one of these markers —
# otherwise the result is a page that *discusses* the file type, not the file.
_FILE_CATEGORY_URL_HINTS = {
    "exposed_files": [
        ".env", ".bak", ".backup", ".sql", ".log", ".conf", ".config",
        ".pem", ".key", ".yml", ".json", ".xml", ".ini",
    ],
    "sensitive_dirs": [".git", ".svn", ".env"],
    "credentials":    [],   # content-based, no URL hint required
    "admin_panels":   [],   # URL-path-based queries, no extension hint
    "directory_listing": [],
    "error_pages":    [],
    "api_exposure":   [],
    "staging":        [],
}

# Title keywords that indicate intentionally public reference/example files.
# Applied only to exposed_files category to reduce FPs on open-source repos.
_SAFE_TITLE_KEYWORDS = [
    "sample", "example", "template", "demo", "mock",
    "schema", "migration", "fixture", "seed",
    "init_structure", "init_schema", "anonymizer", "anonymization",
    "documentation", " docs ", "readme", "changelog",
    "doxygen", "doxyfile",
]

# Filename patterns in the URL that indicate a safe reference file.
# Even if not in title, these are almost never real credentials.
_SAFE_URL_FILENAME_PATTERNS = [
    "sample.env", ".env.example", ".env.sample", ".env.dist",
    ".env.test", ".env.development", ".env.production.example",
    "config.env.example", "env.example",
    "config.env", "local.env", "development.env", "staging.env",
    "anon.sql", "anonymizer", "init_structure.sql",
    "schema.sql", "init.sql", "seed.sql", "fixture.sql",
    "migration", ".bib.bak", "doxyfile.bak", "phpunit.xml.dist.bak",
    "celerybeat-schedule.bak",
]


def _is_false_positive(url: str, title: str, snippet: str, category: str) -> bool:
    """
    Return True if this result is almost certainly a false positive.

    Rules (in priority order):
      1. Subdomain is a known documentation/forum/marketing subdomain
      2. URL path contains a known non-file path segment (/t/, /forum/, etc.)
      3. For file-exposure categories, URL must contain the file extension
      4. URL contains a known safe filename pattern (sample.env, schema.sql…)
      5. Title contains safe/harmless keywords for file-exposure queries
    """
    from urllib.parse import urlparse

    url_lower   = url.lower()
    title_lower = (title or "").lower()

    # Rule 1 — known noisy subdomains
    try:
        host = urlparse(url_lower).netloc
        for sub in _FP_SUBDOMAINS:
            if host.startswith(sub):
                return True
    except Exception:
        pass

    # Rule 2 — documentation/forum/blog path segments
    for seg in _FP_PATH_SEGMENTS:
        if seg in url_lower:
            return True

    # Rule 3 — for file-exposure categories the URL must contain the extension
    hints = _FILE_CATEGORY_URL_HINTS.get(category)
    if hints:   # only apply when list is non-empty
        if not any(hint in url_lower for hint in hints):
            return True     # URL has no file marker → docs/discussion page

    # Rule 4 — known safe filenames (open-source example/schema files)
    for pattern in _SAFE_URL_FILENAME_PATTERNS:
        if pattern in url_lower:
            return True

    # Rule 5 — title keywords indicating example/schema/reference content
    if category == "exposed_files":
        for kw in _SAFE_TITLE_KEYWORDS:
            if kw in title_lower:
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Backend 1 — Brave Search API (preferred)
# Free tier: 2,000 queries/month | 1 req/sec rate limit
# ─────────────────────────────────────────────────────────────────────────────

class BraveDorker:
    """
    Dork engine backed by Brave Search JSON API.
    2,000 free queries/month — no CSE setup, just one API key.
    Get your key: https://api.search.brave.com/app/dashboard
    """

    API_URL = "https://api.search.brave.com/res/v1/web/search"

    def __init__(
        self,
        api_key:     str,
        rate_delay:  float = 1.0,
        max_results: int   = 10,
    ) -> None:
        self.api_key     = api_key
        self.rate_delay  = rate_delay
        self.max_results = min(max(1, max_results), 20)
        self._exhausted  = False

    async def _search(self, session: aiohttp.ClientSession, query: str) -> List[dict]:
        if self._exhausted:
            return []

        headers = {
            "Accept":               "application/json",
            "Accept-Encoding":      "gzip",
            "X-Subscription-Token": self.api_key,
        }
        params = {"q": query, "count": self.max_results}

        try:
            async with session.get(
                self.API_URL,
                headers = headers,
                params  = params,
                timeout = aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("web", {}).get("results", [])

                if resp.status == 429:
                    logger.warning(
                        "[dork] Brave API rate limit (429) — "
                        "monthly quota (2,000 free queries) exhausted. Stopping."
                    )
                    self._exhausted = True
                    return []

                if resp.status == 401:
                    logger.error(
                        "[dork] ❌ Brave API key invalid.\n"
                        "  Get a free key: https://api.search.brave.com/app/dashboard\n"
                        "  Add to .env: BRAVE_SEARCH_API_KEY=BSA..."
                    )
                    self._exhausted = True
                    return []

                logger.debug(f"[dork] Brave HTTP {resp.status} | q={query[:60]}")
                return []

        except asyncio.TimeoutError:
            logger.debug(f"[dork] Brave timeout | q={query[:60]}")
            return []
        except Exception as exc:
            logger.debug(f"[dork] Brave error: {exc}")
            return []

    async def dork(
        self,
        domain:     str,
        program_id: str,
        run_id:     str,
        tenant_id:  str = "default",
    ) -> AsyncIterator[DorkResult]:
        logger.info(
            f"[dork] Brave Search | domain={domain} | "
            f"{len(DORK_TEMPLATES)} queries | max_results={self.max_results}/query"
        )
        connector = aiohttp.TCPConnector(ssl=True, limit=3)
        async with aiohttp.ClientSession(connector=connector) as session:
            for query_template, category, severity, reason in DORK_TEMPLATES:
                if self._exhausted:
                    break
                query = query_template.replace("{domain}", domain)
                await asyncio.sleep(self.rate_delay)

                items = await self._search(session, query)
                if not items:
                    continue

                logger.debug(f"[dork] {len(items)} hit(s) | cat={category} | q={query[:60]}")

                for item in items:
                    try:
                        result = _build_result(
                            domain     = domain,
                            category   = category,
                            severity   = severity,
                            reason     = reason,
                            query      = query,
                            url        = item.get("url", ""),
                            title      = item.get("title"),
                            snippet    = item.get("description"),
                            program_id = program_id,
                            run_id     = run_id,
                            tenant_id  = tenant_id,
                        )
                        if result:
                            yield result
                    except Exception as exc:
                        logger.debug(f"[dork] Brave result error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Backend 2 — Google Custom Search JSON API (fallback)
# Free tier: 100 queries/day
# ─────────────────────────────────────────────────────────────────────────────

class GoogleDorker:
    """
    Dork engine backed by Google Custom Search JSON API.
    100 free queries/day. Requires API key + CSE ID.

    If you get 403 "does not have access":
      Cloud Console → Credentials → your API key → Edit
      → Application restrictions: None
      → API restrictions: Don't restrict key
      → Save → wait 2 min → retry
    """

    API_BASE = "https://www.googleapis.com/customsearch/v1"

    def __init__(
        self,
        api_key:     str,
        cse_id:      str,
        max_results: int   = 10,
        rate_delay:  float = 1.1,
    ) -> None:
        self.api_key       = api_key
        self.cse_id        = cse_id
        self.max_results   = min(max(1, max_results), 10)
        self.rate_delay    = rate_delay
        self._api_disabled = False

    async def _search(self, session: aiohttp.ClientSession, query: str) -> List[dict]:
        if self._api_disabled:
            return []

        params = {
            "key": self.api_key,
            "cx":  self.cse_id,
            "q":   query,
            "num": self.max_results,
        }

        try:
            async with session.get(
                self.API_BASE,
                params  = params,
                timeout = aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("items", [])

                if resp.status == 429:
                    logger.warning("[dork] Google API 429 — daily quota exhausted. Stopping.")
                    self._api_disabled = True
                    return []

                if resp.status == 403:
                    body = await resp.json()
                    err  = body.get("error", {}).get("message", "unknown")

                    if "does not have the access" in err or "not enabled" in err.lower():
                        logger.error(
                            f"[dork] ❌ Google API 403: {err}\n"
                            f"\n"
                            f"  Most likely fix — remove API key restrictions:\n"
                            f"  1. Cloud Console → APIs & Services → Credentials\n"
                            f"  2. Click your key → Edit\n"
                            f"  3. Application restrictions → None\n"
                            f"  4. API restrictions → Don't restrict key\n"
                            f"  5. Save → wait 2 minutes → retry\n"
                            f"\n"
                            f"  Easier alternative: use Brave Search (2,000 free/month):\n"
                            f"  https://api.search.brave.com/app/dashboard\n"
                            f"  Add BRAVE_SEARCH_API_KEY=BSA... to .env"
                        )
                        self._api_disabled = True
                        return []

                    logger.warning(f"[dork] Google 403: {err}")
                    return []

                logger.debug(f"[dork] Google HTTP {resp.status} | q={query[:60]}")
                return []

        except asyncio.TimeoutError:
            logger.debug(f"[dork] Google timeout | q={query[:60]}")
            return []
        except Exception as exc:
            logger.debug(f"[dork] Google error: {exc}")
            return []

    async def dork(
        self,
        domain:     str,
        program_id: str,
        run_id:     str,
        tenant_id:  str = "default",
    ) -> AsyncIterator[DorkResult]:
        logger.info(
            f"[dork] Google CSE | domain={domain} | "
            f"{len(DORK_TEMPLATES)} queries | max_results={self.max_results}/query"
        )
        connector = aiohttp.TCPConnector(ssl=True, limit=3)
        async with aiohttp.ClientSession(connector=connector) as session:
            for query_template, category, severity, reason in DORK_TEMPLATES:
                if self._api_disabled:
                    break
                query = query_template.replace("{domain}", domain)
                await asyncio.sleep(self.rate_delay)

                items = await self._search(session, query)
                if not items:
                    continue

                logger.debug(f"[dork] {len(items)} hit(s) | cat={category} | q={query[:60]}")

                for item in items:
                    try:
                        result = _build_result(
                            domain     = domain,
                            category   = category,
                            severity   = severity,
                            reason     = reason,
                            query      = query,
                            url        = item.get("link", ""),
                            title      = item.get("title"),
                            snippet    = item.get("snippet"),
                            program_id = program_id,
                            run_id     = run_id,
                            tenant_id  = tenant_id,
                        )
                        if result:
                            yield result
                    except Exception as exc:
                        logger.debug(f"[dork] Google result error: {exc}")



# ─────────────────────────────────────────────────────────────────────────────
# Backend 3 — SerpAPI (truly free tier, no card needed)
# Free tier: 100 searches/month, no credit card required
# ─────────────────────────────────────────────────────────────────────────────

class SerpApiDorker:
    """
    Dork engine backed by SerpAPI (Google Search results via proxy).
    100 searches/month free — no credit card required.
    Get key: https://serpapi.com/users/sign_up

    Uses Google search results so all site: operators work perfectly.
    """

    API_URL = "https://serpapi.com/search"

    def __init__(
        self,
        api_key:     str,
        rate_delay:  float = 1.5,
        max_results: int   = 10,
    ) -> None:
        self.api_key     = api_key
        self.rate_delay  = rate_delay
        self.max_results = min(max(1, max_results), 10)
        self._exhausted  = False

    async def _search(self, session: aiohttp.ClientSession, query: str) -> List[dict]:
        if self._exhausted:
            return []

        params = {
            "q":       query,
            "api_key": self.api_key,
            "engine":  "google",
            "num":     self.max_results,
        }

        try:
            async with session.get(
                self.API_URL,
                params  = params,
                timeout = aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # SerpAPI returns organic_results list
                    return data.get("organic_results", [])

                if resp.status == 429 or resp.status == 401:
                    body = await resp.json()
                    err  = body.get("error", "unknown")
                    if "credit" in err.lower() or "out of searches" in err.lower():
                        logger.warning(
                            f"[dork] SerpAPI monthly limit reached: {err}\n"
                            "  Free tier: 100 searches/month\n"
                            "  Upgrade or wait until next month."
                        )
                    else:
                        logger.error(f"[dork] SerpAPI auth error: {err}\n"
                            "  Check your key at https://serpapi.com/manage-api-key")
                    self._exhausted = True
                    return []

                logger.debug(f"[dork] SerpAPI HTTP {resp.status} | q={query[:60]}")
                return []

        except asyncio.TimeoutError:
            logger.debug(f"[dork] SerpAPI timeout | q={query[:60]}")
            return []
        except Exception as exc:
            logger.debug(f"[dork] SerpAPI error: {exc}")
            return []

    async def dork(
        self,
        domain:     str,
        program_id: str,
        run_id:     str,
        tenant_id:  str = "default",
    ) -> AsyncIterator[DorkResult]:
        logger.info(
            f"[dork] SerpAPI | domain={domain} | "
            f"{len(DORK_TEMPLATES)} queries | max_results={self.max_results}/query"
        )
        connector = aiohttp.TCPConnector(ssl=True, limit=3)
        async with aiohttp.ClientSession(connector=connector) as session:
            for query_template, category, severity, reason in DORK_TEMPLATES:
                if self._exhausted:
                    break
                query = query_template.replace("{domain}", domain)
                await asyncio.sleep(self.rate_delay)

                items = await self._search(session, query)
                if not items:
                    continue

                logger.debug(f"[dork] {len(items)} hit(s) | cat={category} | q={query[:60]}")

                for item in items:
                    try:
                        result = _build_result(
                            domain     = domain,
                            category   = category,
                            severity   = severity,
                            reason     = reason,
                            query      = query,
                            url        = item.get("link", ""),
                            title      = item.get("title"),
                            snippet    = item.get("snippet"),
                            program_id = program_id,
                            run_id     = run_id,
                            tenant_id  = tenant_id,
                        )
                        if result:
                            yield result
                    except Exception as exc:
                        logger.debug(f"[dork] SerpAPI result error: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Factory — auto-select backend based on available .env keys
# ─────────────────────────────────────────────────────────────────────────────

def build_dorker(
    brave_key:    Optional[str] = None,
    google_key:   Optional[str] = None,
    google_cse:   Optional[str] = None,
    serpapi_key:  Optional[str] = None,
    max_results:  int   = 10,
    rate_delay:   float = 1.1,
):
    """
    Auto-select the best available dork backend.

    Priority: Brave > SerpAPI > Google > None
    Returns None if no keys are configured.

    Options (add ONE to .env):

      BRAVE_SEARCH_API_KEY=BSA...
        → https://api.search.brave.com/app/dashboard
        → $5 free credits/month = 1,000 free searches
        → Needs a credit card on file (not charged under $5/month)

      SERPAPI_KEY=...
        → https://serpapi.com/users/sign_up
        → 100 free searches/month, NO credit card required
        → Uses Google index so all site: operators work

      GOOGLE_API_KEY=AIza... + GOOGLE_CSE_ID=abc...
        → 100 free queries/day
        → Requires billing linked to GCP project (not charged under quota)
        → Common 403 fix: link a billing account at console.cloud.google.com/billing
    """
    if brave_key:
        logger.info("[dork] Backend: Brave Search API ($5 free credits/month)")
        return BraveDorker(
            api_key     = brave_key,
            rate_delay  = rate_delay,
            max_results = max_results,
        )

    if serpapi_key:
        logger.info("[dork] Backend: SerpAPI (100 free searches/month, no card needed)")
        return SerpApiDorker(
            api_key     = serpapi_key,
            rate_delay  = rate_delay,
            max_results = max_results,
        )

    if google_key and google_cse:
        logger.info("[dork] Backend: Google Custom Search API (100 free queries/day)")
        return GoogleDorker(
            api_key     = google_key,
            cse_id      = google_cse,
            max_results = max_results,
            rate_delay  = rate_delay,
        )

    return None