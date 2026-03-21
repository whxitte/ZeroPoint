"""
ZeroPoint :: config.py
======================
Single source of truth for all configuration.
All values are loaded from environment variables / .env file.
Nothing is hardcoded anywhere else in the codebase.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Override any value by setting the corresponding env var or adding it to .env
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── MongoDB ─────────────────────────────────────────────────────────────
    MONGODB_URI:  str = Field(
        default="mongodb://localhost:27017",
        description="MongoDB Atlas connection string or local URI",
    )
    MONGODB_DB:   str = Field(default="zeropoint", description="Database name")
    MONGO_ASSETS_COLLECTION: str = Field(default="assets")
    MONGO_PROGRAMS_COLLECTION: str = Field(default="programs")

    # ── API Keys ─────────────────────────────────────────────────────────────
    SHODAN_API_KEY:   Optional[str] = Field(default=None, description="Shodan API key")
    GITHUB_TOKEN:     Optional[str] = Field(default=None, description="GitHub PAT — used by Subfinder AND GitHub OSINT module")
    VIRUSTOTAL_KEY:   Optional[str] = Field(default=None)
    CENSYS_ID:        Optional[str] = Field(default=None)
    CENSYS_SECRET:    Optional[str] = Field(default=None)

    # ── GitHub OSINT (Module 6) ──────────────────────────────────────────────
    GITHUB_OSINT_ENABLED:     bool  = Field(default=True)
    GITHUB_OSINT_INTERVAL:    int   = Field(
        default=21600,
        description="Seconds between GitHub OSINT runs in daemon mode (default: 6h)",
    )
    GITHUB_OSINT_MAX_RESULTS: int   = Field(
        default=30,
        description="Max GitHub search results per query (1-100). "
                    "Lower = faster, higher = more coverage.",
    )
    GITHUB_OSINT_RATE_DELAY:  float = Field(
        default=2.5,
        description="Seconds to sleep between GitHub API calls (rate limit: 30 req/min auth)",
    )

    # ── API Server settings ──────────────────────────────────────────────────
    API_HOST:          str  = Field(default="0.0.0.0")
    API_PORT:          int  = Field(default=8000)
    API_SECRET_KEY:    str  = Field(
        default="change-me-in-production",
        description="JWT signing secret — MUST be changed before exposing to network",
    )
    API_TOKEN_EXPIRE_MINUTES: int = Field(default=1440, description="JWT TTL in minutes (default: 24h)")
    API_CORS_ORIGINS:  str  = Field(
        default="http://localhost:3000",
        description="Comma-separated allowed CORS origins for the dashboard",
    )

    # ── Notifications ────────────────────────────────────────────────────────
    DISCORD_WEBHOOK_URL:  Optional[str] = Field(default=None)
    TELEGRAM_BOT_TOKEN:   Optional[str] = Field(default=None)
    TELEGRAM_CHAT_ID:     Optional[str] = Field(default=None)

    # ── Tool Paths (auto-detected if on PATH) ────────────────────────────────
    SUBFINDER_PATH:      str = Field(default="subfinder")
    HTTPX_PATH:          str = Field(default="httpx")
    NUCLEI_PATH:         str = Field(default="nuclei")
    KATANA_PATH:         str = Field(default="katana")
    WAYBACKURLS_PATH:    str = Field(default="waybackurls")
    GAU_PATH:            str = Field(default="gau")
    MASSCAN_PATH:        str = Field(default="masscan",  description="Masscan binary path")
    NMAP_PATH:           str = Field(default="nmap",     description="Nmap binary path")
    SECRETFINDER_PATH:   str = Field(
        default="",
        description="Full path to SecretFinder.py (e.g. /opt/SecretFinder/SecretFinder.py)",
    )

    # ── Port Scanner (Module 7) settings ─────────────────────────────────────
    PORTSCAN_PORTS:    str  = Field(
        default=(
            "21-23,25,53,80,443,445,1433,1521,2181,2375-2376,2379-2380,"
            "3000,3306,3389,4243,4369,5044,5050,5432,5601,5984,"
            "6379,6443,7077,8080,8125,8161,8443,8888,9000,9090,9092,"
            "9200,9300,9443,10250,10255,11211,15672,27017-27018"
        ),
        description="Comma-separated port ranges for Masscan/Nmap",
    )
    MASSCAN_RATE:      int  = Field(
        default=1000,
        description="Masscan packets/sec. Keep ≤1000 for stealth. Max ~10000 on fast links.",
    )
    NMAP_TIMEOUT:      int  = Field(
        default=120,
        description="Seconds per host for Nmap service fingerprint",
    )
    DAEMON_PORTSCAN_INTERVAL: int = Field(
        default=86400,
        description="Seconds between port scan runs in daemon mode (default: 24h)",
    )

    # u2500u2500 Google Dork Engine (Module 8) settings u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500u2500
    BRAVE_SEARCH_API_KEY:    Optional[str] = Field(default=None, description="Brave Search API key — https://api.search.brave.com/app/dashboard")
    SERPAPI_KEY:             Optional[str] = Field(default=None, description="SerpAPI key — 100 free searches/month, no card — https://serpapi.com")
    GOOGLE_API_KEY:          Optional[str] = Field(default=None, description="Google Cloud API key with Custom Search API enabled")
    GOOGLE_CSE_ID:           Optional[str] = Field(default=None, description="Google Custom Search Engine ID (cx parameter)")
    GOOGLE_DORK_MAX_RESULTS: int   = Field(default=10, description="Results per dork query (max 10 for Google CSE free tier)")
    GOOGLE_DORK_RATE_DELAY:  float = Field(default=1.1, description="Seconds between Google API requests (free tier: <=10 req/s)")
    DAEMON_DORK_INTERVAL:    int   = Field(default=86400, description="Seconds between dork runs in daemon mode (default: 24h)")
    DAEMON_ASN_INTERVAL:     int   = Field(default=86400, description="Seconds between ASN mapping runs in daemon mode (default: 24h)")

    # ── ASN Mapper (Module 9) settings ───────────────────────────────────────
    ASN_RATE_DELAY:      float = Field(default=1.2, description="Seconds between BGPView API requests")
    ASN_MAX_PREFIX_SIZE: int   = Field(default=65536, description="Skip prefixes with more IPs than this (/16 and larger)")
    ASN_SKIP_CDN:        bool  = Field(default=True,  description="Skip known CDN/cloud ASNs (Cloudflare, Akamai, AWS, etc.)")
    IPINFO_TOKEN:        Optional[str] = Field(default=None, description="ipinfo.io token for higher rate limits (optional, 50k req/month free without)")

    # ── Crawler (Module 4) settings ──────────────────────────────────────────
    CRAWLER_DEPTH:           int  = Field(default=3,    description="Katana crawl depth")
    CRAWLER_PARALLELISM:     int  = Field(default=10,   description="Katana -parallelism (concurrent crawls per asset)")
    CRAWLER_RATE_LIMIT:      int  = Field(default=50,   description="Katana -rate-limit (req/sec per asset)")
    CRAWLER_TIMEOUT:         int  = Field(default=120,  description="Max seconds per Katana invocation")
    CRAWLER_BATCH_SIZE:      int  = Field(default=20,   description="Assets per crawler batch")
    CRAWLER_PARALLEL_BATCHES: int = Field(default=3,    description="Concurrent crawler batches")
    CRAWLER_RECRAWL_HOURS:   int  = Field(default=48,   description="Re-crawl assets after N hours")
    CRAWLER_JS_ANALYSIS:     bool = Field(default=True, description="Run SecretFinder on JS files")
    CRAWLER_WAYBACK:         bool = Field(default=True, description="Fetch historical URLs via waybackurls")
    CRAWLER_GAU:             bool = Field(default=True, description="Fetch URLs via gau (GetAllUrls)")
    CRAWLER_MIN_INTEREST:    str  = Field(
        default="medium",
        description="Minimum interest_level to qualify for crawling (medium/high/critical)",
    )
    SECRET_MIN_ENTROPY:      float = Field(
        default=3.5,
        description="Shannon entropy threshold — values below this are likely false positives",
    )

    # ── Prober (Module 2) settings ───────────────────────────────────────────
    PROBER_BATCH_SIZE:       int   = Field(default=200,  description="Domains per httpx invocation")
    PROBER_THREADS:          int   = Field(default=50,   description="httpx -threads value")
    PROBER_RATE_LIMIT:       int   = Field(default=150,  description="httpx -rate-limit (req/sec)")
    PROBER_TIMEOUT:          int   = Field(default=10,   description="httpx -timeout per host (sec)")
    PROBER_RETRIES:          int   = Field(default=2,    description="httpx -retries per host")
    PROBER_REPROBE_HOURS:    int   = Field(default=24,   description="Re-probe alive assets after N hours")
    PROBER_FOLLOW_REDIRECTS: bool  = Field(default=True)
    PROBER_SCREENSHOT:       bool  = Field(default=False, description="Enable httpx -screenshot (slow)")
    PROBER_SCREENSHOT_DIR:   str   = Field(default="data/screenshots")

    # ── Scanner (Module 3) settings ──────────────────────────────────────────
    NUCLEI_TEMPLATES_PATH:            str  = Field(
        default="",
        description="Official nuclei-templates dir. Empty = nuclei auto-manages ~/.nuclei-templates",
    )
    NUCLEI_COMMUNITY_TEMPLATES_PATH:  str  = Field(
        default="",
        description="Path to nuclei-templates-community checkout (optional)",
    )
    NUCLEI_CUSTOM_TEMPLATES:          str  = Field(
        default="",
        description="Path to your own custom templates directory (optional)",
    )
    NUCLEI_FUZZING_TEMPLATES_PATH:    str  = Field(
        default="",
        description="Path to nuclei-templates/fuzzing directory. Enable with NUCLEI_ENABLE_FUZZING=true",
    )
    NUCLEI_ENABLE_FUZZING:            bool = Field(
        default=True,
        description="Enable passive fuzzing templates (nuclei -passive flag applied automatically)",
    )
    NUCLEI_SEVERITY:          str  = Field(
        default="critical,high,medium,low,info",
        description="All severities — every finding gets an immediate alert",
    )
    NUCLEI_RATE_LIMIT:        int  = Field(default=50,  description="Nuclei -rate-limit (req/sec)")
    NUCLEI_CONCURRENCY:       int  = Field(default=25,  description="Nuclei -c (template concurrency)")
    NUCLEI_BULK_SIZE:         int  = Field(default=25,  description="Nuclei -bulk-size")
    NUCLEI_TIMEOUT:           int  = Field(default=600, description="Max seconds per Nuclei invocation")
    NUCLEI_RETRIES:           int  = Field(default=1)
    NUCLEI_BATCH_SIZE:        int  = Field(default=50,  description="Targets per Nuclei invocation")
    NUCLEI_PARALLEL_BATCHES:  int  = Field(
        default=3,
        description=(
            "How many Nuclei processes to run simultaneously. "
            "Each process handles one batch of NUCLEI_BATCH_SIZE targets. "
            "Set to 1 to disable parallelism. "
            "Effective total req/sec = NUCLEI_RATE_LIMIT × NUCLEI_PARALLEL_BATCHES. "
            "Keep NUCLEI_RATE_LIMIT × NUCLEI_PARALLEL_BATCHES under ~200 to avoid WAF bans."
        ),
    )
    NUCLEI_RESCAN_HOURS:      int  = Field(default=72,  description="Re-scan assets after N hours")
    NUCLEI_INCLUDE_TAGS:      str  = Field(
        default="",
        description="Extra tags to always include alongside tech-derived tags",
    )
    NUCLEI_EXCLUDE_TAGS:      str  = Field(
        default="dos",
        description="Tags to never run. 'fuzz' removed — fuzzing enabled via NUCLEI_ENABLE_FUZZING",
    )
    SCANNER_MIN_INTEREST:     str  = Field(
        default="high",
        description="Minimum interest_level to qualify for scanning: high or critical",
    )

    # ── Orchestrator / Daemon (Module 5) settings ────────────────────────────
    DAEMON_INGEST_INTERVAL: int = Field(
        default=3600,
        description="Seconds between ingestion runs in daemon mode (default: 1h)",
    )
    DAEMON_PROBE_INTERVAL:  int = Field(
        default=7200,
        description="Seconds between probe runs in daemon mode (default: 2h)",
    )
    DAEMON_SCAN_INTERVAL:   int = Field(
        default=21600,
        description="Seconds between scan runs in daemon mode (default: 6h)",
    )
    DAEMON_CRAWL_INTERVAL:  int = Field(
        default=43200,
        description="Seconds between crawl runs in daemon mode (default: 12h)",
    )
    DAEMON_GITHUB_INTERVAL: int = Field(
        default=21600,
        description="Seconds between GitHub OSINT runs in daemon mode (default: 6h)",
    )

    # ── Concurrency & Rate-Limiting ──────────────────────────────────────────
    MAX_CONCURRENT_PROGRAMS:   int   = Field(default=3)
    MAX_CONCURRENT_TOOLS:      int   = Field(default=3)
    NOTIFICATIONS_CONCURRENCY: int   = Field(default=5, description="Max simultaneous alert HTTP connections")
    TELEGRAM_MAX_RETRIES:      int   = Field(default=3)
    TELEGRAM_RETRY_AFTER_MS:   int   = Field(default=1000)
    SUBFINDER_TIMEOUT:         int   = Field(default=300, description="Seconds")
    CRTSH_TIMEOUT:             int   = Field(default=120)
    CRTSH_RETRIES:             int   = Field(default=3)
    RATE_LIMIT_MIN_JITTER:     float = Field(default=0.5, description="Seconds")
    RATE_LIMIT_MAX_JITTER:     float = Field(default=2.5, description="Seconds")

    # ── Logging ──────────────────────────────────────────────────────────────
    LOG_LEVEL:    str  = Field(default="INFO")
    LOG_FILE:     str  = Field(default="logs/zeropoint.log")
    LOG_ROTATION: str  = Field(default="50 MB")
    LOG_RETENTION: str = Field(default="14 days")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()


# Convenience alias — import this directly throughout the project
settings = get_settings()