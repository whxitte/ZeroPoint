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
    GITHUB_TOKEN:     Optional[str] = Field(default=None, description="For Subfinder sources")
    VIRUSTOTAL_KEY:   Optional[str] = Field(default=None)
    CENSYS_ID:        Optional[str] = Field(default=None)
    CENSYS_SECRET:    Optional[str] = Field(default=None)

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
    SECRETFINDER_PATH:   str = Field(
        default="",
        description="Full path to SecretFinder.py (e.g. /opt/SecretFinder/SecretFinder.py)",
    )

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

    # ── Concurrency & Rate-Limiting ──────────────────────────────────────────
    MAX_CONCURRENT_PROGRAMS: int   = Field(default=3)
    MAX_CONCURRENT_TOOLS:    int   = Field(default=3)
    NOTIFICATIONS_CONCURRENCY: int = Field(default=5, description="Max simultaneous alert messages")
    TELEGRAM_MAX_RETRIES:    int   = Field(default=3)
    TELEGRAM_RETRY_AFTER_MS: int = Field(default=1000)

    SUBFINDER_TIMEOUT:       int   = Field(default=300, description="Seconds")
    CRTSH_TIMEOUT:           int   = Field(default=30)
    CRTSH_RETRIES:           int   = Field(default=3)
    RATE_LIMIT_MIN_JITTER:   float = Field(default=0.5, description="Seconds")
    RATE_LIMIT_MAX_JITTER:   float = Field(default=2.5, description="Seconds")

    # ── Logging ──────────────────────────────────────────────────────────────
    LOG_LEVEL:    str  = Field(default="INFO")
    LOG_FILE:     str  = Field(default="logs/zeropoint.log")
    LOG_ROTATION: str  = Field(default="50 MB")
    LOG_RETENTION: str = Field(default="14 days")

    # ── Daemon / Orchestrator (Module 5) settings ─────────────────────────────
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
        description="Seconds between scanner runs in daemon mode (default: 6h)",
    )
    DAEMON_CRAWL_INTERVAL:  int = Field(
        default=43200,
        description="Seconds between crawler runs in daemon mode (default: 12h)",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()


# Convenience alias — import this directly throughout the project
settings = get_settings()