"""
ZeroPoint :: models.py
======================
Canonical Pydantic schemas for the entire pipeline.
Every byte of data entering or leaving ZeroPoint is validated here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ReconSource(str, Enum):
    """Every discovery tool must have a registered source entry."""
    SUBFINDER = "subfinder"
    CRTSH     = "crtsh"
    SHODAN    = "shodan"
    AMASS     = "amass"    # reserved
    CHAOS     = "chaos"    # reserved
    UNKNOWN   = "unknown"  # for tool errors


class AssetStatus(str, Enum):
    """Lifecycle state of a discovered asset."""
    NEW    = "new"
    ACTIVE = "active"
    STALE  = "stale"


class ProbeStatus(str, Enum):
    """HTTP probing result for an asset — set by the Prober module."""
    NOT_PROBED = "not_probed"
    ALIVE      = "alive"
    DEAD       = "dead"
    ERROR      = "error"


class InterestLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    NOISE    = "noise"


class ProgramPlatform(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD  = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    PRIVATE   = "private"


class ScanSeverity(str, Enum):
    CRITICAL  = "critical"
    HIGH      = "high"
    MEDIUM    = "medium"
    LOW       = "low"
    INFO      = "info"
    UNKNOWN   = "unknown"


class ScanStatus(str, Enum):
    QUEUED    = "queued"
    SCANNING  = "scanning"
    DONE      = "done"
    ERROR     = "error"
    SKIPPED   = "skipped"


# ---------------------------------------------------------------------------
# SaaS: Tenant model
# ---------------------------------------------------------------------------

class Tenant(BaseModel):
    """
    A tenant — one row per customer/user of the platform.
    For personal use, a single "default" tenant exists.

    tenant_id is the partition key added to every collection document.
    All queries filter by it, making the DB fully multi-tenant.
    """
    tenant_id:   str
    name:        str
    api_key:     Optional[str]  = None   # hashed, used for REST API auth
    is_active:   bool           = True
    plan:        str            = "personal"   # personal | pro | enterprise
    created_at:  datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at:  datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Usage limits (None = unlimited)
    max_programs:  Optional[int] = None
    max_assets:    Optional[int] = None


# ---------------------------------------------------------------------------
# Program  —  top-level entity; one entry per bug bounty program
# ---------------------------------------------------------------------------

class Program(BaseModel):
    """Represents a bug bounty program we are monitoring."""

    tenant_id:  str     = "default"          # ← SaaS partition key
    program_id: str
    name:       str
    platform:   ProgramPlatform
    domains:    List[str]
    wildcards:  List[str] = Field(default_factory=list)
    is_active:  bool      = True
    notes:      Optional[str] = None
    created_at: datetime  = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime  = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("domains", "wildcards", mode="before")
    @classmethod
    def lowercase_and_strip(cls, v: List[str]) -> List[str]:
        return [d.lower().strip() for d in v if d.strip()]


# ---------------------------------------------------------------------------
# Asset  —  the atomic unit; one entry per discovered subdomain
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    """
    A single discovered subdomain / IP asset.
    DB upsert key = `domain`.
    """

    tenant_id:   str     = "default"          # ← SaaS partition key
    domain:      str
    program_id:  str
    sources:     List[ReconSource] = Field(default_factory=list)
    ip_addresses: List[str]        = Field(default_factory=list)
    status:      AssetStatus       = AssetStatus.NEW
    is_new:      bool              = True
    first_seen:  datetime          = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:   datetime          = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Module 2: HTTP Probe fields ─────────────────────────────────────
    probe_status:    ProbeStatus    = ProbeStatus.NOT_PROBED
    http_status:     Optional[int]  = None
    http_title:      Optional[str]  = None
    web_server:      Optional[str]  = None
    content_type:    Optional[str]  = None
    technologies:    List[str]      = Field(default_factory=list)
    cdn_provider:    Optional[str]  = None
    redirect_url:    Optional[str]  = None
    favicon_hash:    Optional[str]  = None
    body_preview:    Optional[str]  = None
    content_length:  Optional[int]  = None
    response_time_ms: Optional[int] = None
    last_probed:     Optional[datetime] = None

    # ── Module 2: Triage classification ─────────────────────────────────
    interest_level:  InterestLevel  = InterestLevel.LOW
    interest_reasons: List[str]     = Field(default_factory=list)

    # ── Module 3+ reserved fields ────────────────────────────────────────
    open_ports:      List[int]      = Field(default_factory=list)
    screenshot_path: Optional[str]  = None
    nuclei_findings: List[str]      = Field(default_factory=list)
    extra:           Dict[str, Any] = Field(default_factory=dict)

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")

    @field_validator("ip_addresses", mode="before")
    @classmethod
    def deduplicate_ips(cls, v: List[str]) -> List[str]:
        return list(set(v))


# ---------------------------------------------------------------------------
# Internal DTOs — inter-module communication, never persisted directly
# ---------------------------------------------------------------------------

class ReconResult(BaseModel):
    source:   ReconSource
    domains:  List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    errors:   List[str]      = Field(default_factory=list)


class UpsertResult(BaseModel):
    domain:     str
    program_id: str
    is_new:     bool
    source:     ReconSource


class ProbeResult(BaseModel):
    domain:           str
    probe_status:     ProbeStatus
    http_status:      Optional[int]  = None
    http_title:       Optional[str]  = None
    web_server:       Optional[str]  = None
    content_type:     Optional[str]  = None
    technologies:     List[str]      = Field(default_factory=list)
    cdn_provider:     Optional[str]  = None
    redirect_url:     Optional[str]  = None
    favicon_hash:     Optional[str]  = None
    body_preview:     Optional[str]  = None
    content_length:   Optional[int]  = None
    response_time_ms: Optional[int]  = None
    ip_addresses:     List[str]      = Field(default_factory=list)

    interest_level:   InterestLevel  = InterestLevel.LOW
    interest_reasons: List[str]      = Field(default_factory=list)

    @field_validator("domain", mode="before")
    @classmethod
    def normalise(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


# ---------------------------------------------------------------------------
# Finding  —  a single confirmed vulnerability from Nuclei
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    Persisted to the `findings` collection.
    Dedup key: sha256(template_id + domain + matched_at)
    """
    tenant_id:    str     = "default"          # ← SaaS partition key

    finding_id:   str
    program_id:   str
    domain:       str

    template_id:  str
    template_name: str
    severity:     ScanSeverity
    matched_at:   str
    matcher_name: Optional[str]  = None
    description:  Optional[str]  = None
    reference:    List[str]      = Field(default_factory=list)
    tags:         List[str]      = Field(default_factory=list)
    curl_command: Optional[str]  = None
    request:      Optional[str]  = None
    response:     Optional[str]  = None
    extracted_results: List[str] = Field(default_factory=list)

    first_seen:   datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_new:       bool           = True
    suppress_until: Optional[datetime] = None   # set after alert — suppresses re-alerts until this time
    scan_run_id:  Optional[str]  = None
    confirmed:    bool           = True
    extra:        Dict[str, Any] = Field(default_factory=dict)

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


class ScanRun(BaseModel):
    """Audit record for a single scanner run."""
    run_id:       str            = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:   str
    started_at:   datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:  Optional[datetime] = None
    targets:      int            = 0
    findings:     int            = 0
    new_findings: int            = 0
    templates_used: List[str]    = Field(default_factory=list)
    errors:       List[str]      = Field(default_factory=list)
    success:      bool           = True


# ---------------------------------------------------------------------------
# Module 4: Crawler & JS Analysis models
# ---------------------------------------------------------------------------

class SecretSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    INFO     = "info"


class CrawlSecret(BaseModel):
    """
    A single secret found in JS or page source.
    Dedup key: sha256(secret_type + domain + secret_value[:32])
    """
    tenant_id:    str     = "default"          # ← SaaS partition key

    secret_id:    str
    program_id:   str
    domain:       str
    source_url:   str
    secret_type:  str
    secret_value: str
    severity:     SecretSeverity         = SecretSeverity.HIGH
    line_number:  Optional[int]          = None
    context:      Optional[str]          = None
    tool:         str                    = "secretfinder"
    first_seen:   datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_new:       bool                   = True
    suppress_until: Optional[datetime]   = None
    crawl_run_id: Optional[str]          = None

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")

    @field_validator("secret_value", mode="before")
    @classmethod
    def truncate_value(cls, v: str) -> str:
        return v[:120] if v else v


class CrawledEndpoint(BaseModel):
    """
    A URL endpoint discovered by the crawler.
    Dedup key: sha256(domain + url_path)
    """
    tenant_id:    str     = "default"          # ← SaaS partition key

    endpoint_id:  str
    program_id:   str
    domain:       str
    url:          str
    url_path:     str
    method:       str                    = "GET"
    status_code:  Optional[int]          = None
    content_type: Optional[str]          = None
    source:       str                    = "katana"
    is_interesting: bool                 = False
    interest_tags:  List[str]            = Field(default_factory=list)
    first_seen:   datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_new:       bool                   = True
    crawl_run_id: Optional[str]          = None

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


class CrawlRun(BaseModel):
    """Audit record for a single crawl run."""
    run_id:          str      = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:      str
    started_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:     Optional[datetime] = None
    targets:         int      = 0
    endpoints_found: int      = 0
    new_endpoints:   int      = 0
    js_files:        int      = 0
    secrets_found:   int      = 0
    new_secrets:     int      = 0
    errors:          List[str] = Field(default_factory=list)
    success:         bool     = True


# ---------------------------------------------------------------------------
# Module 6: GitHub OSINT
# ---------------------------------------------------------------------------

class GitHubLeakSeverity(str, Enum):
    CRITICAL = "critical"   # Live credential (key validated or direct DB string)
    HIGH     = "high"       # High-confidence secret pattern (AWS key, GitHub token)
    MEDIUM   = "medium"     # Possible secret (generic password, config value)
    INFO     = "info"       # Interesting exposure (internal URL, company mention)


class GitHubLeak(BaseModel):
    """
    A single leaked secret or sensitive reference found on GitHub.
    Stored in the `github_leaks` collection.

    Dedup key: sha256(repo_full_name + file_path + match_type + match_value[:32])
    Same leak never alerts twice, even across re-runs.
    """
    tenant_id:      str     = "default"          # ← SaaS partition key

    leak_id:        str                          # sha256 dedup fingerprint
    program_id:     str
    domain:         str                          # target domain this was found for

    # GitHub location
    repo_full_name: str                          # "org/repo"
    repo_url:       str                          # https://github.com/org/repo
    file_path:      str                          # path/to/file.py
    file_url:       str                          # direct GitHub URL to file
    commit_sha:     Optional[str]  = None        # commit hash if available
    branch:         str            = "main"

    # Match details
    match_type:     str                          # "aws_key", "github_token", "password", etc.
    match_value:    str                          # truncated matched value (first 80 chars)
    match_context:  Optional[str]  = None        # surrounding line context
    line_number:    Optional[int]  = None
    dork_query:     str            = ""          # which search query found this

    # Triage
    severity:       GitHubLeakSeverity = GitHubLeakSeverity.HIGH
    is_new:         bool           = True
    suppress_until: Optional[datetime] = None
    is_verified:    bool           = False       # manually verified as live credential
    first_seen:     datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:      datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")

    @field_validator("match_value", mode="before")
    @classmethod
    def truncate_match(cls, v: str) -> str:
        return v[:80] if v else v


class GitHubOSINTRun(BaseModel):
    """Audit record for a GitHub OSINT run."""
    run_id:       str      = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:   str
    started_at:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:  Optional[datetime] = None
    queries_run:  int      = 0
    results_raw:  int      = 0        # total GitHub results before dedup
    new_leaks:    int      = 0        # net-new after dedup
    errors:       List[str] = Field(default_factory=list)
    success:      bool     = True


# ---------------------------------------------------------------------------
# Module 7: Port Scanner
# ---------------------------------------------------------------------------

class PortFindingSeverity(str, Enum):
    """
    Triage severity for an exposed service.
    CRITICAL → unauthenticated access to a dangerous service (Redis, MongoDB, ES)
    HIGH     → exposed admin UI or sensitive service
    MEDIUM   → unusual open port worth investigating
    INFO     → expected service (HTTP/HTTPS/SSH)
    """
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    INFO     = "info"


class PortFinding(BaseModel):
    """
    A single open port / service discovered by the port scanner.
    Stored in the `port_findings` collection.

    Dedup key: sha256(ip + port + protocol)
    Same port on same IP never alerts twice.
    """
    tenant_id:    str     = "default"

    finding_id:   str                          # sha256 dedup fingerprint
    program_id:   str
    domain:       str                          # asset domain this IP belongs to
    ip:           str                          # IP address scanned
    port:         int
    protocol:     str     = "tcp"              # tcp | udp
    service:      Optional[str]  = None        # service name (redis, mongodb, http…)
    product:      Optional[str]  = None        # product/version string from Nmap
    banner:       Optional[str]  = None        # raw service banner (first 500 chars)
    severity:     PortFindingSeverity = PortFindingSeverity.INFO
    reason:       str     = ""                 # why this severity was assigned
    is_new:       bool    = True
    suppress_until: Optional[datetime] = None
    scan_run_id:  Optional[str]  = None
    first_seen:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")

    @field_validator("ip", mode="before")
    @classmethod
    def strip_ip(cls, v: str) -> str:
        return v.strip()


class PortScanRun(BaseModel):
    """Audit record for a port scan run."""
    run_id:          str      = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:      str
    started_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:     Optional[datetime] = None
    targets:         int      = 0    # IP addresses scanned
    ports_found:     int      = 0    # total open ports
    new_findings:    int      = 0    # net-new after dedup
    errors:          List[str] = Field(default_factory=list)
    success:         bool     = True


# ---------------------------------------------------------------------------
# Module 8: Google Dork Engine
# ---------------------------------------------------------------------------

class DorkSeverity(str, Enum):
    """
    Triage severity for a Google dork result.
    CRITICAL → directly exposed secret or backup file
    HIGH     → admin panel, login, config file
    MEDIUM   → sensitive directory listing or error page
    INFO     → generic exposure worth investigating
    """
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    INFO     = "info"


class DorkResult(BaseModel):
    """
    A single result from a Google dork query.
    Stored in the `dork_results` collection.

    Dedup key: sha256(domain + dork_category + url[:80])
    Same URL from the same dork type never alerts twice.
    """
    tenant_id:    str     = "default"

    result_id:    str                          # sha256 dedup fingerprint
    program_id:   str
    domain:       str                          # root domain being dorked

    url:          str                          # discovered URL
    title:        Optional[str]  = None        # page title from search snippet
    snippet:      Optional[str]  = None        # search result snippet
    dork_query:   str            = ""          # exact query that found it
    dork_category: str           = ""          # category e.g. "exposed_files"
    severity:     DorkSeverity  = DorkSeverity.INFO
    reason:       str           = ""           # human readable reason

    is_new:       bool          = True
    suppress_until: Optional[datetime] = None
    scan_run_id:  Optional[str] = None
    first_seen:   datetime      = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime      = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")

    @field_validator("url", mode="before")
    @classmethod
    def truncate_url(cls, v: str) -> str:
        return v[:500] if v else v


class DorkScanRun(BaseModel):
    """Audit record for a dork scan run."""
    run_id:          str      = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:      str
    started_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:     Optional[datetime] = None
    queries_run:     int      = 0
    results_raw:     int      = 0    # total results before dedup
    new_findings:    int      = 0    # net-new after dedup
    errors:          List[str] = Field(default_factory=list)
    success:         bool     = True


# ---------------------------------------------------------------------------
# ASN Mapper (Module 9)
# ---------------------------------------------------------------------------

class ASNInfo(BaseModel):
    """
    A discovered ASN and its IP prefixes for a program.
    Stored in `asn_info` collection.

    Dedup key: (program_id, asn_number)
    """
    tenant_id:    str     = "default"

    asn_number:   int                          # e.g. 13335
    asn_name:     str                          # e.g. "CLOUDFLARENET"
    program_id:   str
    domain:       str                          # source domain that resolved to this ASN
    ip_prefixes:  List[str]                    # CIDR ranges, e.g. ["104.16.0.0/12"]
    ipv6_prefixes: List[str] = Field(default_factory=list)
    country_code: Optional[str] = None
    description:  Optional[str] = None

    first_seen:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


class ASNScanRun(BaseModel):
    """Audit record for an ASN mapping run."""
    run_id:          str      = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:      str
    started_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:     Optional[datetime] = None
    asns_found:      int      = 0
    prefixes_found:  int      = 0
    new_ips:         int      = 0
    errors:          List[str] = Field(default_factory=list)
    success:         bool     = True