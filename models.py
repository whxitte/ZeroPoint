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
# Enumerations
# ---------------------------------------------------------------------------

class ReconSource(str, Enum):
    """Every discovery tool must have a registered source entry."""
    SUBFINDER = "subfinder"
    CRTSH     = "crtsh"
    SHODAN    = "shodan"
    AMASS     = "amass"    # reserved
    CHAOS     = "chaos"    # reserved


class AssetStatus(str, Enum):
    """Lifecycle state of a discovered asset."""
    NEW    = "new"     # First time we have ever seen this domain
    ACTIVE = "active"  # Seen in previous runs and confirmed again
    STALE  = "stale"   # Not seen recently (future scan logic)


class ProbeStatus(str, Enum):
    """HTTP probing result for an asset — set by the Prober module."""
    NOT_PROBED = "not_probed"   # Never run through httpx
    ALIVE      = "alive"        # Returned a valid HTTP response
    DEAD       = "dead"         # No response / connection refused / NXDOMAIN
    ERROR      = "error"        # httpx crashed or timed out on this host


class InterestLevel(str, Enum):
    """
    Triage classification assigned by the Fingerprint engine.
    Drives alert priority and scanning depth.

    CRITICAL → Immediate manual review (admin panels, internal tools, CI/CD)
    HIGH     → Schedule targeted Nuclei scan within minutes
    MEDIUM   → Queue for standard Nuclei sweep
    LOW      → Log and move on
    NOISE    → CDN default pages, parking pages, dead ends
    """
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
    """
    Nuclei finding severity levels — mirrors Nuclei's own severity enum.
    Used for deduplication fingerprinting and alert routing.
    """
    CRITICAL  = "critical"
    HIGH      = "high"
    MEDIUM    = "medium"
    LOW       = "low"
    INFO      = "info"
    UNKNOWN   = "unknown"


class ScanStatus(str, Enum):
    """Scan lifecycle state for an asset in the scanner queue."""
    QUEUED    = "queued"     # Waiting to be scanned
    SCANNING  = "scanning"   # Currently being scanned
    DONE      = "done"       # Scan completed (with or without findings)
    ERROR     = "error"      # Scanner crashed on this asset
    SKIPPED   = "skipped"    # Skipped (e.g. dead host at scan time)


# ---------------------------------------------------------------------------
# Program  —  top-level entity; one entry per bug bounty program
# ---------------------------------------------------------------------------

class Program(BaseModel):
    """Represents a bug bounty program we are monitoring."""

    program_id: str                                  # "hackerone_google"
    name:       str                                  # "Google VRP"
    platform:   ProgramPlatform
    domains:    List[str]                            # Root in-scope domains
    wildcards:  List[str] = Field(default_factory=list)  # "*.example.com"
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
    `first_seen` is set-on-insert and NEVER overwritten.
    `last_seen` is updated on every pipeline run.
    `is_new` = True only when the document is freshly inserted.

    Probe fields (populated by Module 2 — Prober):
      probe_status, http_status, http_title, technologies,
      web_server, content_type, cdn_provider, redirect_url,
      favicon_hash, body_preview, interest_level, last_probed
    """

    domain:      str
    program_id:  str
    sources:     List[ReconSource] = Field(default_factory=list)
    ip_addresses: List[str]        = Field(default_factory=list)
    status:      AssetStatus       = AssetStatus.NEW
    is_new:      bool              = True
    first_seen:  datetime          = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:   datetime          = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Module 2: HTTP Probe fields (set by Prober) ─────────────────────
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

    # ── Module 2: Triage classification (set by Fingerprint engine) ─────
    interest_level:  InterestLevel  = InterestLevel.LOW
    interest_reasons: List[str]     = Field(
        default_factory=list,
        description="Human-readable reasons for the interest level, e.g. ['jenkins detected', 'no auth']"
    )

    # ── Module 3+ reserved fields ───────────────────────────────────────
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
    """Lightweight carrier returned by every recon module."""
    source:   ReconSource
    domains:  List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)  # {domain: {ip: ...}}
    errors:   List[str]      = Field(default_factory=list)


class UpsertResult(BaseModel):
    """What the DB layer reports back after a single upsert."""
    domain:     str
    program_id: str
    is_new:     bool
    source:     ReconSource


class ProbeResult(BaseModel):
    """
    Structured output from a single httpx probe hit.
    Parsed from httpx's JSON line output and passed to the DB update layer.
    One ProbeResult maps 1:1 to one asset document update.
    """
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

    # Set by fingerprint engine after parsing
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

    Deduplication key: sha256(template_id + domain + matched_at)
    This ensures the same vuln on the same endpoint is never double-alerted,
    even across multiple scan runs (idempotency guarantee).
    """
    # Identity
    finding_id:   str                       # sha256 dedup fingerprint
    program_id:   str
    domain:       str

    # Nuclei output fields
    template_id:  str                        # e.g. "CVE-2021-44228"
    template_name: str                       # Human-readable name
    severity:     ScanSeverity
    matched_at:   str                        # URL/endpoint where the vuln was confirmed
    matcher_name: Optional[str]  = None      # Which matcher fired (e.g. "status-200")
    description:  Optional[str]  = None
    reference:    List[str]      = Field(default_factory=list)  # CVE links etc.
    tags:         List[str]      = Field(default_factory=list)
    curl_command: Optional[str]  = None      # Nuclei's -include-rr curl reproduction
    request:      Optional[str]  = None      # Raw HTTP request
    response:     Optional[str]  = None      # Truncated raw HTTP response
    extracted_results: List[str] = Field(default_factory=list)

    # Pipeline metadata
    first_seen:   datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_new:       bool           = True      # False after first alert sent
    scan_run_id:  Optional[str]  = None      # Links to ScanRun audit record

    # Confidence flag — True when nuclei had a response-body/status matcher that
    # confirmed the finding, False means URL-pattern match only (review before reporting)
    confirmed:    bool           = True
    extra:        Dict[str, Any] = Field(default_factory=dict)

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


class ScanRun(BaseModel):
    """Audit record for a single scanner run — stored in `scan_runs` collection."""
    run_id:       str            = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:   str
    started_at:   datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:  Optional[datetime] = None
    targets:      int            = 0         # Total assets submitted
    findings:     int            = 0         # Total Nuclei hits
    new_findings: int            = 0         # Net-new after dedup
    templates_used: List[str]    = Field(default_factory=list)
    errors:       List[str]      = Field(default_factory=list)
    success:      bool           = True


# ---------------------------------------------------------------------------
# Module 4: Crawler & JS Analysis models
# ---------------------------------------------------------------------------

class SecretSeverity(str, Enum):
    """
    Triage severity for a discovered secret/sensitive value.
    CRITICAL → live credential (API key with working auth, private key)
    HIGH     → likely valid secret (pattern match + entropy threshold)
    MEDIUM   → possible secret (pattern match, lower entropy)
    INFO     → interesting string worth manual review
    """
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    INFO     = "info"


class CrawlSecret(BaseModel):
    """
    A single secret / sensitive value found in JS or page source.
    Stored in the `secrets` collection.

    Dedup key: sha256(secret_type + domain + secret_value[:32])
    Same secret type on same domain never alerts twice.
    """
    secret_id:    str                    # sha256 dedup fingerprint
    program_id:   str
    domain:       str
    source_url:   str                    # JS file or page URL where found
    secret_type:  str                    # "aws_access_key", "github_token", etc.
    secret_value: str                    # The actual matched value (truncated to 120 chars)
    severity:     SecretSeverity         = SecretSeverity.HIGH
    line_number:  Optional[int]          = None
    context:      Optional[str]          = None   # Surrounding code context (±1 line)
    tool:         str                    = "secretfinder"  # "secretfinder" | "trufflehog" | "regex"
    first_seen:   datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_new:       bool                   = True
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
    Stored in the `endpoints` collection.

    Interesting endpoints (login, upload, admin, API) feed directly
    into Module 3 as additional scanner targets.

    Dedup key: sha256(domain + url_path)
    """
    endpoint_id:  str                    # sha256 dedup fingerprint
    program_id:   str
    domain:       str
    url:          str                    # Full URL
    url_path:     str                    # Path only for dedup (strips params)
    method:       str                    = "GET"
    status_code:  Optional[int]          = None
    content_type: Optional[str]          = None
    source:       str                    = "katana"   # "katana" | "waybackurls" | "gau"
    is_interesting: bool                 = False      # Set by endpoint classifier
    interest_tags:  List[str]            = Field(default_factory=list)   # ["login","api","upload"]
    first_seen:   datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:    datetime               = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_new:       bool                   = True
    crawl_run_id: Optional[str]          = None

    @field_validator("domain", mode="before")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        return v.lower().strip().rstrip(".")


class CrawlRun(BaseModel):
    """Audit record for a single crawl run — stored in `crawl_runs` collection."""
    run_id:          str      = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    program_id:      str
    started_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:     Optional[datetime] = None
    targets:         int      = 0    # Assets crawled
    endpoints_found: int      = 0    # Total unique URLs discovered
    new_endpoints:   int      = 0    # Net-new endpoints
    js_files:        int      = 0    # JS files analysed
    secrets_found:   int      = 0    # Total secret matches
    new_secrets:     int      = 0    # Net-new secrets
    errors:          List[str] = Field(default_factory=list)
    success:         bool     = True