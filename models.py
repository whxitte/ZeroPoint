"""
ZeroPoint :: models.py
======================
Canonical Pydantic schemas for the entire pipeline.
Every byte of data entering or leaving ZeroPoint is validated here.
"""

from __future__ import annotations

from datetime import datetime
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
    UNKNOWN   = "unknown"


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
    created_at: datetime  = Field(default_factory=datetime.utcnow)
    updated_at: datetime  = Field(default_factory=datetime.utcnow)

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
    first_seen:  datetime          = Field(default_factory=datetime.utcnow)
    last_seen:   datetime          = Field(default_factory=datetime.utcnow)

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
