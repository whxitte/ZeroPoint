"""
ZeroPoint :: db/mongo.py
========================
All MongoDB interactions via Motor (async driver).

Design contract:
  - Every public function is async.
  - This module is the ONLY place that speaks to MongoDB.
  - All upsert logic lives here; callers never build raw update documents.
  - Returns typed Pydantic models or primitives — never raw dicts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

import motor.motor_asyncio
from loguru import logger
from pymongo import ASCENDING, IndexModel
from pymongo.errors import PyMongoError

from config import settings
from models import (
    Asset, AssetStatus, Finding, Program,
    ProbeResult, ProbeStatus, ReconSource,
    ScanRun, ScanSeverity, UpsertResult,
)


# ---------------------------------------------------------------------------
# Client & collection accessors
# ---------------------------------------------------------------------------

_client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None


def _get_client() -> motor.motor_asyncio.AsyncIOMotorClient:
    """Lazy-initialise and return the shared Motor client (connection pool)."""
    global _client
    if _client is None:
        _client = motor.motor_asyncio.AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=10_000,
            connectTimeoutMS=10_000,
            socketTimeoutMS=120_000,   # 2 min — large collection queries on Atlas M0 can take >30s
        )
        logger.debug("Motor client initialised.")
    return _client


def get_db() -> motor.motor_asyncio.AsyncIOMotorDatabase:
    return _get_client()[settings.MONGODB_DB]


def get_assets_col() -> motor.motor_asyncio.AsyncIOMotorCollection:
    return get_db()[settings.MONGO_ASSETS_COLLECTION]


def get_programs_col() -> motor.motor_asyncio.AsyncIOMotorCollection:
    return get_db()[settings.MONGO_PROGRAMS_COLLECTION]


# ---------------------------------------------------------------------------
# Index bootstrap  —  call once at startup
# ---------------------------------------------------------------------------

async def ensure_indexes() -> None:
    """
    Idempotently create all required indexes.
    Safe to call on every startup — MongoDB no-ops if indexes already exist.
    """
    assets_col = get_assets_col()
    programs_col = get_programs_col()

    try:
        # Assets: unique on domain (our natural PK)
        await assets_col.create_indexes([
            IndexModel([("domain", ASCENDING)], unique=True, name="domain_unique"),
            IndexModel([("program_id", ASCENDING)],            name="program_id"),
            IndexModel([("is_new", ASCENDING)],                name="is_new"),
            IndexModel([("first_seen", ASCENDING)],            name="first_seen"),
            IndexModel([("last_seen", ASCENDING)],             name="last_seen"),
            IndexModel([("status", ASCENDING)],                name="status"),
            # tenant_id indexes — needed for every API query that filters by tenant
            IndexModel([("tenant_id", ASCENDING)],             name="asset_tenant_id"),
            IndexModel([("tenant_id", ASCENDING), ("program_id", ASCENDING)],
                       name="asset_tenant_program"),
        ])

        # Programs: unique on program_id
        await programs_col.create_indexes([
            IndexModel([("program_id", ASCENDING)], unique=True, name="program_id_unique"),
            IndexModel([("tenant_id", ASCENDING)],             name="program_tenant_id"),
        ])

        # Findings collection
        findings_col = get_db()["findings"]
        await findings_col.create_indexes([
            IndexModel([("finding_id", ASCENDING)],  unique=True, name="finding_id_unique"),
            IndexModel([("program_id", ASCENDING)],  name="findings_program_id"),
            IndexModel([("domain",     ASCENDING)],  name="findings_domain"),
            IndexModel([("severity",   ASCENDING)],  name="findings_severity"),
            IndexModel([("is_new",     ASCENDING)],  name="findings_is_new"),
            IndexModel([("template_id",ASCENDING)],  name="findings_template_id"),
            IndexModel([("first_seen", ASCENDING)],  name="findings_first_seen"),
            IndexModel([("tenant_id",  ASCENDING)],  name="finding_tenant_id"),
            IndexModel([("tenant_id", ASCENDING), ("program_id", ASCENDING)],
                       name="finding_tenant_program"),
            # Compound index for report queries: covers program_id filter + severity+first_seen sort
            IndexModel([("program_id", ASCENDING), ("severity", ASCENDING), ("first_seen", ASCENDING)],
                       name="findings_report_query"),
        ])

        # Scan runs collection
        scan_runs_col = get_db()["scan_runs"]
        await scan_runs_col.create_indexes([
            IndexModel([("run_id",     ASCENDING)],  unique=True, name="run_id_unique"),
            IndexModel([("program_id", ASCENDING)],  name="scan_runs_program_id"),
            IndexModel([("started_at", ASCENDING)],  name="scan_runs_started_at"),
        ])

        logger.info("MongoDB indexes verified / created.")

    except PyMongoError as exc:
        logger.error(f"Failed to ensure indexes: {exc}")
        raise


# ---------------------------------------------------------------------------
# Program CRUD
# ---------------------------------------------------------------------------

async def upsert_program(program: Program) -> None:
    """Insert or update a Program document."""
    col = get_programs_col()
    now = datetime.now(timezone.utc)

    await col.update_one(
        {"program_id": program.program_id, "tenant_id": program.tenant_id},  # tenant-scoped key
        {
            "$set": {
                **program.model_dump(exclude={"created_at"}),
                "updated_at": now,
            },
            "$setOnInsert": {"created_at": now},
        },
        upsert=True,
    )
    logger.debug(f"Program upserted: {program.program_id}")


async def get_program(program_id: str) -> Optional[Program]:
    """Fetch a single Program by its ID."""
    col = get_programs_col()
    doc = await col.find_one({"program_id": program_id})
    if doc:
        doc.pop("_id", None)
        return Program(**doc)
    return None


async def list_active_programs() -> List[Program]:
    """Return all programs with is_active=True."""
    col = get_programs_col()
    programs: List[Program] = []
    async for doc in col.find({"is_active": True}):
        doc.pop("_id", None)
        try:
            programs.append(Program(**doc))
        except Exception as exc:
            logger.warning(f"Skipping malformed program doc: {exc}")
    return programs


# ---------------------------------------------------------------------------
# Asset upsert  —  THE core state-tracking logic
# ---------------------------------------------------------------------------

async def upsert_asset(
    domain: str,
    program_id: str,
    source: ReconSource,
    ip_addresses: Optional[List[str]] = None,
) -> UpsertResult:
    """
    Upsert a single asset with full state-tracking semantics.

    Logic:
      - If domain does NOT exist  → insert with is_new=True, status=new
      - If domain DOES exist      → update last_seen, add source, set is_new=False, status=active

    Returns UpsertResult indicating whether this was a net-new asset.
    """
    col = get_assets_col()
    now = datetime.now(timezone.utc)
    ip_addresses = ip_addresses or []

    filter_doc = {"domain": domain}

    update_doc = {
        # Always update on every run:
        "$set": {
            "last_seen":  now,
            "status":     AssetStatus.ACTIVE.value,
            # is_new is intentionally NOT here — it must only appear in
            # $setOnInsert. Having it in both $set and $setOnInsert causes
            # MongoDB error code 40 (path conflict) on upsert.
            # Existing docs keep their is_new value; new inserts get True
            # from $setOnInsert below.
            "program_id": program_id,
        },
        # Add source to set (no duplicates):
        "$addToSet": {
            "sources": source.value,
        },
        # Only set these fields on the very first insertion:
        "$setOnInsert": {
            "domain":       domain,
            "first_seen":   now,
            "is_new":       True,   # Stays True only for brand-new inserts
            # status is intentionally NOT here — it lives only in $set above.
            # Having the same field in both $set and $setOnInsert causes
            # MongoDB error code 40 (path conflict). is_new=True is the real
            # newness indicator; status=ACTIVE from $set is correct for all docs.
            "http_status":  None,
            "http_title":   None,
            "technologies": [],
            "open_ports":   [],
            "extra":        {},
        },
    }

    # Only add IPs if we actually have some (avoid nuking existing data)
    if ip_addresses:
        update_doc["$addToSet"]["ip_addresses"] = {"$each": ip_addresses}

    try:
        result = await col.update_one(filter_doc, update_doc, upsert=True)
        is_new = result.upserted_id is not None  # True only on actual insert

        log_level = "SUCCESS" if is_new else "DEBUG"
        logger.log(
            log_level,
            f"[{source.value.upper()}] {'NEW' if is_new else 'SEEN'} | "
            f"{domain} | program={program_id}",
        )

        return UpsertResult(
            domain=domain,
            program_id=program_id,
            is_new=is_new,
            source=source,
        )

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for {domain}: {exc}")
        raise


async def bulk_upsert_assets(
    domains: List[str],
    program_id: str,
    source: ReconSource,
) -> List[UpsertResult]:
    """
    Upsert a list of domains concurrently using asyncio.gather.
    Returns a list of UpsertResult for each domain.
    """
    import asyncio

    tasks = [
        upsert_asset(domain=d, program_id=program_id, source=source)
        for d in domains
        if d.strip()
    ]

    results: List[UpsertResult] = []
    raw = await asyncio.gather(*tasks, return_exceptions=True)

    for item in raw:
        if isinstance(item, Exception):
            logger.error(f"Bulk upsert task failed: {item}")
        else:
            results.append(item)  # type: ignore[arg-type]

    return results


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

async def get_new_assets_since(
    program_id: str,
    since: datetime,
) -> List[Asset]:
    """Fetch all assets marked as new for a program after a given timestamp."""
    col = get_assets_col()
    assets: List[Asset] = []
    query = {
        "program_id": program_id,
        "is_new": True,
        "first_seen": {"$gte": since},
    }
    async for doc in col.find(query):
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed asset doc skipped: {exc}")
    return assets


async def count_assets_for_program(program_id: str) -> int:
    col = get_assets_col()
    return await col.count_documents({"program_id": program_id})


async def close_connection() -> None:
    """Gracefully close the Motor client connection pool."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
        logger.info("MongoDB connection closed.")


# ---------------------------------------------------------------------------
# Module 2: Prober query & update operations
# ---------------------------------------------------------------------------

async def get_assets_to_probe(
    program_id: str,
    limit: int = 500,
    reprobe_after_hours: int = 24,
    force_reprobe: bool = False,
) -> List[Asset]:
    """
    Return assets that need an HTTP probe.

    Selection criteria (OR logic):
      1. Never probed:  probe_status = "not_probed"
      2. Stale probe:   last_probed < (now - reprobe_after_hours)
      3. Force flag:    force_reprobe=True — pull ALL assets for this program

    Ordered by: newest first_seen first (prioritise fresh discoveries).
    """
    col = get_assets_col()
    now = datetime.now(timezone.utc)
    cutoff = datetime(
        now.year, now.month, now.day,
        now.hour - reprobe_after_hours % 24,
        now.minute,
        now.second,
    )
    # Simpler: import timedelta
    from datetime import timedelta
    cutoff = now - timedelta(hours=reprobe_after_hours)

    if force_reprobe:
        query: dict = {"program_id": program_id}
    else:
        query = {
            "program_id": program_id,
            "$or": [
                {"probe_status": {"$in": [ProbeStatus.NOT_PROBED.value, None]}},
                {"probe_status": ProbeStatus.ERROR.value},           # retry errored
                {"last_probed": {"$lt": cutoff}},                    # stale probe
            ],
        }

    assets: List[Asset] = []
    cursor = col.find(query).sort("first_seen", -1).limit(limit)

    async for doc in cursor:
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed asset skipped during probe fetch: {exc}")

    logger.info(
        f"Found {len(assets)} asset(s) to probe for program={program_id} "
        f"(force={force_reprobe})"
    )
    return assets


async def update_probe_result(result: ProbeResult) -> None:
    """
    Write httpx probe results back to the asset document.
    Only updates probe-related fields — never touches first_seen or is_new.
    """
    col = get_assets_col()
    now = datetime.now(timezone.utc)

    set_fields: dict = {
        "probe_status":      result.probe_status.value,
        "last_probed":       now,
        "interest_level":    result.interest_level.value,
        "interest_reasons":  result.interest_reasons,
    }

    # Only overwrite these if the probe actually returned data
    if result.probe_status == ProbeStatus.ALIVE:
        if result.http_status is not None:
            set_fields["http_status"]      = result.http_status
        if result.http_title is not None:
            set_fields["http_title"]       = result.http_title
        if result.web_server is not None:
            set_fields["web_server"]       = result.web_server
        if result.content_type is not None:
            set_fields["content_type"]     = result.content_type
        if result.cdn_provider is not None:
            set_fields["cdn_provider"]     = result.cdn_provider
        if result.redirect_url is not None:
            set_fields["redirect_url"]     = result.redirect_url
        if result.favicon_hash is not None:
            set_fields["favicon_hash"]     = result.favicon_hash
        if result.body_preview is not None:
            set_fields["body_preview"]     = result.body_preview
        if result.content_length is not None:
            set_fields["content_length"]   = result.content_length
        if result.response_time_ms is not None:
            set_fields["response_time_ms"] = result.response_time_ms

    update_doc: dict = {"$set": set_fields}

    if result.technologies:
        update_doc["$addToSet"] = {"technologies": {"$each": result.technologies}}
    if result.ip_addresses:
        update_doc.setdefault("$addToSet", {})
        update_doc["$addToSet"]["ip_addresses"] = {"$each": result.ip_addresses}

    try:
        await col.update_one({"domain": result.domain}, update_doc)
        logger.debug(
            f"[probe] Updated {result.domain} | "
            f"status={result.http_status} | "
            f"interest={result.interest_level.value} | "
            f"tech={result.technologies}"
        )
    except PyMongoError as exc:
        logger.error(f"Failed to write probe result for {result.domain}: {exc}")
        raise


async def get_high_value_assets(
    program_id: str,
    min_level: str = "high",
) -> List[Asset]:
    """
    Fetch assets classified as HIGH or CRITICAL interest for a program.
    Used to feed the vulnerability scanner (Module 3).
    """
    level_order = ["noise", "low", "medium", "high", "critical"]
    min_idx = level_order.index(min_level.lower())
    eligible_levels = level_order[min_idx:]

    col = get_assets_col()
    assets: List[Asset] = []
    query = {
        "program_id":    program_id,
        "probe_status":  ProbeStatus.ALIVE.value,
        "interest_level": {"$in": eligible_levels},
    }
    async for doc in col.find(query).sort("interest_level", -1):
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed high-value asset skipped: {exc}")

    logger.info(
        f"High-value assets for program={program_id}: {len(assets)} "
        f"(min_level={min_level})"
    )
    return assets


async def get_probe_stats(program_id: str) -> dict:
    """
    Return a summary dict of probe status counts for a program.
    Useful for dashboards and progress logging.
    """
    col = get_assets_col()
    pipeline = [
        {"$match": {"program_id": program_id}},
        {"$group": {
            "_id": "$probe_status",
            "count": {"$sum": 1},
        }},
    ]
    stats: dict = {}
    async for doc in col.aggregate(pipeline):
        stats[doc["_id"] or "not_probed"] = doc["count"]
    return stats