"""
ZeroPoint :: db/crawler_ops.py
================================
MongoDB operations for Module 4 — Crawler & JS Analysis.

Collections managed:
  endpoints   — every unique URL discovered by the crawler
  secrets     — every secret/sensitive value found in JS/pages
  crawl_runs  — audit log of every crawl run
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import urlparse

from loguru import logger
from pymongo import ASCENDING, IndexModel
from pymongo.errors import PyMongoError

from db.mongo import get_assets_col, get_db
from models import Asset, CrawlRun, CrawledEndpoint, CrawlSecret, ProbeStatus


# ─────────────────────────────────────────────────────────────────────────────
# Collection accessors
# ─────────────────────────────────────────────────────────────────────────────

def get_endpoints_col():
    return get_db()["endpoints"]


def get_secrets_col():
    return get_db()["secrets"]


def get_crawl_runs_col():
    return get_db()["crawl_runs"]


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_endpoint_id(domain: str, url: str) -> str:
    """SHA-256 of domain + normalised URL path (strips query params for dedup)."""
    parsed   = urlparse(url.lower())
    path_key = f"{domain.lower()}|{parsed.netloc}{parsed.path}"
    return hashlib.sha256(path_key.encode()).hexdigest()


def make_secret_id(secret_type: str, domain: str, value: str) -> str:
    """SHA-256 of secret_type + domain + first 32 chars of value."""
    raw = f"{secret_type.lower()}|{domain.lower()}|{value[:32].lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Index bootstrap
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_crawler_indexes() -> None:
    """Create crawler collection indexes — idempotent, call once at startup."""
    endpoints_col  = get_endpoints_col()
    secrets_col    = get_secrets_col()
    crawl_runs_col = get_crawl_runs_col()

    await endpoints_col.create_indexes([
        IndexModel([("endpoint_id",  ASCENDING)], unique=True, name="endpoint_id_unique"),
        IndexModel([("program_id",   ASCENDING)], name="ep_program_id"),
        IndexModel([("domain",       ASCENDING)], name="ep_domain"),
        IndexModel([("is_new",       ASCENDING)], name="ep_is_new"),
        IndexModel([("is_interesting", ASCENDING)], name="ep_interesting"),
        IndexModel([("first_seen",   ASCENDING)], name="ep_first_seen"),
    ])

    await secrets_col.create_indexes([
        IndexModel([("secret_id",    ASCENDING)], unique=True, name="secret_id_unique"),
        IndexModel([("program_id",   ASCENDING)], name="sec_program_id"),
        IndexModel([("domain",       ASCENDING)], name="sec_domain"),
        IndexModel([("secret_type",  ASCENDING)], name="sec_type"),
        IndexModel([("severity",     ASCENDING)], name="sec_severity"),
        IndexModel([("is_new",       ASCENDING)], name="sec_is_new"),
        IndexModel([("first_seen",   ASCENDING)], name="sec_first_seen"),
    ])

    await crawl_runs_col.create_indexes([
        IndexModel([("run_id",       ASCENDING)], unique=True, name="cr_run_id_unique"),
        IndexModel([("program_id",   ASCENDING)], name="cr_program_id"),
        IndexModel([("started_at",   ASCENDING)], name="cr_started_at"),
    ])

    logger.debug("Crawler indexes verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Asset queries — which assets to crawl
# ─────────────────────────────────────────────────────────────────────────────

async def get_assets_to_crawl(
    program_id:         str,
    min_interest:       str = "medium",
    recrawl_after_hours: int = 48,
    limit:              int = 500,
) -> List[Asset]:
    """
    Return assets qualifying for a crawl run.

    Criteria:
      1. probe_status = alive
      2. interest_level >= min_interest
      3. last_crawled is None OR < (now - recrawl_after_hours)
    """
    level_order   = ["noise", "low", "medium", "high", "critical"]
    min_idx       = level_order.index(min_interest.lower())
    eligible_lvls = level_order[min_idx:]
    cutoff        = datetime.now(timezone.utc) - timedelta(hours=recrawl_after_hours)

    col   = get_assets_col()
    query = {
        "program_id":     program_id,
        "probe_status":   ProbeStatus.ALIVE.value,
        "interest_level": {"$in": eligible_lvls},
        "$or": [
            {"last_crawled": {"$exists": False}},
            {"last_crawled": None},
            {"last_crawled": {"$lt": cutoff}},
        ],
    }

    # CRITICAL/HIGH first — crawl most valuable assets earliest
    level_sort = {"critical": 0, "high": 1, "medium": 2, "low": 3, "noise": 4}
    assets: List[Asset] = []
    cursor = col.find(query).limit(limit)
    async for doc in cursor:
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed asset skipped in crawler query: {exc}")

    assets.sort(key=lambda a: level_sort.get(a.interest_level, 99))
    logger.info(
        f"[crawler] {len(assets)} asset(s) queued | "
        f"program={program_id} | min_interest={min_interest}"
    )
    return assets


async def mark_asset_crawled(domain: str, crawl_run_id: str) -> None:
    """Stamp asset with last_crawled timestamp after crawl completes."""
    col = get_assets_col()
    await col.update_one(
        {"domain": domain},
        {"$set": {
            "last_crawled":     datetime.now(timezone.utc),
            "last_crawl_run_id": crawl_run_id,
        }},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint operations
# ─────────────────────────────────────────────────────────────────────────────

async def upsert_endpoint(endpoint: CrawledEndpoint) -> bool:
    """
    Insert or update an endpoint document.

    Returns True  → brand-new endpoint (never seen before)
    Returns False → endpoint already existed
    """
    col = get_endpoints_col()
    now = datetime.now(timezone.utc)

    try:
        result = await col.update_one(
            {"endpoint_id": endpoint.endpoint_id},
            {
                "$set": {
                    "last_seen":    now,
                    "crawl_run_id": endpoint.crawl_run_id,
                },
                "$setOnInsert": {
                    **endpoint.model_dump(exclude={"last_seen", "crawl_run_id"}),
                    "first_seen": now,
                    "is_new":     True,
                },
            },
            upsert=True,
        )
        return result.upserted_id is not None

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for endpoint {endpoint.url}: {exc}")
        raise


async def bulk_upsert_endpoints(
    endpoints: List[CrawledEndpoint],
) -> tuple[int, int]:
    """
    Upsert a list of endpoints concurrently.
    Returns (new_count, updated_count).
    """
    import asyncio

    results = await asyncio.gather(
        *[upsert_endpoint(e) for e in endpoints],
        return_exceptions=True,
    )
    new = sum(1 for r in results if r is True)
    errs = sum(1 for r in results if isinstance(r, Exception))
    if errs:
        logger.warning(f"[crawler] {errs} endpoint upsert error(s)")
    return new, len(endpoints) - new - errs


async def mark_endpoints_notified(endpoint_ids: List[str]) -> None:
    """Flip is_new=False after alerts sent."""
    if not endpoint_ids:
        return
    col = get_endpoints_col()
    await col.update_many(
        {"endpoint_id": {"$in": endpoint_ids}},
        {"$set": {"is_new": False}},
    )


async def get_interesting_endpoints(program_id: str) -> List[CrawledEndpoint]:
    """Return all is_interesting=True endpoints for a program (for reporting)."""
    col       = get_endpoints_col()
    endpoints = []
    async for doc in col.find({"program_id": program_id, "is_interesting": True}):
        doc.pop("_id", None)
        try:
            endpoints.append(CrawledEndpoint(**doc))
        except Exception as exc:
            logger.warning(f"Malformed endpoint doc: {exc}")
    return endpoints


# ─────────────────────────────────────────────────────────────────────────────
# Secret operations
# ─────────────────────────────────────────────────────────────────────────────

async def upsert_secret(secret: CrawlSecret) -> bool:
    """
    Insert or update a secret document.

    Returns True  → brand-new secret (never seen before) → alert should fire
    Returns False → already known → suppress alert
    """
    col = get_secrets_col()
    now = datetime.now(timezone.utc)

    try:
        result = await col.update_one(
            {"secret_id": secret.secret_id},
            {
                "$set": {
                    "last_seen":    now,
                    "crawl_run_id": secret.crawl_run_id,
                },
                "$setOnInsert": {
                    **secret.model_dump(exclude={"last_seen", "crawl_run_id"}),
                    "first_seen": now,
                    "is_new":     True,
                },
            },
            upsert=True,
        )
        is_new = result.upserted_id is not None
        logger.log(
            "SUCCESS" if is_new else "DEBUG",
            f"[crawler] {'NEW' if is_new else 'DUPE'} secret | "
            f"{secret.severity.upper()} | {secret.secret_type} | {secret.domain}",
        )
        return is_new

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for secret {secret.secret_id}: {exc}")
        raise


async def mark_secrets_notified(secret_ids: List[str]) -> None:
    """Flip is_new=False after alerts have been dispatched."""
    if not secret_ids:
        return
    col = get_secrets_col()
    await col.update_many(
        {"secret_id": {"$in": secret_ids}},
        {"$set": {"is_new": False}},
    )
    logger.debug(f"[crawler] Marked {len(secret_ids)} secret(s) notified")


async def get_secret_stats(program_id: str) -> dict:
    """Aggregate secret counts by severity for reporting."""
    col      = get_secrets_col()
    pipeline = [
        {"$match": {"program_id": program_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    stats: dict = {}
    async for doc in col.aggregate(pipeline):
        stats[doc["_id"] or "unknown"] = doc["count"]
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Crawl run audit
# ─────────────────────────────────────────────────────────────────────────────

async def save_crawl_run(run: CrawlRun) -> None:
    col = get_crawl_runs_col()
    await col.update_one(
        {"run_id": run.run_id},
        {"$set": run.model_dump()},
        upsert=True,
    )
    logger.debug(f"[crawler] CrawlRun saved | run_id={run.run_id}")