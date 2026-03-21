"""
ZeroPoint :: db/dork_ops.py
============================
MongoDB operations for Module 8 — Google Dork Engine.

Collections managed:
  dork_results  — every unique URL/page discovered via dorking
  dork_runs     — audit log of every dork scan run
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List

from loguru import logger
from pymongo import ASCENDING, IndexModel
from pymongo.errors import PyMongoError

from db.mongo import get_db
from models import DorkResult, DorkScanRun


# ─────────────────────────────────────────────────────────────────────────────
# Collection accessors
# ─────────────────────────────────────────────────────────────────────────────

def get_results_col():
    return get_db()["dork_results"]


def get_runs_col():
    return get_db()["dork_runs"]


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────

def make_dork_result_id(domain: str, dork_category: str, url: str) -> str:
    """SHA-256 fingerprint — same URL from same dork type never alerts twice."""
    raw = f"{domain.lower()}|{dork_category.lower()}|{url[:80].lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Index bootstrap
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_dork_indexes() -> None:
    """Create dork engine indexes — idempotent, call once at startup."""
    results_col = get_results_col()
    runs_col    = get_runs_col()

    await results_col.create_indexes([
        IndexModel([("result_id",     ASCENDING)], unique=True, name="dr_result_id"),
        IndexModel([("tenant_id",     ASCENDING)],              name="dr_tenant"),
        IndexModel([("program_id",    ASCENDING)],              name="dr_program"),
        IndexModel([("domain",        ASCENDING)],              name="dr_domain"),
        IndexModel([("severity",      ASCENDING)],              name="dr_severity"),
        IndexModel([("dork_category", ASCENDING)],              name="dr_category"),
        IndexModel([("is_new",        ASCENDING)],              name="dr_is_new"),
        IndexModel([("first_seen",    ASCENDING)],              name="dr_first_seen"),
        IndexModel([("tenant_id", ASCENDING), ("program_id", ASCENDING)],
                   name="dr_tenant_program"),
    ])

    await runs_col.create_indexes([
        IndexModel([("run_id",     ASCENDING)], unique=True, name="drr_run_id"),
        IndexModel([("program_id", ASCENDING)],              name="drr_program"),
        IndexModel([("started_at", ASCENDING)],              name="drr_started"),
    ])

    logger.debug("Dork engine indexes verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Upsert
# ─────────────────────────────────────────────────────────────────────────────

async def upsert_dork_result(result: DorkResult) -> bool:
    """
    Insert or update a DorkResult document.

    Returns True  → brand-new result → alert should fire
    Returns False → already known → suppress alert
    """
    col = get_results_col()
    now = datetime.now(timezone.utc)

    insert_fields = result.model_dump(exclude={"last_seen", "is_new"})

    try:
        res = await col.update_one(
            {"result_id": result.result_id},
            {
                "$set": {"last_seen": now},
                "$setOnInsert": {
                    **insert_fields,
                    "first_seen": now,
                    "is_new":     True,
                },
            },
            upsert=True,
        )
        is_new = res.upserted_id is not None
        logger.log(
            "SUCCESS" if is_new else "DEBUG",
            f"[dork] {'NEW' if is_new else 'DUPE'} | "
            f"{result.severity.upper()} | {result.dork_category} | {result.url[:80]}",
        )
        return is_new

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for dork result {result.result_id}: {exc}")
        raise


async def mark_results_notified(result_ids: List[str], suppress_days: int = 7) -> None:
    """Flip is_new=False and set suppress_until after alerts dispatched."""
    if not result_ids:
        return
    from datetime import timedelta
    col         = get_results_col()
    suppress_ts = datetime.now(timezone.utc) + timedelta(days=suppress_days)
    await col.update_many(
        {"result_id": {"$in": result_ids}},
        {"$set": {"is_new": False, "suppress_until": suppress_ts}},
    )
    logger.debug(f"[dork] Marked {len(result_ids)} item(s) notified | suppress_until={suppress_ts.date()}")


async def get_dork_stats(program_id: str) -> dict:
    """Aggregate result counts by severity."""
    col      = get_results_col()
    pipeline = [
        {"$match": {"program_id": program_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    stats: dict = {}
    async for doc in col.aggregate(pipeline):
        stats[doc["_id"] or "unknown"] = doc["count"]
    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Run audit
# ─────────────────────────────────────────────────────────────────────────────

async def save_dork_run(run: DorkScanRun) -> None:
    col = get_runs_col()
    await col.update_one(
        {"run_id": run.run_id},
        {"$set": run.model_dump()},
        upsert=True,
    )
    logger.debug(f"[dork] Run saved | run_id={run.run_id}")