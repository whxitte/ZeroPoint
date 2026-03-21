"""
ZeroPoint :: db/github_ops.py
================================
MongoDB operations for Module 6 — GitHub OSINT.

Collection managed:
  github_leaks  — every unique credential/secret reference found on GitHub
  github_runs   — audit log of every GitHub OSINT run
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from loguru import logger
from pymongo import ASCENDING, IndexModel
from pymongo.errors import PyMongoError

from db.mongo import get_db
from models import GitHubLeak, GitHubLeakSeverity, GitHubOSINTRun


# ─────────────────────────────────────────────────────────────────────────────
# Collection accessors
# ─────────────────────────────────────────────────────────────────────────────

def get_leaks_col():
    return get_db()["github_leaks"]


def get_runs_col():
    return get_db()["github_runs"]


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────

def make_leak_id(repo_full_name: str, file_path: str, match_type: str, match_value: str) -> str:
    """SHA-256 fingerprint — same leak on same file never alerts twice."""
    raw = f"{repo_full_name.lower()}|{file_path}|{match_type.lower()}|{match_value[:32].lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Index bootstrap
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_github_indexes() -> None:
    """Create GitHub OSINT indexes — idempotent, call once at startup."""
    leaks_col = get_leaks_col()
    runs_col  = get_runs_col()

    await leaks_col.create_indexes([
        IndexModel([("leak_id",        ASCENDING)], unique=True, name="leak_id_unique"),
        IndexModel([("tenant_id",      ASCENDING)], name="gh_tenant"),
        IndexModel([("program_id",     ASCENDING)], name="gh_program"),
        IndexModel([("domain",         ASCENDING)], name="gh_domain"),
        IndexModel([("severity",       ASCENDING)], name="gh_severity"),
        IndexModel([("is_new",         ASCENDING)], name="gh_is_new"),
        IndexModel([("repo_full_name", ASCENDING)], name="gh_repo"),
        IndexModel([("match_type",     ASCENDING)], name="gh_match_type"),
        IndexModel([("first_seen",     ASCENDING)], name="gh_first_seen"),
    ])

    await runs_col.create_indexes([
        IndexModel([("run_id",     ASCENDING)], unique=True, name="ghr_run_id"),
        IndexModel([("program_id", ASCENDING)], name="ghr_program"),
        IndexModel([("started_at", ASCENDING)], name="ghr_started"),
    ])

    logger.debug("GitHub OSINT indexes verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Leak upsert
# ─────────────────────────────────────────────────────────────────────────────

async def upsert_leak(leak: GitHubLeak) -> bool:
    """
    Insert or update a GitHubLeak document.

    Returns True  → brand-new leak (never seen before) → alert should fire
    Returns False → already known → suppress alert
    """
    col = get_leaks_col()
    now = datetime.now(timezone.utc)

    insert_fields = leak.model_dump(exclude={"last_seen", "is_new"})

    try:
        result = await col.update_one(
            {"leak_id": leak.leak_id},
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
        is_new = result.upserted_id is not None
        logger.log(
            "SUCCESS" if is_new else "DEBUG",
            f"[github] {'NEW' if is_new else 'DUPE'} leak | "
            f"{leak.severity.upper()} | {leak.match_type} | {leak.repo_full_name}",
        )
        return is_new

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for leak {leak.leak_id}: {exc}")
        raise


async def mark_leaks_notified(leak_ids: List[str], suppress_days: int = 7) -> None:
    """Flip is_new=False and set suppress_until after alerts dispatched."""
    if not leak_ids:
        return
    from datetime import timedelta
    from datetime import datetime, timezone
    col         = get_leaks_col()
    suppress_ts = datetime.now(timezone.utc) + timedelta(days=suppress_days)
    await col.update_many(
        {"leak_id": {"$in": leak_ids}},
        {"$set": {"is_new": False, "suppress_until": suppress_ts}},
    )
    logger.debug(f"[github] Marked {len(leak_ids)} leak(s) notified | suppress_until={suppress_ts.date()}")


async def get_leak_stats(program_id: str) -> dict:
    """Aggregate leak counts by severity for a program."""
    col      = get_leaks_col()
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

async def save_github_run(run: GitHubOSINTRun) -> None:
    col = get_runs_col()
    await col.update_one(
        {"run_id": run.run_id},
        {"$set": run.model_dump()},
        upsert=True,
    )
    logger.debug(f"[github] Run saved | run_id={run.run_id}")