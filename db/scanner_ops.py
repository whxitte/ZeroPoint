"""
ZeroPoint :: db/scanner_ops.py
================================
MongoDB operations for Module 3 — Scanner (Nuclei).
Keeps scanner-specific DB logic isolated from the core mongo.py module.
Imported by scanner.py — never call directly from other modules.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

from loguru import logger
from pymongo.errors import PyMongoError

from db.mongo import get_assets_col, get_db
from models import Asset, Finding, ProbeStatus, ScanRun


def get_findings_col():
    return get_db()["findings"]


def get_scan_runs_col():
    return get_db()["scan_runs"]


async def upsert_finding(finding: Finding) -> bool:
    """
    Insert or update a Finding document using `finding_id` as the dedup key.

    Returns:
        True  → brand-new finding (never seen before) → alert should fire
        False → finding already existed → suppress alert (idempotent)

    State:
      First insert  → is_new=True, first_seen=now
      Subsequent   → only last_seen updated; is_new preserved until notified
    """
    col = get_findings_col()
    now = datetime.now(timezone.utc)

    # Build the $setOnInsert payload — explicitly exclude fields that are
    # also in $set to avoid MongoDB error code 40 (path conflict).
    # Rule: a field must appear in EITHER $set OR $setOnInsert, never both.
    insert_fields = finding.model_dump(
        exclude={"last_seen", "scan_run_id", "is_new"}
    )

    try:
        result = await col.update_one(
            {"finding_id": finding.finding_id},
            {
                # Always updated on every run (existing or new document)
                "$set": {
                    "last_seen":   now,
                    "scan_run_id": finding.scan_run_id,
                },
                # Only set on first insert — never touched on subsequent runs
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
            f"[scanner] {'NEW' if is_new else 'DUPE'} | "
            f"{finding.severity.upper():8} | {finding.template_id} | {finding.matched_at}",
        )
        return is_new

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for finding {finding.finding_id}: {exc}")
        raise


async def mark_findings_notified(finding_ids: List[str]) -> None:
    """Flip is_new=False after Discord/Telegram alerts have been sent."""
    if not finding_ids:
        return
    col = get_findings_col()
    await col.update_many(
        {"finding_id": {"$in": finding_ids}},
        {"$set": {"is_new": False}},
    )
    logger.debug(f"[scanner] Marked {len(finding_ids)} finding(s) notified (is_new=False)")


async def get_new_findings(program_id: str) -> List[Finding]:
    """Return all findings with is_new=True for a program (unnotified)."""
    col      = get_findings_col()
    findings = []
    async for doc in col.find({"program_id": program_id, "is_new": True}):
        doc.pop("_id", None)
        try:
            findings.append(Finding(**doc))
        except Exception as exc:
            logger.warning(f"Malformed finding doc skipped: {exc}")
    return findings


async def get_assets_to_scan(
    program_id:         str,
    min_interest:       str = "high",
    rescan_after_hours: int = 72,
    limit:              int = 500,
) -> List[Asset]:
    """
    Query the `assets` collection for targets that qualify for a Nuclei scan.

    Selection logic:
      1. probe_status = alive (never scan dead hosts)
      2. interest_level >= min_interest (HIGH or CRITICAL by default)
      3. last_scanned is None OR last_scanned < (now - rescan_after_hours)

    Ordered by interest_level DESC so CRITICAL targets always get scanned first.
    """
    level_order   = ["noise", "low", "medium", "high", "critical"]
    min_idx       = level_order.index(min_interest.lower())
    eligible_lvls = level_order[min_idx:]
    cutoff        = datetime.now(timezone.utc) - timedelta(hours=rescan_after_hours)

    col   = get_assets_col()
    query = {
        "program_id":     program_id,
        "probe_status":   ProbeStatus.ALIVE.value,
        "interest_level": {"$in": eligible_lvls},
        "$or": [
            {"last_scanned": {"$exists": False}},
            {"last_scanned": None},
            {"last_scanned": {"$lt": cutoff}},
        ],
    }

    assets: List[Asset] = []
    # CRITICAL first, then HIGH — sort by level desc
    level_sort = {"critical": 0, "high": 1, "medium": 2, "low": 3, "noise": 4}

    cursor = col.find(query).limit(limit)
    async for doc in cursor:
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed asset skipped in scanner query: {exc}")

    assets.sort(key=lambda a: level_sort.get(a.interest_level, 99))

    logger.info(
        f"[scanner] {len(assets)} asset(s) queued | "
        f"program={program_id} | min_interest={min_interest}"
    )
    return assets


async def mark_asset_scanned(domain: str, scan_run_id: str) -> None:
    """Stamp the asset with last_scanned timestamp after Nuclei completes."""
    col = get_assets_col()
    await col.update_one(
        {"domain": domain},
        {"$set": {
            "last_scanned":  datetime.now(timezone.utc),
            "last_scan_run": scan_run_id,
        }},
    )


async def save_scan_run(run: ScanRun) -> None:
    """Upsert a ScanRun audit record."""
    col = get_scan_runs_col()
    await col.update_one(
        {"run_id": run.run_id},
        {"$set": run.model_dump()},
        upsert=True,
    )
    logger.debug(f"[scanner] ScanRun saved | run_id={run.run_id}")


async def get_finding_stats(program_id: str) -> dict:
    """Aggregate finding counts by severity for reporting."""
    col      = get_findings_col()
    pipeline = [
        {"$match": {"program_id": program_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    stats: dict = {}
    async for doc in col.aggregate(pipeline):
        stats[doc["_id"] or "unknown"] = doc["count"]
    return stats


async def ensure_scanner_indexes() -> None:
    """Create scanner-specific indexes. Called once at startup by scanner.py."""
    from pymongo import ASCENDING
    from pymongo import IndexModel

    findings_col  = get_findings_col()
    scan_runs_col = get_scan_runs_col()

    await findings_col.create_indexes([
        IndexModel([("finding_id",  ASCENDING)], unique=True, name="finding_id_unique"),
        IndexModel([("program_id",  ASCENDING)], name="findings_program_id"),
        IndexModel([("domain",      ASCENDING)], name="findings_domain"),
        IndexModel([("severity",    ASCENDING)], name="findings_severity"),
        IndexModel([("is_new",      ASCENDING)], name="findings_is_new"),
        IndexModel([("template_id", ASCENDING)], name="findings_template_id"),
        IndexModel([("first_seen",  ASCENDING)], name="findings_first_seen"),
    ])

    await scan_runs_col.create_indexes([
        IndexModel([("run_id",     ASCENDING)], unique=True, name="run_id_unique"),
        IndexModel([("program_id", ASCENDING)], name="scan_runs_program_id"),
        IndexModel([("started_at", ASCENDING)], name="scan_runs_started_at"),
    ])

    logger.debug("Scanner indexes verified ✓")