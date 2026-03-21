"""
ZeroPoint :: db/portscan_ops.py
================================
MongoDB operations for Module 7 — Port Scanner.

Collections managed:
  port_findings  — every unique open port / service discovered
  port_scan_runs — audit log of every scan run
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List

from loguru import logger
from pymongo import ASCENDING, IndexModel
from pymongo.errors import PyMongoError

from db.mongo import get_db
from models import PortFinding, PortScanRun


# ─────────────────────────────────────────────────────────────────────────────
# Collection accessors
# ─────────────────────────────────────────────────────────────────────────────

def get_findings_col():
    return get_db()["port_findings"]


def get_runs_col():
    return get_db()["port_scan_runs"]


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────────────────────

def make_port_finding_id(ip: str, port: int, protocol: str) -> str:
    """SHA-256 fingerprint — same service on same IP never alerts twice."""
    raw = f"{ip.strip()}|{port}|{protocol.lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Index bootstrap
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_portscan_indexes() -> None:
    """Create port scanner indexes — idempotent, call once at startup."""
    findings_col = get_findings_col()
    runs_col     = get_runs_col()

    await findings_col.create_indexes([
        IndexModel([("finding_id",  ASCENDING)], unique=True, name="pf_finding_id"),
        IndexModel([("tenant_id",   ASCENDING)],              name="pf_tenant"),
        IndexModel([("program_id",  ASCENDING)],              name="pf_program"),
        IndexModel([("domain",      ASCENDING)],              name="pf_domain"),
        IndexModel([("ip",          ASCENDING)],              name="pf_ip"),
        IndexModel([("port",        ASCENDING)],              name="pf_port"),
        IndexModel([("severity",    ASCENDING)],              name="pf_severity"),
        IndexModel([("is_new",      ASCENDING)],              name="pf_is_new"),
        IndexModel([("first_seen",  ASCENDING)],              name="pf_first_seen"),
        IndexModel([("tenant_id", ASCENDING), ("program_id", ASCENDING)],
                   name="pf_tenant_program"),
    ])

    await runs_col.create_indexes([
        IndexModel([("run_id",     ASCENDING)], unique=True, name="psr_run_id"),
        IndexModel([("program_id", ASCENDING)],              name="psr_program"),
        IndexModel([("started_at", ASCENDING)],              name="psr_started"),
    ])

    logger.debug("Port scanner indexes verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Upsert
# ─────────────────────────────────────────────────────────────────────────────

async def upsert_port_finding(finding: PortFinding) -> bool:
    """
    Insert or update a PortFinding document.

    Returns True  → brand-new finding (never seen before) → alert should fire
    Returns False → already known → suppress alert
    """
    col = get_findings_col()
    now = datetime.now(timezone.utc)

    insert_fields = finding.model_dump(exclude={"last_seen", "is_new"})

    try:
        result = await col.update_one(
            {"finding_id": finding.finding_id},
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
            f"[portscan] {'NEW' if is_new else 'DUPE'} | "
            f"{finding.severity.upper()} | {finding.ip}:{finding.port} | "
            f"{finding.service or 'unknown'} | {finding.domain}",
        )
        return is_new

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for port finding {finding.finding_id}: {exc}")
        raise


async def mark_findings_notified(finding_ids: List[str]) -> None:
    """Flip is_new=False after alerts dispatched."""
    if not finding_ids:
        return
    col = get_findings_col()
    await col.update_many(
        {"finding_id": {"$in": finding_ids}},
        {"$set": {"is_new": False}},
    )
    logger.debug(f"[portscan] Marked {len(finding_ids)} finding(s) notified")


async def get_port_stats(program_id: str) -> dict:
    """Aggregate open port counts by severity."""
    col      = get_findings_col()
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

async def save_port_scan_run(run: PortScanRun) -> None:
    col = get_runs_col()
    await col.update_one(
        {"run_id": run.run_id},
        {"$set": run.model_dump()},
        upsert=True,
    )
    logger.debug(f"[portscan] Run saved | run_id={run.run_id}")