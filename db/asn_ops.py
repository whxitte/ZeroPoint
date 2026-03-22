"""
ZeroPoint :: db/asn_ops.py
============================
MongoDB operations for the ASN Mapper.

Collections managed:
  asn_info   — discovered ASNs and their IP prefixes per program
  asn_runs   — audit log of every ASN mapping run
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Set

from loguru import logger
from pymongo import ASCENDING, IndexModel
from pymongo.errors import PyMongoError

from db.mongo import get_db
from models import ASNInfo, ASNScanRun


# ─────────────────────────────────────────────────────────────────────────────
# Collection accessors
# ─────────────────────────────────────────────────────────────────────────────

def get_asn_col():
    return get_db()["asn_info"]


def get_runs_col():
    return get_db()["asn_runs"]


# ─────────────────────────────────────────────────────────────────────────────
# Index bootstrap
# ─────────────────────────────────────────────────────────────────────────────

async def ensure_asn_indexes() -> None:
    """Create ASN mapper indexes — idempotent."""
    asn_col  = get_asn_col()
    runs_col = get_runs_col()

    await asn_col.create_indexes([
        IndexModel(
            [("program_id", ASCENDING), ("asn_number", ASCENDING)],
            unique=True, name="asn_program_unique"
        ),
        IndexModel([("tenant_id",  ASCENDING)], name="asn_tenant"),
        IndexModel([("program_id", ASCENDING)], name="asn_program"),
        IndexModel([("domain",     ASCENDING)], name="asn_domain"),
        IndexModel([("last_seen",  ASCENDING)], name="asn_last_seen"),
    ])

    await runs_col.create_indexes([
        IndexModel([("run_id",     ASCENDING)], unique=True, name="asnr_run_id"),
        IndexModel([("program_id", ASCENDING)],              name="asnr_program"),
        IndexModel([("started_at", ASCENDING)],              name="asnr_started"),
    ])

    logger.debug("ASN mapper indexes verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Upsert
# ─────────────────────────────────────────────────────────────────────────────

async def upsert_asn_info(asn: ASNInfo) -> bool:
    """
    Insert or update an ASNInfo document.

    Returns True if new (or prefixes changed), False if unchanged.
    """
    col = get_asn_col()
    now = datetime.now(timezone.utc)

    try:
        result = await col.update_one(
            {"program_id": asn.program_id, "asn_number": asn.asn_number},
            {
                # Rule: a field must appear in EITHER $set OR $setOnInsert, never both.
                # asn_name and description are in $set → excluded from $setOnInsert.
                "$set": {
                    "last_seen":    now,
                    "ip_prefixes":  asn.ip_prefixes,
                    "ipv6_prefixes": asn.ipv6_prefixes,
                    "asn_name":     asn.asn_name,
                    "description":  asn.description,
                },
                "$setOnInsert": {
                    **asn.model_dump(exclude={
                        "last_seen", "ip_prefixes", "ipv6_prefixes",
                        "asn_name", "description",   # already in $set above
                    }),
                    "first_seen": now,
                },
            },
            upsert=True,
        )
        is_new = result.upserted_id is not None
        logger.log(
            "SUCCESS" if is_new else "DEBUG",
            f"[asn] {'NEW' if is_new else 'UPDATED'} | "
            f"AS{asn.asn_number} ({asn.asn_name}) | "
            f"{len(asn.ip_prefixes)} prefixes | {asn.domain}"
        )
        return is_new

    except PyMongoError as exc:
        logger.error(f"DB upsert failed for AS{asn.asn_number}: {exc}")
        raise


async def get_asn_prefixes_for_program(program_id: str) -> List[str]:
    """
    Return all discovered IPv4 CIDR prefixes for a program.
    Used by the port scanner to extend its scan targets beyond known IPs.
    """
    col      = get_asn_col()
    prefixes: List[str] = []
    async for doc in col.find({"program_id": program_id}):
        prefixes.extend(doc.get("ip_prefixes", []))
    return prefixes


async def get_asn_summary(program_id: str) -> dict:
    """Return a summary of ASNs and prefix count for a program."""
    col    = get_asn_col()
    asns   = []
    total_prefixes = 0
    async for doc in col.find({"program_id": program_id}):
        asns.append({
            "asn":      doc.get("asn_number"),
            "name":     doc.get("asn_name"),
            "prefixes": len(doc.get("ip_prefixes", [])),
        })
        total_prefixes += len(doc.get("ip_prefixes", []))
    return {
        "program_id":    program_id,
        "asns":          len(asns),
        "total_prefixes": total_prefixes,
        "details":       asns,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Run audit
# ─────────────────────────────────────────────────────────────────────────────

async def save_asn_run(run: ASNScanRun) -> None:
    col = get_runs_col()
    await col.update_one(
        {"run_id": run.run_id},
        {"$set": run.model_dump()},
        upsert=True,
    )
    logger.debug(f"[asn] Run saved | run_id={run.run_id}")