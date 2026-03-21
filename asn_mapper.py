"""
ZeroPoint :: asn_mapper.py
===========================
Module 9 Orchestrator — ASN Mapper.

Discovers the full IP space owned by a target company by resolving
known IPs to their BGP Autonomous System Numbers (ASNs), then fetching
all CIDR prefixes announced by those ASNs.

Why this unlocks more findings:
  The prober (Module 2) discovers IPs only for subdomains that have DNS.
  Many company-owned IPs have no DNS record — dev environments, internal
  APIs, staging boxes, legacy servers. BGP routing tables don't lie:
  if the company owns the ASN, they own every IP in those prefixes.

  A /24 range = 254 IPs. Shopify owns ~40 prefixes. That's potentially
  10,000+ IPs the prober never touches — but Masscan sweeps them in seconds.

Output stored in `asn_info` collection and automatically consumed by
the port scanner (Module 7) in subsequent runs.

Usage:
    python3 asn_mapper.py --program-id shopify_h1
    python3 asn_mapper.py                           # all active programs
    python3 asn_mapper.py --domain shopify.com      # quick single-domain test
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from loguru import logger

import db.mongo as mongo_ops
from config import settings
from db.asn_ops import (
    ensure_asn_indexes,
    get_asn_summary,
    save_asn_run,
    upsert_asn_info,
)
from db.mongo import get_assets_col
from models import ASNScanRun, Asset, ProbeStatus
from modules.asn_mapper import ASNMapper


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def configure_logging() -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level=settings.LOG_LEVEL,
        colorize=True,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{line}</cyan> | "
            "{message}"
        ),
    )
    logger.add(
        settings.LOG_FILE.replace(".log", "_asn.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Asset query
# ─────────────────────────────────────────────────────────────────────────────

async def get_assets_for_asn_mapping(
    program_id: str,
    limit:      int = 2000,
) -> List[Asset]:
    """Return alive assets with IPs — same source as port scanner."""
    col   = get_assets_col()
    query = {
        "program_id":   program_id,
        "probe_status": ProbeStatus.ALIVE.value,
        "ip_addresses": {"$exists": True, "$not": {"$size": 0}},
    }
    assets: List[Asset] = []
    # batch_size(100) — fetch 100 docs per network round trip instead of default
    # large batch, prevents socketTimeoutMS exhaustion on Atlas free tier when
    # the collection has thousands of documents
    cursor = col.find(query).limit(limit).batch_size(100)
    async for doc in cursor:
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed asset skipped: {exc}")

    # Only keep unique IPs — deduplicate before BGPView calls (saves API rate)
    seen_ips: set = set()
    deduped: List[Asset] = []
    for a in assets:
        new_ips = [ip for ip in (a.ip_addresses or []) if ip not in seen_ips]
        if new_ips:
            seen_ips.update(new_ips)
            a.ip_addresses = new_ips
            deduped.append(a)

    logger.info(f"[asn] {len(deduped)} asset(s) with unique IPs | program={program_id}")
    return deduped


# ─────────────────────────────────────────────────────────────────────────────
# Per-program mapping
# ─────────────────────────────────────────────────────────────────────────────

async def map_program(
    program_id: str,
    mapper:     ASNMapper,
) -> ASNScanRun:
    """Run ASN mapping for one program."""
    run = ASNScanRun(
        run_id     = uuid.uuid4().hex,
        program_id = program_id,
        started_at = datetime.now(timezone.utc),
    )
    await save_asn_run(run)

    logger.info(f"{'━' * 60}")
    logger.info(f"  ASN Mapper | program={program_id} | run_id={run.run_id}")
    logger.info(f"{'━' * 60}")

    assets = await get_assets_for_asn_mapping(program_id)

    if not assets:
        logger.info(
            f"[asn] No assets with IPs for {program_id}. "
            "Run prober first (Module 2)."
        )
        run.finished_at = datetime.now(timezone.utc)
        run.success     = True
        await save_asn_run(run)
        return run

    async for asn_info in mapper.map(assets, program_id):
        try:
            is_new = await upsert_asn_info(asn_info)
        except Exception as exc:
            logger.error(f"[asn] DB write failed: {exc}")
            run.errors.append(str(exc))
            continue

        run.asns_found    += 1
        run.prefixes_found += len(asn_info.ip_prefixes)
        if is_new:
            run.new_ips += len(asn_info.ip_prefixes)

    # Print summary
    summary = await get_asn_summary(program_id)
    run.finished_at = datetime.now(timezone.utc)
    run.success     = len(run.errors) == 0
    await save_asn_run(run)

    elapsed = (run.finished_at - run.started_at).total_seconds()
    logger.success(
        f"[asn] ✓ {program_id} | "
        f"asns={run.asns_found} | "
        f"prefixes={run.prefixes_found} | "
        f"total_in_db={summary['total_prefixes']} | "
        f"elapsed={elapsed:.1f}s"
    )

    # Print the ASN table for visibility
    if summary["details"]:
        logger.info("[asn] Discovered ASNs:")
        for entry in summary["details"]:
            logger.info(
                f"  AS{entry['asn']:>8}  {entry['name']:<35}  "
                f"{entry['prefixes']} prefixes"
            )

    return run


# ─────────────────────────────────────────────────────────────────────────────
# All-programs orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def map_all_programs(mapper: ASNMapper) -> List[ASNScanRun]:
    programs = await mongo_ops.list_active_programs()
    if not programs:
        logger.warning("[asn] No active programs in DB.")
        return []

    logger.info(f"[asn] Starting ASN mapping for {len(programs)} program(s)")
    runs = []
    for program in programs:
        try:
            run = await map_program(program.program_id, mapper)
            runs.append(run)
        except Exception as exc:
            logger.exception(f"[asn] Fatal error on {program.program_id}: {exc}")

    return runs


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-domain test (no DB write)
# ─────────────────────────────────────────────────────────────────────────────

async def map_single_domain(domain: str) -> None:
    """Dev/debug — resolve one domain's ASN and print prefixes, no DB write."""
    import socket

    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"[asn] {domain} → {ip}")
    except Exception as exc:
        logger.error(f"[asn] Could not resolve {domain}: {exc}")
        return

    # Build a fake asset
    from models import Asset, InterestLevel
    fake_asset = Asset(
        domain       = domain,
        program_id   = "__test__",
        ip_addresses = [ip],
    )

    mapper = _build_mapper()
    print(f"\n  {'━' * 56}")
    print(f"  ASN Mapper: {domain} → {ip}")
    print(f"  {'━' * 56}\n")

    async for asn_info in mapper.map([fake_asset], "__test__"):
        print(f"  AS{asn_info.asn_number}  {asn_info.asn_name}")
        print(f"  IPv4 prefixes: {len(asn_info.ip_prefixes)}")
        for prefix in asn_info.ip_prefixes[:20]:
            print(f"    {prefix}")
        if len(asn_info.ip_prefixes) > 20:
            print(f"    ... and {len(asn_info.ip_prefixes) - 20} more")
        print()

    print(f"  Run with --program-id to save to DB and feed port scanner.")


def _build_mapper() -> ASNMapper:
    return ASNMapper(
        rate_delay      = settings.ASN_RATE_DELAY,
        max_prefix_size = settings.ASN_MAX_PREFIX_SIZE,
        skip_cdn        = settings.ASN_SKIP_CDN,
        ipinfo_token    = settings.IPINFO_TOKEN,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    program_id: Optional[str] = None,
    domain:     Optional[str] = None,
) -> None:
    configure_logging()

    logger.info("=" * 60)
    logger.info("  ZeroPoint ASN Mapper — Module 9 Starting")
    logger.info("=" * 60)

    if domain:
        await map_single_domain(domain)
        return

    await mongo_ops.ensure_indexes()
    await ensure_asn_indexes()

    mapper = _build_mapper()

    try:
        if program_id:
            run = await map_program(program_id, mapper)
            logger.success(
                f"[asn] Done | "
                f"asns={run.asns_found} | prefixes={run.prefixes_found}"
            )
        else:
            runs = await map_all_programs(mapper)
            total = sum(r.prefixes_found for r in runs)
            logger.success(
                f"[asn] All programs done | "
                f"runs={len(runs)} | total_prefixes={total}"
            )

    except KeyboardInterrupt:
        logger.warning("[asn] Interrupted by user (Ctrl+C)")
    except Exception as exc:
        logger.exception(f"[asn] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[asn] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint ASN Mapper — company IP range discovery"
    )
    parser.add_argument("--program-id", type=str, default=None)
    parser.add_argument(
        "--domain", type=str, default=None,
        help="Quick-map a single domain (no DB write). For testing.",
    )
    args = parser.parse_args()
    asyncio.run(main(program_id=args.program_id, domain=args.domain))