"""
ZeroPoint :: prober.py
======================
Module 2 Orchestrator — Asset Probing & Fingerprinting Engine.

Pipeline:
  1. Query MongoDB for assets that need probing (probe_status=not_probed
     OR last_probed is stale, ordered by newest first_seen)
  2. Chunk assets into batches (configurable PROBER_BATCH_SIZE)
  3. Feed each batch to HttpxProber, stream results back as they arrive
  4. Pass each ProbeResult through FingerprintClassifier
  5. Write classified result to MongoDB (update_probe_result)
  6. Immediately alert on CRITICAL / HIGH findings (first-mover advantage)
  7. Log a summary digest at the end of each program run

Concurrency model:
  - Programs are processed one at a time (DB writes are fast; the bottleneck
    is httpx I/O, not Python). If you have 10+ programs, increase
    MAX_CONCURRENT_PROGRAMS in .env.
  - Within each program, batches are processed sequentially but httpx
    itself runs all hosts in each batch concurrently via its -threads flag.

Usage:
    # Probe all programs (respects reprobe interval)
    python prober.py

    # Force-reprobe a specific program
    python prober.py --program-id shopify_h1 --force

    # Probe a single domain without DB lookup (quick test)
    python prober.py --domain api.shopify.com
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter
from typing import Dict, List, Optional

from loguru import logger

import db.mongo as mongo_ops
from config import settings
from core.alerts import notify_high_value_probe, notify_probe_summary
from core.fingerprint import classifier
from models import Asset, InterestLevel, ProbeResult, ProbeStatus
from modules.prober import HttpxProber


# ─────────────────────────────────────────────────────────────────────────────
# Logging setup
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
        settings.LOG_FILE.replace(".log", "_prober.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Probe run for a single program
# ─────────────────────────────────────────────────────────────────────────────

async def probe_program(
    program_id:    str,
    prober:        HttpxProber,
    force_reprobe: bool = False,
) -> Dict[str, int]:
    """
    Execute the full probe + fingerprint pipeline for one program.

    Returns a stats dict:
      {total, alive, dead, error, critical, high, medium, low, noise}
    """
    stats: Counter = Counter()

    # ── 1. Fetch assets needing a probe ───────────────────────────────────
    assets: List[Asset] = await mongo_ops.get_assets_to_probe(
        program_id=program_id,
        limit=5000,
        reprobe_after_hours=settings.PROBER_REPROBE_HOURS,
        force_reprobe=force_reprobe,
    )

    if not assets:
        logger.info(f"[prober] No assets to probe for program={program_id}")
        return dict(stats)

    stats["total"] = len(assets)
    logger.info(
        f"[prober] Probing {len(assets)} assets for program={program_id} "
        f"| force={force_reprobe}"
    )

    # ── 2. Chunk into batches ─────────────────────────────────────────────
    batch_size = settings.PROBER_BATCH_SIZE
    batches    = [
        assets[i : i + batch_size]
        for i in range(0, len(assets), batch_size)
    ]
    logger.info(
        f"[prober] {len(batches)} batch(es) × {batch_size} domains each"
    )

    # ── 3. Process each batch ─────────────────────────────────────────────
    for batch_idx, batch in enumerate(batches, start=1):
        domain_list = [a.domain for a in batch]
        logger.debug(
            f"[prober] Batch {batch_idx}/{len(batches)} | {len(domain_list)} domains"
        )

        # Track which domains were submitted but got no result (= DEAD)
        probed_domains: set[str] = set()

        # Stream results as they come from httpx
        async for raw_result in prober.probe(domain_list):

            # ── 4. Classify with fingerprint engine ───────────────────
            classified: ProbeResult = classifier.classify(raw_result)
            probed_domains.add(classified.domain)

            # ── 5. Write to MongoDB ───────────────────────────────────
            try:
                await mongo_ops.update_probe_result(classified)
            except Exception as exc:
                logger.error(f"[prober] DB write failed for {classified.domain}: {exc}")
                stats["error"] += 1
                continue

            # ── 6. Update run stats ───────────────────────────────────
            status_key = classified.probe_status.value
            stats[status_key] += 1
            stats[classified.interest_level.value] += 1

            # ── 7. Immediate alert for CRITICAL / HIGH findings ───────
            if classified.interest_level in (InterestLevel.CRITICAL, InterestLevel.HIGH):
                asyncio.create_task(
                    notify_high_value_probe(classified, program_id)
                )

        # ── Mark domains that returned no httpx output as DEAD ────────────
        silent_domains = set(domain_list) - probed_domains
        if silent_domains:
            logger.debug(
                f"[prober] {len(silent_domains)} domain(s) got no httpx response → marking DEAD"
            )
            dead_results = [
                ProbeResult(
                    domain=d,
                    probe_status=ProbeStatus.DEAD,
                    interest_level=InterestLevel.NOISE,
                    interest_reasons=["no httpx response"],
                )
                for d in silent_domains
            ]
            write_tasks = [mongo_ops.update_probe_result(r) for r in dead_results]
            await asyncio.gather(*write_tasks, return_exceptions=True)
            stats["dead"] += len(silent_domains)

    # ── 8. Summary alert ─────────────────────────────────────────────────
    await notify_probe_summary(
        program_id=program_id,
        total_probed=stats["total"],
        alive=stats.get("alive", 0),
        dead=stats.get("dead", 0),
        critical=stats.get("critical", 0),
        high=stats.get("high", 0),
        medium=stats.get("medium", 0),
    )

    return dict(stats)


# ─────────────────────────────────────────────────────────────────────────────
# Multi-program orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def probe_all_programs(force_reprobe: bool = False) -> None:
    """
    Probe all active programs sequentially.
    Extend to asyncio.gather with semaphore if you have many programs and
    want them running in parallel.
    """
    programs = await mongo_ops.list_active_programs()

    if not programs:
        logger.warning("[prober] No active programs found in DB.")
        return

    logger.info(f"[prober] Starting probe run for {len(programs)} active program(s)")

    prober = HttpxProber(
        binary_path=settings.HTTPX_PATH,
        threads=settings.PROBER_THREADS,
        rate_limit=settings.PROBER_RATE_LIMIT,
        timeout=settings.PROBER_TIMEOUT,
        retries=settings.PROBER_RETRIES,
        follow_redirects=settings.PROBER_FOLLOW_REDIRECTS,
        screenshot=settings.PROBER_SCREENSHOT,
        screenshot_dir=settings.PROBER_SCREENSHOT_DIR,
    )

    grand_total: Counter = Counter()

    for program in programs:
        try:
            stats = await probe_program(
                program_id=program.program_id,
                prober=prober,
                force_reprobe=force_reprobe,
            )
            grand_total.update(stats)

            logger.success(
                f"[prober] ✓ {program.program_id} | "
                f"total={stats.get('total',0)} | "
                f"alive={stats.get('alive',0)} | "
                f"dead={stats.get('dead',0)} | "
                f"🚨critical={stats.get('critical',0)} | "
                f"🔴high={stats.get('high',0)} | "
                f"🟡medium={stats.get('medium',0)}"
            )

        except Exception as exc:
            logger.exception(
                f"[prober] Fatal error probing program={program.program_id}: {exc}"
            )

    logger.info(
        f"[prober] All programs complete | "
        f"grand_total={dict(grand_total)}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-domain probe (dev/debug utility)
# ─────────────────────────────────────────────────────────────────────────────

async def probe_single_domain(domain: str) -> None:
    """Probe one domain, classify it, and print the result. Does NOT write to DB."""
    prober = HttpxProber(
        binary_path=settings.HTTPX_PATH,
        threads=1,
        rate_limit=10,
        timeout=settings.PROBER_TIMEOUT,
    )
    logger.info(f"[prober] Single-domain probe: {domain}")

    async for raw in prober.probe([domain]):
        classified = classifier.classify(raw)
        logger.info(
            f"\n"
            f"  Domain:        {classified.domain}\n"
            f"  Status:        {classified.http_status}\n"
            f"  Title:         {classified.http_title}\n"
            f"  Tech:          {classified.technologies}\n"
            f"  Interest:      {classified.interest_level.value.upper()}\n"
            f"  Reasons:       {classified.interest_reasons}\n"
            f"  Server:        {classified.web_server}\n"
            f"  CDN:           {classified.cdn_provider}\n"
            f"  Response time: {classified.response_time_ms}ms\n"
        )
        return

    logger.warning(f"[prober] No response from {domain}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    program_id: Optional[str]  = None,
    domain:     Optional[str]  = None,
    force:      bool           = False,
) -> None:
    configure_logging()

    logger.info("=" * 60)
    logger.info("  ZeroPoint Prober — Module 2 Starting")
    logger.info("=" * 60)

    # Single-domain quick-test (no DB required)
    if domain:
        await probe_single_domain(domain)
        return

    # All other modes require DB
    await mongo_ops.ensure_indexes()

    try:
        if program_id:
            prober = HttpxProber(
                binary_path=settings.HTTPX_PATH,
                threads=settings.PROBER_THREADS,
                rate_limit=settings.PROBER_RATE_LIMIT,
                timeout=settings.PROBER_TIMEOUT,
                retries=settings.PROBER_RETRIES,
                follow_redirects=settings.PROBER_FOLLOW_REDIRECTS,
                screenshot=settings.PROBER_SCREENSHOT,
                screenshot_dir=settings.PROBER_SCREENSHOT_DIR,
            )
            stats = await probe_program(
                program_id=program_id,
                prober=prober,
                force_reprobe=force,
            )
            logger.success(f"[prober] Done | stats={stats}")
        else:
            await probe_all_programs(force_reprobe=force)

    except KeyboardInterrupt:
        logger.warning("[prober] Interrupted by user (Ctrl+C)")
    except Exception as exc:
        logger.exception(f"[prober] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[prober] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint Prober — HTTP probe and fingerprint engine"
    )
    parser.add_argument(
        "--program-id",
        type=str,
        default=None,
        help="Probe a specific program only (by program_id). Default: all active programs.",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default=None,
        help="Quick-probe a single domain (no DB write). For testing/debugging.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Re-probe all assets regardless of last_probed timestamp.",
    )
    args = parser.parse_args()

    asyncio.run(main(
        program_id=args.program_id,
        domain=args.domain,
        force=args.force,
    ))
