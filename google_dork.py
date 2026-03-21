"""
ZeroPoint :: google_dork.py
============================
Module 8 Orchestrator — Google Dork Engine.

Finds publicly indexed sensitive exposures that no port scanner or crawler
can reach — because they exist only in Google's index:

  Exposed .env files    → site:target.com filetype:env
  SQL dumps             → site:target.com filetype:sql
  Backup files          → site:target.com ext:bak
  Hardcoded credentials → site:target.com "DB_PASSWORD"
  Private keys          → site:target.com "BEGIN RSA PRIVATE KEY"
  AWS keys              → site:target.com "AWS_ACCESS_KEY_ID"
  Admin panels          → site:target.com inurl:admin
  Open directory listings → site:target.com intitle:"Index of /"
  Swagger/API docs      → site:target.com inurl:swagger
  Stack traces          → site:target.com "Stack Trace"
  phpMyAdmin            → site:target.com inurl:phpmyadmin
  Jenkins               → site:target.com inurl:jenkins

Pipeline per program:
  1. Load program root domains from DB
  2. For each domain: run all 35+ dork queries via Google CSE API
  3. Each result is deduped via SHA-256 (domain + category + url)
  4. Upsert to `dork_results` collection
  5. Alert immediately on CRITICAL/HIGH findings
  6. Save DorkScanRun audit record

Setup (5 minutes, free tier = 100 queries/day):
  1. https://console.cloud.google.com → enable "Custom Search API" → create API key
  2. https://cse.google.com/cse/ → create engine with "Search the entire web"
  3. Add to .env:
       GOOGLE_API_KEY=AIzaSy...
       GOOGLE_CSE_ID=abc123...

Usage:
    python3 google_dork.py --program-id shopify_h1
    python3 google_dork.py                           # all active programs
    python3 google_dork.py --domain shopify.com      # quick single-domain test
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional

from loguru import logger

import db.mongo as mongo_ops
from config import settings
from core.alerts import notify_dork_finding, notify_dork_summary
from db.dork_ops import (
    ensure_dork_indexes,
    mark_results_notified,
    save_dork_run,
    upsert_dork_result,
)
from models import DorkScanRun, DorkSeverity
from modules.dorker import GoogleDorker


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
        settings.LOG_FILE.replace(".log", "_dork.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Severity filter for immediate alerts
# ─────────────────────────────────────────────────────────────────────────────

_ALERT_SEVERITIES = {DorkSeverity.CRITICAL, DorkSeverity.HIGH}


# ─────────────────────────────────────────────────────────────────────────────
# Per-program dork scan
# ─────────────────────────────────────────────────────────────────────────────

async def dork_program(
    program_id: str,
    dorker:     GoogleDorker,
    tenant_id:  str = "default",
) -> DorkScanRun:
    """Execute the full dork scan pipeline for one program."""
    run = DorkScanRun(
        run_id     = uuid.uuid4().hex,
        program_id = program_id,
        started_at = datetime.now(timezone.utc),
    )
    await save_dork_run(run)

    logger.info(f"{'━' * 60}")
    logger.info(f"  Google Dork | program={program_id} | run_id={run.run_id}")
    logger.info(f"{'━' * 60}")

    program = await mongo_ops.get_program(program_id)
    if not program:
        logger.error(f"[dork] Program '{program_id}' not found in DB")
        run.finished_at = datetime.now(timezone.utc)
        run.success     = False
        run.errors.append(f"Program '{program_id}' not found")
        await save_dork_run(run)
        return run

    new_result_ids: List[str] = []
    sev_counter:    Counter   = Counter()
    alert_tasks:    List      = []

    for domain in program.domains:
        logger.info(f"[dork] Scanning domain: {domain}")

        async for result in dorker.dork(
            domain     = domain,
            program_id = program_id,
            run_id     = run.run_id,
            tenant_id  = tenant_id,
        ):
            run.results_raw += 1
            run.queries_run   = 1  # approximation — incremented per yield batch

            try:
                is_new = await upsert_dork_result(result)
            except Exception as exc:
                logger.error(f"[dork] DB write failed: {exc}")
                run.errors.append(str(exc))
                continue

            if is_new:
                run.new_findings += 1
                sev_key = result.severity.value
                sev_counter[sev_key] += 1
                new_result_ids.append(result.result_id)

                if result.severity in _ALERT_SEVERITIES:
                    alert_tasks.append(notify_dork_finding(result, program_id))

    # Fire all queued alerts
    if alert_tasks:
        results = await asyncio.gather(*alert_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"[dork] Alert error: {r}")

    # Flip is_new=False after notifications
    if new_result_ids:
        await mark_results_notified(new_result_ids)

    # Summary digest
    await notify_dork_summary(
        program_id   = program_id,
        new_findings = run.new_findings,
        by_severity  = dict(sev_counter),
        run_id       = run.run_id,
    )

    run.finished_at = datetime.now(timezone.utc)
    run.success     = len(run.errors) == 0
    await save_dork_run(run)

    elapsed = (run.finished_at - run.started_at).total_seconds()
    logger.success(
        f"[dork] ✓ {program_id} | "
        f"raw={run.results_raw} new={run.new_findings} elapsed={elapsed:.1f}s | "
        f"🚨crit={sev_counter.get('critical', 0)} "
        f"🔴high={sev_counter.get('high', 0)} "
        f"🟡med={sev_counter.get('medium', 0)}"
    )
    return run


# ─────────────────────────────────────────────────────────────────────────────
# All-programs orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def dork_all_programs(dorker: GoogleDorker) -> List[DorkScanRun]:
    programs = await mongo_ops.list_active_programs()
    if not programs:
        logger.warning("[dork] No active programs in DB.")
        return []

    logger.info(f"[dork] Starting dork scan for {len(programs)} program(s)")
    runs = []
    for program in programs:
        try:
            run = await dork_program(program.program_id, dorker)
            runs.append(run)
        except Exception as exc:
            logger.exception(f"[dork] Fatal error on {program.program_id}: {exc}")

    return runs


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-domain test (no DB write)
# ─────────────────────────────────────────────────────────────────────────────

async def dork_single_domain(domain: str) -> None:
    """Dev/debug — dork one domain, print results, no DB write."""
    if not settings.GOOGLE_API_KEY or not settings.GOOGLE_CSE_ID:
        logger.error(
            "[dork] GOOGLE_API_KEY and GOOGLE_CSE_ID not configured.\n"
            "  Setup guide:\n"
            "  1. https://console.cloud.google.com → Custom Search API → API key\n"
            "  2. https://cse.google.com/cse/ → Create engine (search entire web)\n"
            "  3. Add to .env:\n"
            "       GOOGLE_API_KEY=AIzaSy...\n"
            "       GOOGLE_CSE_ID=abc123..."
        )
        return

    dorker = _build_dorker()

    print(f"\n  {'━' * 56}")
    print(f"  Google Dork: {domain}")
    print(f"  {'━' * 56}\n")

    count = 0
    async for result in dorker.dork(domain, "__test__", "test_run"):
        count += 1
        sev = result.severity.value
        print(f"  [{sev.upper():8}]  [{result.dork_category}]")
        print(f"             URL:    {result.url[:100]}")
        if result.title:
            print(f"             Title:  {result.title[:80]}")
        if result.snippet:
            print(f"             Snip:   {result.snippet[:120]}")
        print(f"             Reason: {result.reason}")
        print()

    if count == 0:
        print(f"  No dork results found for {domain}")
        print("  (This is good — it means nothing sensitive is indexed.)")
    else:
        print(f"  Total: {count} result(s) found")


def _build_dorker() -> GoogleDorker:
    return GoogleDorker(
        api_key     = settings.GOOGLE_API_KEY or "",
        cse_id      = settings.GOOGLE_CSE_ID  or "",
        max_results = settings.GOOGLE_DORK_MAX_RESULTS,
        rate_delay  = settings.GOOGLE_DORK_RATE_DELAY,
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
    logger.info("  ZeroPoint Google Dork Engine — Module 8 Starting")
    logger.info("=" * 60)

    if not settings.GOOGLE_API_KEY or not settings.GOOGLE_CSE_ID:
        logger.error(
            "[dork] GOOGLE_API_KEY and GOOGLE_CSE_ID are required.\n"
            "  See https://developers.google.com/custom-search/v1/overview\n"
            "  Add both to your .env file."
        )
        sys.exit(1)

    if domain:
        await dork_single_domain(domain)
        return

    await mongo_ops.ensure_indexes()
    await ensure_dork_indexes()

    dorker = _build_dorker()

    try:
        if program_id:
            run = await dork_program(program_id, dorker)
            logger.success(
                f"[dork] Done | "
                f"new={run.new_findings} | raw={run.results_raw}"
            )
        else:
            runs = await dork_all_programs(dorker)
            total_new = sum(r.new_findings for r in runs)
            logger.success(
                f"[dork] All programs done | "
                f"runs={len(runs)} | total_new={total_new}"
            )

    except KeyboardInterrupt:
        logger.warning("[dork] Interrupted by user (Ctrl+C)")
    except Exception as exc:
        logger.exception(f"[dork] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[dork] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint Google Dork Engine — publicly indexed exposure scanner"
    )
    parser.add_argument("--program-id", type=str, default=None)
    parser.add_argument(
        "--domain", type=str, default=None,
        help="Quick-dork a single domain (no DB write). For testing.",
    )
    args = parser.parse_args()
    asyncio.run(main(program_id=args.program_id, domain=args.domain))