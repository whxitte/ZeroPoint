"""
ZeroPoint :: google_dork.py
============================
Module 8 Orchestrator — Google Dork Engine.

Changes vs previous version:
  - FIX: run.queries_run += 1 → run.queries_run += 1  (Qwen bug #3)
  - NEW: dork→asset pipeline integration — when a dork result exposes a new
         subdomain of the target domain, upsert it into the assets collection
         so Module 2/3/4 can pick it up on the next cycle. This is how
         quipo-dev-test.quipohealth.com would have been auto-added.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

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
from models import DorkScanRun, DorkSeverity, ReconSource
from modules.dorker import build_dorker


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
# Dork → Asset pipeline integration
# ─────────────────────────────────────────────────────────────────────────────

def _extract_subdomain(url: str, root_domain: str) -> Optional[str]:
    """
    Extract subdomain from a dork result URL if it belongs to root_domain.

    Examples:
      "https://quipo-dev-test.quipohealth.com/" + "quipohealth.com"
        → "quipo-dev-test.quipohealth.com"
      "https://quipohealth.com/login" + "quipohealth.com"
        → None  (apex domain, not a subdomain)
      "https://evil.com/" + "quipohealth.com"
        → None  (out of scope)
    """
    try:
        host = urlparse(url.lower()).netloc.split(":")[0].strip()
        if not host:
            return None
        # Must be a proper subdomain (not the apex itself)
        if host == root_domain:
            return None
        if host.endswith(f".{root_domain}"):
            return host
        return None
    except Exception:
        return None


async def _inject_dork_subdomains_into_assets(
    dork_url:   str,
    root_domain: str,
    program_id:  str,
) -> bool:
    """
    If the dork result URL contains a new subdomain of root_domain,
    upsert it into the assets collection so the pipeline can process it.

    Returns True if a new asset was injected.
    """
    subdomain = _extract_subdomain(dork_url, root_domain)
    if not subdomain:
        return False

    try:
        result = await mongo_ops.upsert_asset(
            domain       = subdomain,
            program_id   = program_id,
            source       = ReconSource.UNKNOWN,   # special source tag
            ip_addresses = [],
        )
        # Override source label for clarity in DB
        col = mongo_ops.get_assets_col()
        await col.update_one(
            {"domain": subdomain},
            {"$addToSet": {"sources": "dork"}},
        )
        if result.is_new:
            logger.success(
                f"[dork→asset] NEW subdomain injected into assets: "
                f"{subdomain} (from dork result {dork_url[:60]})"
            )
        return result.is_new
    except Exception as exc:
        logger.warning(f"[dork→asset] Failed to inject {subdomain}: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-program dork scan
# ─────────────────────────────────────────────────────────────────────────────

async def dork_program(
    program_id: str,
    dorker,
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
    injected_count: int       = 0

    for domain in program.domains:
        logger.info(f"[dork] Scanning domain: {domain}")

        async for result in dorker.dork(
            domain     = domain,
            program_id = program_id,
            run_id     = run.run_id,
            tenant_id  = tenant_id,
        ):
            run.results_raw  += 1
            run.queries_run  += 1   # FIX: was `= 1` (never incremented past 1)

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

                # NEW: inject newly discovered subdomains into assets pipeline
                injected = await _inject_dork_subdomains_into_assets(
                    result.url, domain, program_id
                )
                if injected:
                    injected_count += 1

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
        f"raw={run.results_raw} new={run.new_findings} "
        f"injected_assets={injected_count} elapsed={elapsed:.1f}s | "
        f"🚨crit={sev_counter.get('critical', 0)} "
        f"🔴high={sev_counter.get('high', 0)} "
        f"🟡med={sev_counter.get('medium', 0)}"
    )
    return run


# ─────────────────────────────────────────────────────────────────────────────
# All-programs orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def dork_all_programs(dorker) -> List[DorkScanRun]:
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
    dorker = _build_dorker()
    if not dorker:
        logger.error(
            "[dork] No search API key configured. Add one of:\n"
            "  BRAVE_SEARCH_API_KEY=BSA...  (recommended)\n"
            "  OR  SERPAPI_KEY=...          (100 free/month, no card)\n"
            "  OR  GOOGLE_API_KEY=AIza... + GOOGLE_CSE_ID=abc..."
        )
        return

    print(f"\n  {'━' * 56}")
    print(f"  Google Dork: {domain}")
    print(f"  {'━' * 56}\n")

    count = 0
    async for result in dorker.dork(domain, "__test__", "test_run"):
        count += 1
        sev = result.severity.value
        sub = _extract_subdomain(result.url, domain)
        sub_tag = f"  ⚡ New subdomain: {sub}" if sub else ""
        print(f"  [{sev.upper():8}]  [{result.dork_category}]{sub_tag}")
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


def _build_dorker():
    """Auto-select backend: Brave → SerpAPI → Google (whichever key is set)."""
    return build_dorker(
        brave_key   = settings.BRAVE_SEARCH_API_KEY,
        serpapi_key = settings.SERPAPI_KEY,
        google_key  = settings.GOOGLE_API_KEY,
        google_cse  = settings.GOOGLE_CSE_ID,
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

    dorker = _build_dorker()
    if not dorker:
        logger.error(
            "[dork] No search API key configured. Add ONE to .env:\n"
            "\n"
            "  Option A — SerpAPI (100 free/month, NO credit card):\n"
            "    SERPAPI_KEY=...\n"
            "    Sign up: https://serpapi.com/users/sign_up\n"
            "\n"
            "  Option B — Brave Search ($5 free credits/month, needs card):\n"
            "    BRAVE_SEARCH_API_KEY=BSA...\n"
            "    Sign up: https://api.search.brave.com/app/dashboard\n"
            "\n"
            "  Option C — Google Custom Search (100 free/day, needs billing linked):\n"
            "    GOOGLE_API_KEY=AIza... + GOOGLE_CSE_ID=abc...\n"
            "    Billing fix: console.cloud.google.com/billing"
        )
        sys.exit(1)

    if domain:
        await dork_single_domain(domain)
        return

    await mongo_ops.ensure_indexes()
    await ensure_dork_indexes()

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
