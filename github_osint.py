"""
ZeroPoint :: github_osint.py
=============================
Module 6 Orchestrator — GitHub OSINT Engine.

Searches public GitHub repositories for leaked credentials, API keys,
database connection strings, and other sensitive references belonging
to your target programs.

Why this matters:
  Developers accidentally push .env files, hardcoded passwords, and
  production credentials to public repos all the time. Some programs
  pay $5,000–$25,000 for a critical credential leak found this way.
  This module finds them automatically before anyone else does.

Pipeline per program:
  1. Load program's root domains from DB
  2. For each domain: run all 40+ GitHub dork queries
  3. For each result: extract and score the matched secret
  4. Upsert to `github_leaks` collection (SHA-256 dedup)
  5. Alert immediately on every new unique leak
  6. Save run audit record

Usage:
    python3 github_osint.py --program-id shopify_h1
    python3 github_osint.py                          # all active programs
    python3 github_osint.py --domain shopify.com     # quick single-domain test
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
from core.alerts import notify_github_leak, notify_github_summary
from db.github_ops import (
    ensure_github_indexes,
    mark_leaks_notified,
    save_github_run,
    upsert_leak,
)
from models import GitHubOSINTRun
from modules.github_osint import GitHubOSINTScanner


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
        settings.LOG_FILE.replace(".log", "_github.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Per-program scan
# ─────────────────────────────────────────────────────────────────────────────

async def scan_program(
    program_id: str,
    scanner:    GitHubOSINTScanner,
    tenant_id:  str = "default",
) -> GitHubOSINTRun:
    """Run GitHub OSINT for all domains in one program."""
    run = GitHubOSINTRun(
        run_id     = uuid.uuid4().hex,
        program_id = program_id,
        started_at = datetime.now(timezone.utc),
    )
    await save_github_run(run)

    logger.info(f"{'━' * 60}")
    logger.info(f"  GitHub OSINT | program={program_id} | run_id={run.run_id}")
    logger.info(f"{'━' * 60}")

    program = await mongo_ops.get_program(program_id)
    if not program:
        logger.error(f"[github] Program '{program_id}' not found in DB")
        run.finished_at = datetime.now(timezone.utc)
        run.success     = False
        run.errors.append(f"Program '{program_id}' not found")
        await save_github_run(run)
        return run

    new_leak_ids: List[str] = []
    sev_counter:  Counter   = Counter()

    for domain in program.domains:
        logger.info(f"[github] Scanning domain: {domain}")

        async for leak in scanner.scan(
            domain     = domain,
            program_id = program_id,
            run_id     = run.run_id,
            tenant_id  = tenant_id,
        ):
            run.results_raw += 1
            run.queries_run += 1

            try:
                is_new = await upsert_leak(leak)
            except Exception as exc:
                logger.error(f"[github] DB write failed: {exc}")
                run.errors.append(str(exc))
                continue

            if is_new:
                run.new_leaks += 1
                sev_key = leak.severity.value if hasattr(leak.severity, "value") else str(leak.severity)
                sev_counter[sev_key] += 1
                new_leak_ids.append(leak.leak_id)
                await notify_github_leak(leak, program_id)

    # Flip is_new=False after all alerts dispatched
    if new_leak_ids:
        await mark_leaks_notified(new_leak_ids)

    # Summary alert
    await notify_github_summary(
        program_id  = program_id,
        new_leaks   = run.new_leaks,
        by_severity = dict(sev_counter),
        run_id      = run.run_id,
    )

    run.finished_at = datetime.now(timezone.utc)
    run.success     = len(run.errors) == 0
    await save_github_run(run)

    elapsed = (run.finished_at - run.started_at).total_seconds()
    logger.success(
        f"[github] ✓ {program_id} | "
        f"raw={run.results_raw} new_leaks={run.new_leaks} elapsed={elapsed:.1f}s | "
        f"🔑crit={sev_counter.get('critical',0)} "
        f"🔐high={sev_counter.get('high',0)}"
    )
    return run


# ─────────────────────────────────────────────────────────────────────────────
# All-programs orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def scan_all_programs(scanner: GitHubOSINTScanner) -> List[GitHubOSINTRun]:
    programs = await mongo_ops.list_active_programs()
    if not programs:
        logger.warning("[github] No active programs in DB.")
        return []

    logger.info(f"[github] Starting GitHub OSINT for {len(programs)} program(s)")
    runs = []
    for program in programs:
        try:
            run = await scan_program(program.program_id, scanner)
            runs.append(run)
        except Exception as exc:
            logger.exception(f"[github] Fatal error on {program.program_id}: {exc}")

    return runs


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-domain test (no DB write)
# ─────────────────────────────────────────────────────────────────────────────

async def scan_single_domain(domain: str) -> None:
    """Dev/debug — scan one domain, print results, no DB write."""
    if not settings.GITHUB_TOKEN:
        logger.error(
            "[github] GITHUB_TOKEN not set. GitHub OSINT requires an API token.\n"
            "  1. Go to https://github.com/settings/tokens\n"
            "  2. Generate a token with 'public_repo' read scope\n"
            "  3. Add GITHUB_TOKEN=your_token to .env"
        )
        return

    scanner = GitHubOSINTScanner(
        github_token = settings.GITHUB_TOKEN,
        max_results  = settings.GITHUB_OSINT_MAX_RESULTS,
        rate_delay   = settings.GITHUB_OSINT_RATE_DELAY,
    )

    print(f"\n  {'━' * 56}")
    print(f"  GitHub OSINT: {domain}")
    print(f"  {'━' * 56}\n")

    count = 0
    async for leak in scanner.scan(domain, "__test__", "test_run"):
        count += 1
        sev = leak.severity.value if hasattr(leak.severity, "value") else str(leak.severity)
        val = leak.match_value
        safe = (val[:6] + "..." + val[-4:]) if len(val) > 12 else val[:4] + "..."
        print(f"  [{sev.upper():8}]  {leak.match_type:25}  {safe}")
        print(f"             Repo: {leak.repo_full_name}")
        print(f"             File: {leak.file_path}")
        print(f"             URL:  {leak.file_url[:100]}")
        if leak.match_context:
            print(f"          Context: {leak.match_context[:100]}")
        print()

    if count == 0:
        print(f"  No leaks found for {domain}")
    else:
        print(f"\n  Total: {count} potential leak(s) found")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    program_id: Optional[str] = None,
    domain:     Optional[str] = None,
) -> None:
    configure_logging()

    logger.info("=" * 60)
    logger.info("  ZeroPoint GitHub OSINT — Module 6 Starting")
    logger.info("=" * 60)

    if not settings.GITHUB_TOKEN:
        logger.error(
            "[github] GITHUB_TOKEN not configured. "
            "Add it to your .env file. "
            "Generate at: https://github.com/settings/tokens (public_repo scope)"
        )
        sys.exit(1)

    if domain:
        await scan_single_domain(domain)
        return

    await mongo_ops.ensure_indexes()
    await ensure_github_indexes()

    scanner = GitHubOSINTScanner(
        github_token = settings.GITHUB_TOKEN,
        max_results  = settings.GITHUB_OSINT_MAX_RESULTS,
        rate_delay   = settings.GITHUB_OSINT_RATE_DELAY,
    )

    try:
        if program_id:
            run = await scan_program(program_id, scanner)
            logger.success(f"[github] Done | new_leaks={run.new_leaks}")
        else:
            runs = await scan_all_programs(scanner)
            total = sum(r.new_leaks for r in runs)
            logger.success(f"[github] All programs done | runs={len(runs)} total_new_leaks={total}")

    except KeyboardInterrupt:
        logger.warning("[github] Interrupted")
    except Exception as exc:
        logger.exception(f"[github] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[github] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint GitHub OSINT — leaked credential scanner"
    )
    parser.add_argument("--program-id", type=str, default=None)
    parser.add_argument(
        "--domain", type=str, default=None,
        help="Quick-scan a single domain (no DB write). For testing.",
    )
    args = parser.parse_args()
    asyncio.run(main(program_id=args.program_id, domain=args.domain))