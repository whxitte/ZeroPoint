"""
ZeroPoint :: ingestor.py
=========================
Module 1 — The Ingestion Engine Orchestrator.

This is the entry point for a full subdomain discovery + ingestion run.
It coordinates:
  1. Loading active programs from MongoDB
  2. Running all recon tools in parallel (Subfinder, crt.sh, Shodan)
  3. Deduplicating and upserting results into MongoDB with state tracking
  4. Dispatching new-asset notifications (Discord / Telegram)
  5. Emitting a structured run summary

Usage:
    # Run against all active programs in DB:
    python ingestor.py

    # Run against a specific program:
    python ingestor.py --program-id hackerone_google

    # Seed the DB with a program first time:
    python ingestor.py --seed-program example.com --program-id my_program

Architecture:
    Programs are processed with a concurrency semaphore (MAX_CONCURRENT_PROGRAMS)
    to avoid hammering all tools against 50 targets simultaneously, which would
    trigger WAF bans and IP blocks — we're optimising for stealth AND speed.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from loguru import logger

import db
from config import settings
from core.alerts import notify_new_assets
from models import Program, ProgramPlatform, ReconResult, ReconSource, UpsertResult
from modules.recon import discover_subdomains


# ---------------------------------------------------------------------------
# Logging setup — structured, rotated, pretty
# ---------------------------------------------------------------------------

def configure_logging() -> None:
    """Set up Loguru with console + rotating file sinks."""
    logger.remove()  # Remove default handler

    # Console — colour-coded, human readable
    logger.add(
        sys.stderr,
        level=settings.LOG_LEVEL,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level:<8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
        backtrace=True,
        diagnose=True,
    )

    # File — JSON-structured for later analysis / grep
    logger.add(
        settings.LOG_FILE,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        compression="gz",
        serialize=False,
        enqueue=True,        # Thread-safe async logging
    )

    logger.info("ZeroPoint Ingestion Engine — logging initialised.")


# ---------------------------------------------------------------------------
# Run Summary — emitted after every execution
# ---------------------------------------------------------------------------

@dataclass
class ProgramRunSummary:
    program_id:       str
    root_domain:      str
    started_at:       datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:      Optional[datetime] = None
    total_discovered: int = 0
    net_new_count:    int = 0
    source_breakdown: Dict[str, int] = field(default_factory=dict)
    errors:           List[str] = field(default_factory=list)
    elapsed_seconds:  float = 0.0

    def finalise(self) -> None:
        self.finished_at = datetime.now(timezone.utc)
        self.elapsed_seconds = (
            self.finished_at - self.started_at
        ).total_seconds()

    def log(self) -> None:
        status = "✅" if not self.errors else "⚠️"
        logger.info(
            f"{status} [{self.program_id}] Run complete | "
            f"discovered={self.total_discovered} | "
            f"net_new={self.net_new_count} | "
            f"elapsed={self.elapsed_seconds:.1f}s | "
            f"breakdown={self.source_breakdown}"
        )
        if self.errors:
            for err in self.errors:
                logger.warning(f"  ↳ Error: {err}")


@dataclass
class EngineRunSummary:
    started_at:    datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    program_count: int = 0
    total_new:     int = 0
    total_found:   int = 0
    failed_programs: List[str] = field(default_factory=list)

    def log(self) -> None:
        elapsed = (datetime.now(timezone.utc) - self.started_at).total_seconds()
        logger.info(
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"  ZeroPoint Run Complete\n"
            f"  Programs processed : {self.program_count}\n"
            f"  Total discovered   : {self.total_found}\n"
            f"  Net new assets     : {self.total_new}\n"
            f"  Failed programs    : {len(self.failed_programs)}\n"
            f"  Total elapsed      : {elapsed:.1f}s\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )


# ---------------------------------------------------------------------------
# Per-program ingestion logic
# ---------------------------------------------------------------------------

async def ingest_program(
    program: Program,
    semaphore: asyncio.Semaphore,
) -> ProgramRunSummary:
    """
    Full ingestion run for a single program.

    Steps:
      1. Acquire semaphore slot (limits concurrent programs)
      2. For each root domain: run all recon tools in parallel
      3. Merge results across domains
      4. Bulk-upsert into MongoDB
      5. Return summary (does NOT trigger notifications — caller handles that)
    """
    summary = ProgramRunSummary(
        program_id=program.program_id,
        root_domain=", ".join(program.domains),
    )

    async with semaphore:
        logger.info(f"{'━' * 60}")
        logger.info(
            f"  Ingestor | program={program.program_id} "
            f"| domains={len(program.domains)}"
        )
        logger.info(f"{'━' * 60}")

        all_upsert_results: List[UpsertResult] = []

        # Run discovery for each root domain in the program scope
        for root_domain in program.domains:
            try:
                recon_results: List[ReconResult] = await discover_subdomains(root_domain)

                for recon_result in recon_results:
                    # Collect errors into summary
                    summary.errors.extend(recon_result.errors)

                    if not recon_result.domains:
                        continue

                    source = recon_result.source
                    summary.source_breakdown[source.value] = (
                        summary.source_breakdown.get(source.value, 0)
                        + len(recon_result.domains)
                    )
                    summary.total_discovered += len(recon_result.domains)

                    # Upsert all discovered domains into MongoDB
                    upsert_results = await db.bulk_upsert_assets(
                        domains=recon_result.domains,
                        program_id=program.program_id,
                        source=source,
                    )
                    all_upsert_results.extend(upsert_results)

            except Exception as exc:
                msg = f"Unhandled error processing {root_domain}: {repr(exc)}"
                logger.error(msg)
                summary.errors.append(msg)

        # Tally net-new assets
        summary.net_new_count = sum(1 for r in all_upsert_results if r.is_new)
        summary.finalise()
        summary.log()

        # Dispatch notifications for new assets discovered in this program
        if all_upsert_results:
            await notify_new_assets(all_upsert_results)

    return summary


# ---------------------------------------------------------------------------
# Engine entry point
# ---------------------------------------------------------------------------

async def run_engine(
    program_id_filter: Optional[str] = None,
) -> EngineRunSummary:
    """
    Main async entry point for the Ingestion Engine.

    1. Ensures DB indexes exist
    2. Loads active programs
    3. Runs all programs concurrently (bounded by semaphore)
    4. Returns engine-level summary
    """
    engine_summary = EngineRunSummary()

    # Ensure MongoDB indexes on every run (idempotent)
    await db.ensure_indexes()

    # Load programs
    programs = await db.list_active_programs()

    if not programs:
        logger.warning(
            "No active programs found in database. "
            "Seed one with: python ingestor.py --seed-program <domain> "
            "--program-id <id>"
        )
        return engine_summary

    # Apply optional filter
    if program_id_filter:
        programs = [p for p in programs if p.program_id == program_id_filter]
        if not programs:
            logger.error(f"No active program found with ID: {program_id_filter}")
            return engine_summary

    engine_summary.program_count = len(programs)
    logger.info(f"[Engine] Processing {len(programs)} active program(s).")

    # Semaphore controls max concurrent program scans
    semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_PROGRAMS)

    # Launch all program ingestion tasks concurrently
    tasks = [ingest_program(p, semaphore) for p in programs]
    program_summaries: List[ProgramRunSummary] = await asyncio.gather(
        *tasks, return_exceptions=False
    )

    # Aggregate engine-level totals
    for ps in program_summaries:
        engine_summary.total_found += ps.total_discovered
        engine_summary.total_new   += ps.net_new_count
        if ps.errors:
            engine_summary.failed_programs.append(ps.program_id)

    engine_summary.log()
    return engine_summary


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

async def seed_program(
    program_id: str,
    domain: str,
    platform: str = "private",
    name: Optional[str] = None,
) -> None:
    """Seed a new program into MongoDB for first-time setup."""
    await db.ensure_indexes()

    try:
        plat = ProgramPlatform(platform)
    except ValueError:
        plat = ProgramPlatform.PRIVATE

    program = Program(
        program_id=program_id,
        name=name or program_id,
        platform=plat,
        domains=[domain],
    )
    await db.upsert_program(program)
    total = await db.count_assets_for_program(program_id)
    logger.success(
        f"Program '{program_id}' seeded with domain '{domain}'. "
        f"Existing assets in DB: {total}"
    )


# ---------------------------------------------------------------------------
# __main__
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ZeroPoint — Ingestion Engine (Module 1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run against all active programs:
  python ingestor.py

  # Run against a single program:
  python ingestor.py --program-id hackerone_acme

  # Seed a new program and run it immediately:
  python ingestor.py --seed-program example.com --program-id acme_corp --run-after-seed
        """,
    )
    parser.add_argument(
        "--program-id",
        type=str,
        default=None,
        help="Only process this specific program ID",
    )
    parser.add_argument(
        "--seed-program",
        type=str,
        default=None,
        metavar="DOMAIN",
        help="Seed a new program with this root domain",
    )
    parser.add_argument(
        "--program-name",
        type=str,
        default=None,
        help="Human-readable name for the seeded program",
    )
    parser.add_argument(
        "--platform",
        type=str,
        default="private",
        choices=[p.value for p in ProgramPlatform],
        help="Bug bounty platform for the seeded program",
    )
    parser.add_argument(
        "--run-after-seed",
        action="store_true",
        help="Immediately run ingestion after seeding",
    )
    return parser.parse_args()


async def main() -> None:
    configure_logging()
    args = parse_args()

    try:
        # Seed mode
        if args.seed_program:
            prog_id = args.program_id or args.seed_program.replace(".", "_")
            await seed_program(
                program_id=prog_id,
                domain=args.seed_program,
                platform=args.platform,
                name=args.program_name,
            )
            if not args.run_after_seed:
                logger.info("Seeding complete. Run without --seed-program to start ingestion.")
                return
            # Fall through to run engine against the newly seeded program
            args.program_id = prog_id

        # Main ingestion run
        await run_engine(program_id_filter=args.program_id)

    finally:
        await db.close_connection()


if __name__ == "__main__":
    asyncio.run(main())