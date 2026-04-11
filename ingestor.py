"""
ZeroPoint :: ingestor.py
=========================
Module 1 — The Ingestion Engine Orchestrator.

Changes vs previous version:
  - NEW: Optional Module 1b — Subdomain Permutation via dnsgen + massdns
         Enabled by PERMUTATION_ENABLED=true in .env
         Runs *after* passive recon so dnsgen has the full seed list to work from

This is the entry point for a full subdomain discovery + ingestion run.
It coordinates:
  1. Loading active programs from MongoDB
  2. Running all recon tools in parallel (Subfinder, crt.sh, Shodan)
  3. [Optional] Running permutation on the collected seeds (dnsgen + massdns)
  4. Deduplicating and upserting results into MongoDB with state tracking
  5. Dispatching new-asset notifications (Discord / Telegram)
  6. Emitting a structured run summary

Usage:
    python ingestor.py                              # all active programs
    python ingestor.py --program-id hackerone_google
    python ingestor.py --seed-program example.com --program-id my_program
    python ingestor.py --permute                    # force permutation even if disabled in .env
    python ingestor.py --no-permute                 # skip permutation even if enabled in .env
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
# Logging setup
# ---------------------------------------------------------------------------

def configure_logging() -> None:
    logger.remove()
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
    logger.add(
        settings.LOG_FILE,
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        compression="gz",
        serialize=False,
        enqueue=True,
    )
    logger.info("ZeroPoint Ingestion Engine — logging initialised.")


# ---------------------------------------------------------------------------
# Run Summaries
# ---------------------------------------------------------------------------

@dataclass
class ProgramRunSummary:
    program_id:       str
    root_domain:      str
    started_at:       datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:      Optional[datetime] = None
    total_discovered: int = 0
    net_new_count:    int = 0
    permutation_new:  int = 0   # NEW: subdomains found via permutation
    source_breakdown: Dict[str, int] = field(default_factory=dict)
    errors:           List[str] = field(default_factory=list)
    elapsed_seconds:  float = 0.0

    def finalise(self) -> None:
        self.finished_at = datetime.now(timezone.utc)
        self.elapsed_seconds = (self.finished_at - self.started_at).total_seconds()

    def log(self) -> None:
        status = "✅" if not self.errors else "⚠️"
        perm_note = f" | permutation_new={self.permutation_new}" if self.permutation_new else ""
        logger.info(
            f"{status} [{self.program_id}] Run complete | "
            f"discovered={self.total_discovered} | "
            f"net_new={self.net_new_count}{perm_note} | "
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
# Permutation helper
# ---------------------------------------------------------------------------

async def _run_permutation(
    program_id:  str,
    root_domain: str,
    summary:     ProgramRunSummary,
) -> List[UpsertResult]:
    """
    Run Module 1b — permutation — using existing assets as seeds.
    Returns list of UpsertResult for new assets found by permutation.
    """
    from modules.permutation import PermutationWorker

    # Fetch existing subdomains from DB as seeds
    existing = await db.get_new_assets_since.__wrapped__ if hasattr(
        db.get_new_assets_since, '__wrapped__'
    ) else None

    # Use the assets collection directly for a broader seed list
    from db.mongo import get_assets_col
    col = get_assets_col()
    seeds: List[str] = []
    async for doc in col.find(
        {"program_id": program_id},
        {"domain": 1, "_id": 0}
    ).limit(5000):
        seeds.append(doc["domain"])

    if len(seeds) < 3:
        logger.info(f"[permutation] Too few seeds ({len(seeds)}) — skipping. Run ingest first.")
        return []

    logger.info(
        f"[permutation] Starting permutation | "
        f"seeds={len(seeds)} | root={root_domain}"
    )

    worker = PermutationWorker(
        massdns_binary = getattr(settings, "MASSDNS_PATH", "massdns"),
        massdns_rate   = getattr(settings, "PERMUTATION_RATE", 5000),
        wordlist       = getattr(settings, "PERMUTATION_WORDLIST", ""),
        max_candidates = getattr(settings, "PERMUTATION_MAX_CANDIDATES", 500_000),
    )

    perm_results: List[UpsertResult] = []
    async for new_domain in worker.permute(seeds, root_domain):
        try:
            result = await db.upsert_asset(
                domain     = new_domain,
                program_id = program_id,
                source     = ReconSource.UNKNOWN,  # source=permutation label
            )
            # Tag with permutation source
            from db.mongo import get_assets_col as _col
            await _col().update_one(
                {"domain": new_domain},
                {"$addToSet": {"sources": "permutation"}},
            )
            perm_results.append(result)
        except Exception as exc:
            logger.warning(f"[permutation] DB upsert failed for {new_domain}: {exc}")

    new_perm = sum(1 for r in perm_results if r.is_new)
    summary.permutation_new  += new_perm
    summary.total_discovered += len(perm_results)
    summary.source_breakdown["permutation"] = len(perm_results)

    logger.success(
        f"[permutation] ✓ {root_domain} | "
        f"found={len(perm_results)} new={new_perm}"
    )
    return perm_results


# ---------------------------------------------------------------------------
# Per-program ingestion logic
# ---------------------------------------------------------------------------

async def ingest_program(
    program:    Program,
    semaphore:  asyncio.Semaphore,
    run_permutation: bool = False,
) -> ProgramRunSummary:
    """
    Full ingestion run for a single program.

    Steps:
      1. Acquire semaphore slot
      2. For each root domain: run all recon tools in parallel
      3. [Optional] Run permutation on collected seeds
      4. Bulk-upsert into MongoDB
      5. Return summary
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

        # Passive recon for each root domain
        for root_domain in program.domains:
            try:
                recon_results: List[ReconResult] = await discover_subdomains(root_domain)

                for recon_result in recon_results:
                    summary.errors.extend(recon_result.errors)

                    if not recon_result.domains:
                        continue

                    source = recon_result.source
                    summary.source_breakdown[source.value] = (
                        summary.source_breakdown.get(source.value, 0)
                        + len(recon_result.domains)
                    )
                    summary.total_discovered += len(recon_result.domains)

                    upsert_results = await db.bulk_upsert_assets(
                        domains    = recon_result.domains,
                        program_id = program.program_id,
                        source     = source,
                    )
                    all_upsert_results.extend(upsert_results)

            except Exception as exc:
                msg = f"Unhandled error processing {root_domain}: {repr(exc)}"
                logger.error(msg)
                summary.errors.append(msg)

        # Optional permutation phase
        if run_permutation:
            for root_domain in program.domains:
                try:
                    perm_results = await _run_permutation(
                        program.program_id, root_domain, summary
                    )
                    all_upsert_results.extend(perm_results)
                except Exception as exc:
                    msg = f"Permutation error for {root_domain}: {repr(exc)}"
                    logger.error(msg)
                    summary.errors.append(msg)

        summary.net_new_count = sum(1 for r in all_upsert_results if r.is_new)
        summary.finalise()
        summary.log()

        if all_upsert_results:
            await notify_new_assets(all_upsert_results)

    return summary


# ---------------------------------------------------------------------------
# Engine entry point
# ---------------------------------------------------------------------------

async def run_engine(
    program_id_filter: Optional[str] = None,
    run_permutation:   bool          = False,
) -> EngineRunSummary:
    engine_summary = EngineRunSummary()

    await db.ensure_indexes()

    programs = await db.list_active_programs()

    if not programs:
        logger.warning(
            "No active programs found in database. "
            "Seed one with: python ingestor.py --seed-program <domain> --program-id <id>"
        )
        return engine_summary

    if program_id_filter:
        programs = [p for p in programs if p.program_id == program_id_filter]
        if not programs:
            logger.error(f"No active program found with ID: {program_id_filter}")
            return engine_summary

    engine_summary.program_count = len(programs)
    logger.info(f"[Engine] Processing {len(programs)} active program(s).")

    # Check permutation availability early
    if run_permutation:
        import shutil
        massdns_bin = getattr(settings, "MASSDNS_PATH", "massdns")
        if not shutil.which(massdns_bin):
            logger.error(
                f"[permutation] massdns not found at '{massdns_bin}'.\n"
                "  Install: go install github.com/blechschmidt/massdns/cmd/massdns@latest\n"
                "  Disabling permutation for this run."
            )
            run_permutation = False
        try:
            import dnsgen  # noqa: F401
        except ImportError:
            logger.error(
                "[permutation] dnsgen not installed.\n"
                "  Install: pip install dnsgen\n"
                "  Disabling permutation for this run."
            )
            run_permutation = False

    semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_PROGRAMS)
    tasks     = [
        ingest_program(p, semaphore, run_permutation=run_permutation)
        for p in programs
    ]
    program_summaries: List[ProgramRunSummary] = await asyncio.gather(
        *tasks, return_exceptions=False
    )

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
    domain:     str,
    platform:   str           = "private",
    name:       Optional[str] = None,
) -> None:
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
  # Run passive recon only:
  python ingestor.py

  # Run passive recon + permutation:
  python ingestor.py --permute

  # Single program with permutation:
  python ingestor.py --program-id quipo --permute

  # Seed and run immediately:
  python ingestor.py --seed-program example.com --program-id acme_corp --run-after-seed
        """,
    )
    parser.add_argument("--program-id",    type=str, default=None)
    parser.add_argument("--seed-program",  type=str, default=None, metavar="DOMAIN")
    parser.add_argument("--program-name",  type=str, default=None)
    parser.add_argument(
        "--platform",
        type=str,
        default="private",
        choices=[p.value for p in ProgramPlatform],
    )
    parser.add_argument("--run-after-seed", action="store_true")
    parser.add_argument(
        "--permute",
        action="store_true",
        default=False,
        help="Run subdomain permutation (dnsgen + massdns) after passive recon",
    )
    parser.add_argument(
        "--no-permute",
        action="store_true",
        default=False,
        help="Skip permutation even if PERMUTATION_ENABLED=true in .env",
    )
    return parser.parse_args()


async def main() -> None:
    configure_logging()
    args = parse_args()

    # Determine if permutation should run
    env_permute = getattr(settings, "PERMUTATION_ENABLED", False)
    run_perm    = (args.permute or env_permute) and not args.no_permute

    try:
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
            args.program_id = prog_id

        await run_engine(
            program_id_filter=args.program_id,
            run_permutation=run_perm,
        )

    finally:
        await logger.complete()   # flush loguru's enqueued file sink before exit
        await db.close_connection()


if __name__ == "__main__":
    asyncio.run(main())
