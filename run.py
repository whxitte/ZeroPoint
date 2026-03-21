"""
ZeroPoint :: run.py
====================
Module 5 — Pipeline Orchestrator.

The single entrypoint that chains all four modules in the correct order:
    Module 1 → Ingestion   (find subdomains)
    Module 2 → Prober      (HTTP probe + fingerprint)
    Module 3 → Scanner     (Nuclei vuln scan)
    Module 4 → Crawler     (endpoint discovery + JS secrets)

Two operating modes:

  MANUAL — Run once, now, against a specific program or all programs:
      python3 run.py --program-id shopify_h1
      python3 run.py                              # all active programs
      python3 run.py --modules ingest,probe       # specific modules only
      python3 run.py --program-id shopify_h1 --force

  AUTO (daemon) — Run continuously on a schedule, 24/7:
      python3 run.py --daemon
      python3 run.py --daemon --program-id shopify_h1

  Both modes support:
      --skip-modules scan,crawl   # skip specific modules this run
      --only-new                  # only process assets with is_new=True
      --dry-run                   # print what would run, don't execute

Pipeline design:
  Each module is imported directly and its per-program function called.
  No subprocess spawning — all four modules run in the same Python process,
  sharing the same event loop and MongoDB connection pool.
  This means:
    - Zero process startup overhead between modules
    - Shared asyncio semaphores prevent resource contention
    - A single unified log stream across all modules
    - Ctrl+C cleanly cancels the entire pipeline

Schedule defaults (tuned for first-come-first-served advantage):
  Ingestion  — every 1 hour   (catch new subdomains fast)
  Probe      — every 2 hours  (fingerprint anything new)
  Scanner    — every 6 hours  (targeted Nuclei on HIGH/CRITICAL)
  Crawler    — every 12 hours (deep crawl + JS analysis)
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from loguru import logger

import db.mongo as mongo_ops
from config import settings
from db.crawler_ops import ensure_crawler_indexes
from db.github_ops import ensure_github_indexes
from db.scanner_ops import ensure_scanner_indexes


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline stage definitions
# ─────────────────────────────────────────────────────────────────────────────

ALL_MODULES = ["ingest", "probe", "scan", "crawl", "github", "portscan", "dork", "asn"]

MODULE_LABELS = {
    "ingest":   "Module 1 \u2014 Ingestion",
    "probe":    "Module 2 \u2014 Prober",
    "scan":     "Module 3 \u2014 Scanner",
    "crawl":    "Module 4 \u2014 Crawler",
    "github":   "Module 6 \u2014 GitHub OSINT",
    "portscan": "Module 7 \u2014 Port Scanner",
    "dork":     "Module 8 \u2014 Google Dork Engine",
}

# Default schedule intervals in seconds
DEFAULT_INTERVALS = {
    "ingest":   3600,    # 1 hour
    "probe":    7200,    # 2 hours
    "scan":     21600,   # 6 hours
    "crawl":    43200,   # 12 hours
    "github":   21600,   # 6 hours  (GitHub rate limit: 30 req/min auth)
    "portscan": 86400,   # 24 hours (port scan daily)
    "dork":     86400,   # 24 hours (Google CSE: 100 free queries/day)
    "asn":      86400,   # 24 hours (IP ranges change infrequently)
}



# ─────────────────────────────────────────────────────────────────────────────
# Run result tracking
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModuleResult:
    """Outcome of a single module run."""
    module:     str
    program_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    success:    bool = True
    error:      Optional[str] = None
    stats:      Dict = field(default_factory=dict)

    @property
    def elapsed_seconds(self) -> float:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0


@dataclass
class PipelineResult:
    """Full pipeline run outcome for one program."""
    program_id:  str
    started_at:  datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    modules_run: List[ModuleResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(r.success for r in self.modules_run)

    @property
    def elapsed_seconds(self) -> float:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0

    def summary_line(self) -> str:
        statuses = " → ".join(
            f"{'✓' if r.success else '✗'} {r.module} ({r.elapsed_seconds:.0f}s)"
            for r in self.modules_run
        )
        total = f"{self.elapsed_seconds:.0f}s total"
        return f"[{self.program_id}] {statuses} | {total}"


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
        settings.LOG_FILE.replace(".log", "_orchestrator.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Per-module runners — lazy import to keep startup fast
# ─────────────────────────────────────────────────────────────────────────────

async def run_ingest(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 1 (Ingestion) for one program."""
    result = ModuleResult(module="ingest", program_id=program_id)
    try:
        from ingestor import ingest_program

        logger.info(f"[orchestrator] ▶ ingest | program={program_id}")

        programs = await mongo_ops.list_active_programs()
        target   = next((p for p in programs if p.program_id == program_id), None)

        if target is None:
            raise ValueError(f"Program '{program_id}' not found in DB. Run seed_programs.py first.")

        semaphore = asyncio.Semaphore(1)
        summary   = await ingest_program(target, semaphore)

        result.stats = {
            "new_assets":   summary.net_new_count,
            "total_assets": summary.total_discovered,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] ingest FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result


async def run_probe(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 2 (Prober) for one program."""
    result = ModuleResult(module="probe", program_id=program_id)
    try:
        from prober import probe_program
        from modules.prober import HttpxProber

        logger.info(f"[orchestrator] ▶ probe | program={program_id}")

        # Build the prober directly from settings — avoids depending on
        # a private function (_build_prober) that may differ across versions
        prober = HttpxProber(
            binary_path      = settings.HTTPX_PATH,
            threads          = settings.PROBER_THREADS,
            rate_limit       = settings.PROBER_RATE_LIMIT,
            timeout          = settings.PROBER_TIMEOUT,
            retries          = settings.PROBER_RETRIES,
            follow_redirects = settings.PROBER_FOLLOW_REDIRECTS,
            screenshot       = settings.PROBER_SCREENSHOT,
            screenshot_dir   = settings.PROBER_SCREENSHOT_DIR,
        )
        stats = await probe_program(
            program_id    = program_id,
            prober        = prober,
            force_reprobe = force,
        )
        result.stats = stats

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] probe FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result


async def run_scan(
    program_id: str,
    force:      bool          = False,
    severity:   Optional[str] = None,
) -> ModuleResult:
    """Run Module 3 (Scanner) for one program."""
    result = ModuleResult(module="scan", program_id=program_id)
    try:
        from scanner import scan_program, _build_scanner

        logger.info(f"[orchestrator] ▶ scan | program={program_id}")

        scanner     = _build_scanner(severity)
        scan_run    = await scan_program(
            program_id        = program_id,
            scanner           = scanner,
            force             = force,
            severity_override = severity,
        )
        result.stats = {
            "targets":      scan_run.targets,
            "findings":     scan_run.findings,
            "new_findings": scan_run.new_findings,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] scan FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result


async def run_crawl(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 4 (Crawler) for one program."""
    result = ModuleResult(module="crawl", program_id=program_id)
    try:
        from crawler import crawl_program

        logger.info(f"[orchestrator] ▶ crawl | program={program_id}")

        crawl_run = await crawl_program(
            program_id = program_id,
            force      = force,
        )
        result.stats = {
            "endpoints_found": crawl_run.endpoints_found,
            "new_endpoints":   crawl_run.new_endpoints,
            "new_secrets":     crawl_run.new_secrets,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] crawl FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result


async def run_github(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 6 (GitHub OSINT) for one program."""
    result = ModuleResult(module="github", program_id=program_id)
    try:
        from github_osint import scan_program as github_scan_program
        from modules.github_osint import GitHubOSINTScanner

        if not settings.GITHUB_TOKEN:
            logger.warning(
                "[orchestrator] GITHUB_TOKEN not set — skipping GitHub OSINT. "
                "Add it to .env to enable."
            )
            result.stats = {"skipped": True, "reason": "GITHUB_TOKEN not configured"}
            result.finished_at = datetime.now(timezone.utc)
            return result

        logger.info(f"[orchestrator] ▶ github | program={program_id}")

        scanner = GitHubOSINTScanner(
            github_token = settings.GITHUB_TOKEN,
            max_results  = settings.GITHUB_OSINT_MAX_RESULTS,
            rate_delay   = settings.GITHUB_OSINT_RATE_DELAY,
        )
        run = await github_scan_program(program_id, scanner)
        result.stats = {
            "new_leaks":   run.new_leaks,
            "results_raw": run.results_raw,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] github FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result


async def run_portscan(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 7 (Port Scanner) for one program."""
    result = ModuleResult(module="portscan", program_id=program_id)
    try:
        from port_scanner import scan_program as portscan_scan_program, _build_scanner
        from db.portscan_ops import ensure_portscan_indexes

        await ensure_portscan_indexes()

        logger.info(f"[orchestrator] ▶ portscan | program={program_id}")
        scanner = _build_scanner()
        run     = await portscan_scan_program(program_id, scanner)
        result.stats = {
            "targets":      run.targets,
            "ports_found":  run.ports_found,
            "new_findings": run.new_findings,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] portscan FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result



async def run_dork(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 8 (Google Dork Engine) for one program."""
    result = ModuleResult(module="dork", program_id=program_id)
    try:
        from google_dork import dork_program, _build_dorker
        from db.dork_ops import ensure_dork_indexes

        if not settings.GOOGLE_API_KEY or not settings.GOOGLE_CSE_ID:
            logger.warning(
                "[orchestrator] GOOGLE_API_KEY or GOOGLE_CSE_ID not set — skipping dork. "
                "Add both to .env to enable Module 8."
            )
            result.stats      = {"skipped": True, "reason": "Google API credentials not configured"}
            result.finished_at = datetime.now(timezone.utc)
            return result

        await ensure_dork_indexes()
        logger.info(f"[orchestrator] ▶ dork | program={program_id}")
        dorker = _build_dorker()
        run    = await dork_program(program_id, dorker)
        result.stats = {
            "new_findings": run.new_findings,
            "results_raw":  run.results_raw,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] dork FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result



async def run_asn(program_id: str, force: bool = False) -> ModuleResult:
    """Run Module 9 (ASN Mapper) for one program."""
    result = ModuleResult(module="asn", program_id=program_id)
    try:
        from asn_mapper import map_program, _build_mapper
        from db.asn_ops import ensure_asn_indexes

        await ensure_asn_indexes()
        logger.info(f"[orchestrator] ▶ asn | program={program_id}")
        mapper = _build_mapper()
        run    = await map_program(program_id, mapper)
        result.stats = {
            "asns_found":    run.asns_found,
            "prefixes_found": run.prefixes_found,
        }

    except Exception as exc:
        result.success = False
        result.error   = str(exc)
        logger.error(f"[orchestrator] asn FAILED for {program_id}: {exc}")
    finally:
        result.finished_at = datetime.now(timezone.utc)

    return result


# Dispatch table — maps module name → runner function
MODULE_RUNNERS = {
    "ingest":   run_ingest,
    "probe":    run_probe,
    "scan":     run_scan,
    "crawl":    run_crawl,
    "github":   run_github,
    "portscan": run_portscan,
    "dork":     run_dork,
    "asn":      run_asn,
}


# ─────────────────────────────────────────────────────────────────────────────
# Full pipeline for one program
# ─────────────────────────────────────────────────────────────────────────────

async def run_pipeline(
    program_id:     str,
    modules:        List[str]     = ALL_MODULES,
    force:          bool          = False,
    severity:       Optional[str] = None,
    dry_run:        bool          = False,
    stop_on_error:  bool          = False,
) -> PipelineResult:
    """
    Run the full ZeroPoint pipeline for one program.

    Modules execute sequentially — each stage feeds the next:
      ingest → populates assets
      probe  → enriches assets with http data + interest_level
      scan   → runs Nuclei on HIGH/CRITICAL assets
      crawl  → discovers endpoints + JS secrets on MEDIUM+ assets

    Args:
        modules:       Which modules to run (default: all four)
        force:         Ignore all interval checks — re-run everything
        severity:      Override Nuclei severity filter for this run
        dry_run:       Print what would run without executing
        stop_on_error: Abort pipeline if any module fails
    """
    pipeline = PipelineResult(program_id=program_id)

    logger.info(
        f"\n{'═' * 62}\n"
        f"  ZeroPoint Pipeline | program={program_id}\n"
        f"  Modules: {' → '.join(modules)}\n"
        f"  Force: {force} | DryRun: {dry_run}\n"
        f"{'═' * 62}"
    )

    for module_name in modules:
        if module_name not in MODULE_RUNNERS:
            logger.warning(f"[orchestrator] Unknown module '{module_name}' — skipping")
            continue

        if dry_run:
            logger.info(f"[orchestrator] DRY-RUN: would run {MODULE_LABELS[module_name]}")
            continue

        # ── Module start banner ───────────────────────────────────────────
        logger.info(
            f"\n{'━' * 62}\n"
            f"  ▶  {MODULE_LABELS[module_name]}\n"
            f"  program={program_id} | force={force}\n"
            f"{'━' * 62}"
        )

        # Call the appropriate runner
        if module_name == "scan":
            result = await MODULE_RUNNERS[module_name](program_id, force=force, severity=severity)
        else:
            result = await MODULE_RUNNERS[module_name](program_id, force=force)

        pipeline.modules_run.append(result)

        elapsed = f"{result.elapsed_seconds:.1f}s"

        # ── Module end banner ─────────────────────────────────────────────
        if result.success:
            logger.success(
                f"\n{'━' * 62}\n"
                f"  ✓  {MODULE_LABELS[module_name]} complete\n"
                f"  elapsed={elapsed} | stats={result.stats}\n"
                f"{'━' * 62}"
            )
        else:
            logger.error(
                f"\n{'━' * 62}\n"
                f"  ✗  {MODULE_LABELS[module_name]} FAILED\n"
                f"  elapsed={elapsed} | error={result.error}\n"
                f"{'━' * 62}"
            )
            if stop_on_error:
                logger.warning(f"[orchestrator] stop_on_error=True — aborting pipeline")
                break

    pipeline.finished_at = datetime.now(timezone.utc)

    # Print summary banner
    logger.info(
        f"\n{'═' * 62}\n"
        f"  Pipeline complete: {pipeline.summary_line()}\n"
        f"{'═' * 62}"
    )

    return pipeline


# ─────────────────────────────────────────────────────────────────────────────
# Multi-program orchestration
# ─────────────────────────────────────────────────────────────────────────────

async def run_all_programs(
    modules:       List[str]     = ALL_MODULES,
    force:         bool          = False,
    severity:      Optional[str] = None,
    dry_run:       bool          = False,
    stop_on_error: bool          = False,
) -> List[PipelineResult]:
    """Run the full pipeline for all active programs, sequentially."""
    programs = await mongo_ops.list_active_programs()

    if not programs:
        logger.warning("[orchestrator] No active programs found. Run seed_programs.py first.")
        return []

    logger.info(f"[orchestrator] Running pipeline for {len(programs)} active program(s)")

    results = []
    for program in programs:
        result = await run_pipeline(
            program_id    = program.program_id,
            modules       = modules,
            force         = force,
            severity      = severity,
            dry_run       = dry_run,
            stop_on_error = stop_on_error,
        )
        results.append(result)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Daemon mode — continuous 24/7 monitoring
# ─────────────────────────────────────────────────────────────────────────────

class PipelineDaemon:
    """
    Runs each module on its own independent schedule.
    Each module tracks its own last-run time and fires independently,
    so a slow crawl doesn't delay the next ingestion run.

    Schedule (configurable in .env):
      ingest → every DAEMON_INGEST_INTERVAL seconds  (default: 1h)
      probe  → every DAEMON_PROBE_INTERVAL seconds   (default: 2h)
      scan   → every DAEMON_SCAN_INTERVAL seconds    (default: 6h)
      crawl  → every DAEMON_CRAWL_INTERVAL seconds   (default: 12h)
      github → every DAEMON_GITHUB_INTERVAL seconds  (default: 6h)
    """

    def __init__(
        self,
        program_id: Optional[str] = None,
        modules:    List[str]     = ALL_MODULES,
        severity:   Optional[str] = None,
        intervals:  Optional[Dict[str, int]] = None,
    ) -> None:
        self.program_id = program_id
        self.modules    = modules
        self.severity   = severity
        self.intervals  = intervals or {
            "ingest":   settings.DAEMON_INGEST_INTERVAL,
            "probe":    settings.DAEMON_PROBE_INTERVAL,
            "scan":     settings.DAEMON_SCAN_INTERVAL,
            "crawl":    settings.DAEMON_CRAWL_INTERVAL,
            "github":   settings.DAEMON_GITHUB_INTERVAL,
            "portscan": settings.DAEMON_PORTSCAN_INTERVAL,
                "dork":     settings.DAEMON_DORK_INTERVAL,
        }
        self._last_run:   Dict[str, Optional[datetime]] = {m: None for m in ALL_MODULES}
        self._running:    bool = True
        self._run_counts: Dict[str, int] = {m: 0 for m in ALL_MODULES}

    def stop(self) -> None:
        self._running = False
        logger.info("[daemon] Stop signal received — finishing current module then exiting")

    def _is_due(self, module: str) -> bool:
        """Return True if this module is due to run based on its interval."""
        last = self._last_run[module]
        if last is None:
            return True  # Never run → run immediately
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()
        return elapsed >= self.intervals[module]

    async def _run_module_loop(self, module: str) -> None:
        """
        Independent async loop for a single module.
        Each module runs on its own timer, completely independent of other modules.
        A 4-hour crawl will never block ingest from firing on its 1-hour schedule.
        """
        while self._running:
            try:
                if self._is_due(module):
                    interval_h = self.intervals[module] / 3600
                    logger.info(
                        f"[daemon] ► {module} is due "
                        f"(interval={interval_h:.1f}h | runs={self._run_counts[module]})"
                    )

                    if self.program_id:
                        if module == "scan":
                            result = await MODULE_RUNNERS[module](
                                self.program_id, force=False, severity=self.severity
                            )
                        else:
                            result = await MODULE_RUNNERS[module](self.program_id, force=False)
                        module_results = [result]
                    else:
                        programs = await mongo_ops.list_active_programs()
                        module_results = []
                        for prog in programs:
                            if not self._running:
                                break
                            if module == "scan":
                                r = await MODULE_RUNNERS[module](
                                    prog.program_id, force=False, severity=self.severity
                                )
                            else:
                                r = await MODULE_RUNNERS[module](prog.program_id, force=False)
                            module_results.append(r)

                    self._last_run[module]    = datetime.now(timezone.utc)
                    self._run_counts[module] += 1

                    successes = sum(1 for r in module_results if r.success)
                    failures  = len(module_results) - successes
                    logger.info(
                        f"[daemon] ✓ {module} complete | "
                        f"programs={len(module_results)} ok={successes} fail={failures}"
                    )

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(f"[daemon] {module} raised exception: {exc}")
                # Mark as run even on failure so it doesn't immediately retry
                self._last_run[module] = datetime.now(timezone.utc)

            # Sleep in 30s increments so stop() is responsive
            for _ in range(30):
                if not self._running:
                    return
                await asyncio.sleep(1)

    async def run(self) -> None:
        """
        Main daemon entry point.

        Launches each module as its own independent async loop running concurrently.
        This means a 4-hour crawl will never block ingest from firing on its 1-hour
        schedule — each module is completely independent.

        Order within each module is still sequential (one program at a time),
        but ingest/probe/scan/crawl all run on their own clocks simultaneously.
        """
        logger.info(
            f"\n{'═' * 62}\n"
            f"  ZeroPoint Daemon starting\n"
            f"  program={'all' if not self.program_id else self.program_id}\n"
            f"  modules={self.modules}\n"
            f"  intervals: "
            + " | ".join(
                f"{m}={self.intervals[m]//3600}h" for m in self.modules
            )
            + f"\n{'═' * 62}"
        )

        # Each module gets its own independent loop — they run concurrently,
        # never blocking each other regardless of how long any one module takes.
        try:
            await asyncio.gather(
                *[self._run_module_loop(module) for module in self.modules],
                return_exceptions=True,
            )
        except asyncio.CancelledError:
            logger.info("[daemon] Cancelled — shutting down cleanly")

        logger.info("[daemon] Daemon stopped")


# ─────────────────────────────────────────────────────────────────────────────
# DB / index bootstrap — called once before any module runs
# ─────────────────────────────────────────────────────────────────────────────

async def bootstrap_db() -> None:
    """Ensure all MongoDB indexes exist across all collections."""
    await mongo_ops.ensure_indexes()
    await ensure_scanner_indexes()
    await ensure_crawler_indexes()
    await ensure_github_indexes()
    from db.portscan_ops import ensure_portscan_indexes
    await ensure_portscan_indexes()
    from db.dork_ops import ensure_dork_indexes
    await ensure_dork_indexes()
    from db.asn_ops import ensure_asn_indexes
    await ensure_asn_indexes()
    logger.debug("[orchestrator] All DB indexes verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Signal handling for graceful shutdown
# ─────────────────────────────────────────────────────────────────────────────

def _install_signal_handlers(daemon: Optional[PipelineDaemon] = None) -> None:
    """Handle SIGINT / SIGTERM gracefully."""
    def _handler(sig, frame):
        logger.warning(f"\n[orchestrator] Signal {sig} received — shutting down...")
        if daemon:
            daemon.stop()
        else:
            sys.exit(0)

    signal.signal(signal.SIGINT,  _handler)
    signal.signal(signal.SIGTERM, _handler)


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="ZeroPoint Pipeline Orchestrator — run all 4 modules in sequence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full pipeline for one program
  python3 run.py --program-id shopify_h1

  # Run full pipeline for all active programs
  python3 run.py

  # Run specific modules only
  python3 run.py --program-id shopify_h1 --modules ingest,probe

  # Skip specific modules
  python3 run.py --program-id shopify_h1 --skip scan,crawl

  # Force re-run everything (ignore all intervals/timestamps)
  python3 run.py --program-id shopify_h1 --force

  # Preview what would run without executing
  python3 run.py --program-id shopify_h1 --dry-run

  # Start 24/7 daemon mode (all programs, all modules on schedule)
  python3 run.py --daemon

  # Daemon for one program only
  python3 run.py --daemon --program-id shopify_h1

  # Daemon with custom intervals (in seconds)
  python3 run.py --daemon --ingest-interval 1800 --scan-interval 3600
        """,
    )

    p.add_argument(
        "--program-id", type=str, default=None,
        help="Target a specific program. Default: all active programs.",
    )
    p.add_argument(
        "--modules", type=str, default=None,
        help="Comma-separated list of modules to run: ingest,probe,scan,crawl",
    )
    p.add_argument(
        "--skip", type=str, default=None,
        help="Comma-separated list of modules to skip.",
    )
    p.add_argument(
        "--force", action="store_true", default=False,
        help="Re-run all modules ignoring last-run timestamps.",
    )
    p.add_argument(
        "--severity", type=str, default=None,
        help="Override Nuclei severity filter (e.g. critical,high). Default: from .env",
    )
    p.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Print what would run without executing anything.",
    )
    p.add_argument(
        "--stop-on-error", action="store_true", default=False,
        help="Abort the pipeline if any module fails.",
    )
    p.add_argument(
        "--daemon", action="store_true", default=False,
        help="Run in continuous daemon mode on a schedule.",
    )
    p.add_argument(
        "--ingest-interval", type=int, default=None,
        help="Daemon: seconds between ingestion runs (default: 3600)",
    )
    p.add_argument(
        "--probe-interval", type=int, default=None,
        help="Daemon: seconds between probe runs (default: 7200)",
    )
    p.add_argument(
        "--scan-interval", type=int, default=None,
        help="Daemon: seconds between scan runs (default: 21600)",
    )
    p.add_argument(
        "--crawl-interval", type=int, default=None,
        help="Daemon: seconds between crawl runs (default: 43200)",
    )
    p.add_argument(
        "--github-interval", type=int, default=None,
        help="Daemon: seconds between GitHub OSINT runs (default: 21600)",
    )
    p.add_argument(
        "--portscan-interval", type=int, default=None,
        help="Daemon: seconds between port scan runs (default: 86400)",
    )
    p.add_argument(
        "--dork-interval", type=int, default=None,
        help="Daemon: seconds between Google dork runs (default: 86400)",
    )
    p.add_argument(
        "--asn-interval", type=int, default=None,
        help="Daemon: seconds between ASN mapping runs (default: 86400)",
    )

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    configure_logging()
    parser = build_parser()
    args   = parser.parse_args()

    # ── Resolve module list ───────────────────────────────────────────────
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        invalid = [m for m in modules if m not in ALL_MODULES]
        if invalid:
            logger.error(f"Unknown modules: {invalid}. Valid: {ALL_MODULES}")
            sys.exit(1)
    else:
        modules = list(ALL_MODULES)

    if args.skip:
        skip    = {m.strip() for m in args.skip.split(",")}
        modules = [m for m in modules if m not in skip]

    if not modules:
        logger.error("No modules left to run after applying --skip.")
        sys.exit(1)

    logger.info("=" * 62)
    logger.info("  ZeroPoint Pipeline Orchestrator")
    logger.info("=" * 62)
    logger.info(f"  Mode:       {'DAEMON' if args.daemon else 'MANUAL'}")
    logger.info(f"  Program:    {args.program_id or 'all active'}")
    logger.info(f"  Modules:    {' → '.join(modules)}")
    logger.info(f"  Force:      {args.force}")
    logger.info(f"  Dry-run:    {args.dry_run}")
    logger.info("=" * 62)

    if not args.dry_run:
        await bootstrap_db()

    try:
        if args.daemon:
            # ── Daemon mode ───────────────────────────────────────────────
            intervals = {
                "ingest":   args.ingest_interval   or settings.DAEMON_INGEST_INTERVAL,
                "probe":    args.probe_interval    or settings.DAEMON_PROBE_INTERVAL,
                "scan":     args.scan_interval     or settings.DAEMON_SCAN_INTERVAL,
                "crawl":    args.crawl_interval    or settings.DAEMON_CRAWL_INTERVAL,
                "github":   args.github_interval   or settings.DAEMON_GITHUB_INTERVAL,
                "portscan": args.portscan_interval or settings.DAEMON_PORTSCAN_INTERVAL,
                "dork":     args.dork_interval     or settings.DAEMON_DORK_INTERVAL,
                "asn":      args.asn_interval      or settings.DAEMON_ASN_INTERVAL,
            }
            daemon = PipelineDaemon(
                program_id = args.program_id,
                modules    = modules,
                severity   = args.severity,
                intervals  = intervals,
            )
            _install_signal_handlers(daemon)
            await daemon.run()

        else:
            # ── Manual one-shot mode ──────────────────────────────────────
            _install_signal_handlers()

            if args.program_id:
                await run_pipeline(
                    program_id    = args.program_id,
                    modules       = modules,
                    force         = args.force,
                    severity      = args.severity,
                    dry_run       = args.dry_run,
                    stop_on_error = args.stop_on_error,
                )
            else:
                results = await run_all_programs(
                    modules       = modules,
                    force         = args.force,
                    severity      = args.severity,
                    dry_run       = args.dry_run,
                    stop_on_error = args.stop_on_error,
                )

                if results:
                    all_ok = all(r.success for r in results)
                    logger.info(
                        f"\n[orchestrator] All programs done | "
                        f"success={'✓' if all_ok else '✗'} | "
                        f"programs={len(results)}"
                    )

    except KeyboardInterrupt:
        logger.warning("[orchestrator] Interrupted by user")
    except Exception as exc:
        logger.exception(f"[orchestrator] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[orchestrator] Shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())