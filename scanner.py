"""
ZeroPoint :: scanner.py
=======================
Module 3 Orchestrator — Vulnerability Scanner Engine.

Pipeline per program:
  1. Query MongoDB for CRITICAL/HIGH interest assets not recently scanned
     (get_assets_to_scan — ordered CRITICAL first for maximum speed-to-find)
  2. Chunk targets into batches (NUCLEI_BATCH_SIZE)
  3. Per batch: resolve smart template tags from tech stack (build_template_tags)
  4. Run NucleiScanner, stream findings line-by-line as they arrive
  5. For each finding:
       a. Compute SHA-256 dedup fingerprint
       b. Upsert to `findings` collection — is_new=True only on first insert
       c. If is_new=True AND severity in (critical, high): fire immediate alert
       d. Stamp asset with last_scanned timestamp
  6. End-of-run: send summary digest, save ScanRun audit record

Deduplication guarantee:
  The same vulnerability (template_id + domain + matched_at) will NEVER
  produce a duplicate alert, even if the scanner runs every hour 24/7.

Usage:
    python scanner.py                          # scan all active programs
    python scanner.py --program-id shopify_h1  # single program
    python scanner.py --domain api.shopify.com # quick single-domain test (no DB write)
    python scanner.py --force                  # ignore rescan interval
    python scanner.py --severity critical,high # override severity filter
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from collections import Counter
from datetime import datetime
from typing import List, Optional

from loguru import logger

import db.mongo as mongo_ops
from config import settings
from core.alerts import notify_finding, notify_scan_summary
from db.scanner_ops import (
    ensure_scanner_indexes,
    get_assets_to_scan,
    get_new_findings,
    mark_asset_scanned,
    mark_findings_notified,
    save_scan_run,
    upsert_finding,
)
from models import ScanRun, ScanSeverity
from modules.nuclei import NucleiScanner


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
        settings.LOG_FILE.replace(".log", "_scanner.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Alert routing — ALL findings get immediate alerts per user preference.
# Dedup in upsert_finding() guarantees the same finding never fires twice.
# ─────────────────────────────────────────────────────────────────────────────

# Every severity fires immediately — no digest batching for any level.
_IMMEDIATE_ALERT_SEVERITIES = {
    ScanSeverity.CRITICAL,
    ScanSeverity.HIGH,
    ScanSeverity.MEDIUM,
    ScanSeverity.LOW,
    ScanSeverity.INFO,
    ScanSeverity.UNKNOWN,
}


# ─────────────────────────────────────────────────────────────────────────────
# Core scan logic for a single program
# ─────────────────────────────────────────────────────────────────────────────

async def scan_program(
    program_id:    str,
    scanner:       NucleiScanner,
    force:         bool = False,
    severity_override: Optional[str] = None,
) -> ScanRun:
    """
    Execute the full scan pipeline for one program.
    Returns a completed ScanRun audit record.
    """
    run = ScanRun(
        run_id=uuid.uuid4().hex,
        program_id=program_id,
        started_at=datetime.utcnow(),
        templates_used=[settings.NUCLEI_TEMPLATES_PATH or "default"],
    )
    await save_scan_run(run)  # save at start so we can track in-progress runs

    logger.info(f"{'━'*60}")
    logger.info(f"  Scanner | program={program_id} | run_id={run.run_id}")
    logger.info(f"{'━'*60}")

    # ── 1. Fetch scan targets ─────────────────────────────────────────────
    min_interest = settings.SCANNER_MIN_INTEREST
    assets = await get_assets_to_scan(
        program_id=program_id,
        min_interest=min_interest,
        rescan_after_hours=0 if force else settings.NUCLEI_RESCAN_HOURS,
        limit=2000,
    )
    run.targets = len(assets)

    if not assets:
        logger.info(f"[scanner] No targets to scan for {program_id}")
        run.finished_at = datetime.utcnow()
        run.success     = True
        await save_scan_run(run)
        return run

    # ── 2. Chunk into batches ─────────────────────────────────────────────
    batch_size = settings.NUCLEI_BATCH_SIZE
    batches    = [assets[i: i + batch_size] for i in range(0, len(assets), batch_size)]
    parallel   = max(1, settings.NUCLEI_PARALLEL_BATCHES)
    logger.info(
        f"[scanner] {len(assets)} targets → {len(batches)} batch(es) × {batch_size} "
        f"| parallel={parallel} nuclei processes"
    )

    # Override severity if passed via CLI
    if severity_override:
        scanner.severity = severity_override

    sev_counter: Counter = Counter()
    new_finding_ids: List[str] = []

    # Thread-safe accumulators shared across parallel batch coroutines
    import threading
    _lock = asyncio.Lock()

    # ── 3. Process batches in parallel (semaphore-controlled) ─────────────
    semaphore = asyncio.Semaphore(parallel)

    async def _run_batch(batch_idx: int, batch: list) -> None:
        """Run one nuclei batch, write findings, queue alerts — all under semaphore."""
        async with semaphore:
            logger.info(
                f"[scanner] → Batch {batch_idx}/{len(batches)} starting | "
                f"{len(batch)} targets | "
                f"interest={set(a.interest_level for a in batch)}"
            )

            pending_alerts: List = []

            async for raw_finding in scanner.scan(batch, program_id, run.run_id):

                # Upsert to DB (dedup enforced)
                try:
                    is_new = await upsert_finding(raw_finding)
                except Exception as exc:
                    logger.error(f"[scanner] DB write failed: {exc}")
                    async with _lock:
                        run.errors.append(str(exc))
                    continue

                sev_key = (
                    raw_finding.severity.value
                    if hasattr(raw_finding.severity, "value")
                    else str(raw_finding.severity)
                )

                async with _lock:
                    run.findings += 1
                    sev_counter[sev_key] += 1
                    if is_new:
                        run.new_findings += 1
                        new_finding_ids.append(raw_finding.finding_id)

                if is_new:
                    pending_alerts.append(notify_finding(raw_finding, program_id))

            # Dispatch alerts for this batch
            if pending_alerts:
                alert_results = await asyncio.gather(*pending_alerts, return_exceptions=True)
                for r in alert_results:
                    if isinstance(r, Exception):
                        logger.error(f"[scanner] Alert error: {r}")
                logger.info(
                    f"[scanner] ✓ Batch {batch_idx} done | "
                    f"{len(pending_alerts)} alert(s) sent"
                )

            # Stamp all assets in this batch with last_scanned timestamp
            stamp_tasks = [mark_asset_scanned(a.domain, run.run_id) for a in batch]
            await asyncio.gather(*stamp_tasks, return_exceptions=True)

    # Launch all batch coroutines — semaphore ensures only `parallel` run at once
    await asyncio.gather(
        *[_run_batch(idx, batch) for idx, batch in enumerate(batches, start=1)],
        return_exceptions=True,
    )

    # ── 6. Flip is_new=False on all alerted findings ──────────────────────
    if new_finding_ids:
        # For medium/low — they weren't immediately alerted,
        # so we still need to flip them before the summary
        await mark_findings_notified(new_finding_ids)

    # ── 7. Summary digest ─────────────────────────────────────────────────
    await notify_scan_summary(
        program_id=program_id,
        targets=run.targets,
        new_findings=run.new_findings,
        by_severity=dict(sev_counter),
        scan_run_id=run.run_id,
    )

    # ── 8. Save completed run record ──────────────────────────────────────
    run.finished_at = datetime.utcnow()
    run.success     = len(run.errors) == 0
    await save_scan_run(run)

    elapsed = (run.finished_at - run.started_at).total_seconds()
    logger.success(
        f"[scanner] ✓ {program_id} | "
        f"targets={run.targets} | findings={run.findings} | "
        f"new={run.new_findings} | elapsed={elapsed:.1f}s | "
        f"🚨crit={sev_counter.get('critical',0)} "
        f"🔴high={sev_counter.get('high',0)} "
        f"🟡med={sev_counter.get('medium',0)}"
    )
    return run


# ─────────────────────────────────────────────────────────────────────────────
# Multi-program orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def scan_all_programs(
    force:             bool          = False,
    severity_override: Optional[str] = None,
) -> List[ScanRun]:
    """Scan all active programs sequentially."""
    programs = await mongo_ops.list_active_programs()

    if not programs:
        logger.warning("[scanner] No active programs in DB.")
        return []

    scanner = _build_scanner(severity_override)
    runs    = []

    for program in programs:
        try:
            run = await scan_program(
                program_id=program.program_id,
                scanner=scanner,
                force=force,
                severity_override=severity_override,
            )
            runs.append(run)
        except Exception as exc:
            logger.exception(
                f"[scanner] Fatal error on program={program.program_id}: {exc}"
            )

    return runs


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-domain test (no DB write)
# ─────────────────────────────────────────────────────────────────────────────

async def scan_single_domain(
    domain:   str,
    severity: str = "critical,high,medium",
) -> None:
    """
    Quick-scan one domain — prints findings live, fires alerts, no DB write.

    Runs nuclei with NO tag filter (full template library).
    Alerts fire via notify_finding() for every result if channels are configured.
    """
    import shutil
    from models import Asset, InterestLevel, ProbeStatus

    nuclei_bin = settings.NUCLEI_PATH
    if not shutil.which(nuclei_bin):
        logger.error(
            f"[scanner] nuclei binary not found: '{nuclei_bin}'\n"
            f"  Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
            f"  Then:    nuclei -update-templates"
        )
        return

    fake_asset = Asset(
        domain=domain,
        program_id="__test__",
        probe_status=ProbeStatus.ALIVE,
        interest_level=InterestLevel.CRITICAL,
        technologies=[],   # empty → no_tag_filter=True → full template sweep
    )

    scanner          = _build_scanner(severity)
    scanner.severity = severity
    found            = 0
    alert_tasks      = []   # collect coroutines, await them all at the end

    logger.info(
        f"[scanner] Quick-scan | domain={domain} | severity={severity} | "
        f"mode=full-template-sweep (no tag filter)"
    )

    async for finding in scanner.scan(
        [fake_asset], "__test__", "test_run", no_tag_filter=True
    ):
        found += 1
        sev       = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        confirmed = finding.confirmed
        conf_tag  = "✓ CONFIRMED" if confirmed else "⚠ UNCONFIRMED (verify manually before reporting)"

        print(
            f"\n  {'─' * 54}\n"
            f"  [{sev.upper():8}]  {finding.template_name}  [{conf_tag}]\n"
            f"  Template :  {finding.template_id}\n"
            f"  Matched  :  {finding.matched_at}\n"
            f"  Matcher  :  {finding.matcher_name or '(none — no response confirmation)'}\n"
            f"  Tags     :  {', '.join(finding.tags) or '—'}\n"
            + (f"  Refs     :  {finding.reference[0]}\n" if finding.reference else "")
            + (f"  curl     :  {finding.curl_command[:150]}...\n" if finding.curl_command else "")
        )

        # Queue alert — do NOT fire-and-forget with create_task here because
        # the event loop exits right after the scan and drops pending tasks.
        alert_tasks.append(notify_finding(finding, domain))

    print()

    # ── Await ALL alerts together after scan stream closes ────────────────
    # This is the correct pattern — create_task() would silently drop alerts
    # when the event loop exits before the background task runs.
    if alert_tasks:
        logger.info(f"[scanner] Sending {len(alert_tasks)} alert(s)...")
        results = await asyncio.gather(*alert_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"[scanner] Alert dispatch error: {r}")
        logger.success(f"[scanner] Alerts dispatched ✓")

    if found == 0:
        logger.warning(
            f"[scanner] 0 findings for {domain} at severity={severity}\n"
            f"  Possible reasons:\n"
            f"    1. No matching vulnerabilities (expected for hardened targets)\n"
            f"    2. Templates not updated — run: nuclei -update-templates\n"
            f"    3. Target blocked the scan (WAF, rate-limiting)\n"
            f"    4. Severity filter too narrow — try --severity critical,high,medium,low,info"
        )
    else:
        logger.success(f"[scanner] {found} finding(s) for {domain}")


def _build_scanner(severity_override: Optional[str] = None) -> NucleiScanner:
    return NucleiScanner(
        binary_path              = settings.NUCLEI_PATH,
        templates_path           = settings.NUCLEI_TEMPLATES_PATH,
        community_templates_path = settings.NUCLEI_COMMUNITY_TEMPLATES_PATH,
        custom_templates         = settings.NUCLEI_CUSTOM_TEMPLATES,
        fuzzing_templates_path   = settings.NUCLEI_FUZZING_TEMPLATES_PATH,
        enable_fuzzing           = settings.NUCLEI_ENABLE_FUZZING,
        severity                 = severity_override or settings.NUCLEI_SEVERITY,
        rate_limit               = settings.NUCLEI_RATE_LIMIT,
        concurrency              = settings.NUCLEI_CONCURRENCY,
        bulk_size                = settings.NUCLEI_BULK_SIZE,
        timeout                  = settings.NUCLEI_TIMEOUT,
        retries                  = settings.NUCLEI_RETRIES,
        exclude_tags             = settings.NUCLEI_EXCLUDE_TAGS,
        include_tags             = settings.NUCLEI_INCLUDE_TAGS,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    program_id:        Optional[str] = None,
    domain:            Optional[str] = None,
    force:             bool          = False,
    severity_override: Optional[str] = None,
) -> None:
    configure_logging()

    logger.info("=" * 60)
    logger.info("  ZeroPoint Scanner — Module 3 Starting")
    logger.info("=" * 60)

    # Single-domain quick test — no DB connection needed
    if domain:
        await scan_single_domain(domain, severity=severity_override or settings.NUCLEI_SEVERITY)
        return

    # All DB-backed modes
    await mongo_ops.ensure_indexes()
    await ensure_scanner_indexes()

    try:
        if program_id:
            scanner = _build_scanner(severity_override)
            run = await scan_program(
                program_id=program_id,
                scanner=scanner,
                force=force,
                severity_override=severity_override,
            )
            logger.info(
                f"[scanner] Run complete | "
                f"new_findings={run.new_findings} | "
                f"total_findings={run.findings}"
            )
        else:
            runs = await scan_all_programs(
                force=force,
                severity_override=severity_override,
            )
            total_new = sum(r.new_findings for r in runs)
            logger.success(
                f"[scanner] All programs done | "
                f"runs={len(runs)} | total_new_findings={total_new}"
            )

    except KeyboardInterrupt:
        logger.warning("[scanner] Interrupted by user (Ctrl+C)")
    except Exception as exc:
        logger.exception(f"[scanner] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[scanner] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint Scanner — Nuclei vulnerability scanning engine"
    )
    parser.add_argument(
        "--program-id",
        type=str,
        default=None,
        help="Scan a specific program only. Default: all active programs.",
    )
    parser.add_argument(
        "--domain",
        type=str,
        default=None,
        help="Quick-scan a single domain (no DB write). For testing.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Ignore rescan interval — scan all qualifying targets regardless of last_scanned.",
    )
    parser.add_argument(
        "--severity",
        type=str,
        default=None,
        help="Override severity filter (e.g. 'critical,high'). Default: from .env",
    )
    args = parser.parse_args()

    asyncio.run(main(
        program_id        = args.program_id,
        domain            = args.domain,
        force             = args.force,
        severity_override = args.severity,
    ))