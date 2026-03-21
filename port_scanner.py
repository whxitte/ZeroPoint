"""
ZeroPoint :: port_scanner.py
=============================
Module 7 Orchestrator — Port Scanner Engine.

Finds exposed services that the HTTP pipeline (Modules 1-4) completely misses:
  Redis on 6379  (often auth-free → full key/value access)
  MongoDB on 27017 (auth optional → data exposure)
  Elasticsearch on 9200 (unauthenticated API common → data dump)
  Docker API on 2375 (unauthenticated → container escape → RCE)
  Kubernetes kubelet on 10250 (node-level access)
  Jupyter on 8888 (often no token → code execution)

Pipeline per program:
  1. Query MongoDB for assets with ip_addresses populated (probe_status=alive)
  2. Run Masscan at configurable rate for fast port discovery
  3. Run Nmap -sV -sC on found open ports for service fingerprinting
  4. Classify each finding by severity using the port/service table
  5. Upsert to `port_findings` (SHA-256 dedup)
  6. Alert immediately on CRITICAL/HIGH findings
  7. Save PortScanRun audit record

Requirements:
  masscan  — sudo apt install masscan
  nmap     — sudo apt install nmap

Usage:
    python3 port_scanner.py --program-id shopify_h1
    python3 port_scanner.py                           # all active programs
    python3 port_scanner.py --ip 1.2.3.4              # quick single-IP test
    python3 port_scanner.py --skip-nmap               # masscan discovery only
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
from core.alerts import notify_port_finding, notify_port_scan_summary
from db.mongo import get_assets_col
from db.portscan_ops import (
    ensure_portscan_indexes,
    mark_findings_notified,
    save_port_scan_run,
    upsert_port_finding,
)
from models import Asset, PortFindingSeverity, PortScanRun, ProbeStatus
from modules.port_scanner import PortScanner


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
        settings.LOG_FILE.replace(".log", "_portscan.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Severity filter for immediate alerts
# ─────────────────────────────────────────────────────────────────────────────

_ALERT_SEVERITIES = {
    PortFindingSeverity.CRITICAL,
    PortFindingSeverity.HIGH,
}


# ─────────────────────────────────────────────────────────────────────────────
# Asset query — which assets to scan
# ─────────────────────────────────────────────────────────────────────────────

async def get_assets_with_ips(
    program_id: str,
    limit:      int = 2000,
) -> List[Asset]:
    """
    Return alive assets that have at least one IP address populated.
    Assets without IPs haven't been probed yet — skip them.
    """
    col    = get_assets_col()
    query  = {
        "program_id":   program_id,
        "probe_status": ProbeStatus.ALIVE.value,
        "ip_addresses": {"$exists": True, "$not": {"$size": 0}},
    }
    assets: List[Asset] = []
    async for doc in col.find(query).limit(limit):
        doc.pop("_id", None)
        try:
            assets.append(Asset(**doc))
        except Exception as exc:
            logger.warning(f"Malformed asset skipped: {exc}")

    logger.info(
        f"[portscan] {len(assets)} asset(s) with IPs queued | program={program_id}"
    )
    return assets


# ─────────────────────────────────────────────────────────────────────────────
# Per-program scan
# ─────────────────────────────────────────────────────────────────────────────

async def scan_program(
    program_id: str,
    scanner:    PortScanner,
) -> PortScanRun:
    """Execute the full port scan pipeline for one program."""
    run = PortScanRun(
        run_id     = uuid.uuid4().hex,
        program_id = program_id,
        started_at = datetime.now(timezone.utc),
    )
    await save_port_scan_run(run)

    logger.info(f"{'━' * 60}")
    logger.info(f"  Port Scanner | program={program_id} | run_id={run.run_id}")
    logger.info(f"{'━' * 60}")

    assets = await get_assets_with_ips(program_id)

    if not assets:
        logger.info(
            f"[portscan] No assets with IP addresses for {program_id}. "
            "Run prober first (Module 2) to populate ip_addresses."
        )
        run.finished_at = datetime.now(timezone.utc)
        run.success     = True
        await save_port_scan_run(run)
        return run

    # Count unique IPs
    all_ips = set()
    for a in assets:
        all_ips.update(a.ip_addresses or [])
    run.targets = len(all_ips)

    sev_counter:     Counter   = Counter()
    new_finding_ids: List[str] = []
    alert_tasks:     List      = []

    async for finding in scanner.scan(assets, program_id, run.run_id):
        run.ports_found += 1

        try:
            is_new = await upsert_port_finding(finding)
        except Exception as exc:
            logger.error(f"[portscan] DB write failed: {exc}")
            run.errors.append(str(exc))
            continue

        sev_key = finding.severity.value
        sev_counter[sev_key] += 1

        if is_new:
            run.new_findings += 1
            new_finding_ids.append(finding.finding_id)

            # Immediate alert for CRITICAL/HIGH
            if finding.severity in _ALERT_SEVERITIES:
                alert_tasks.append(notify_port_finding(finding, program_id))

    # Fire all alerts
    if alert_tasks:
        results = await asyncio.gather(*alert_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"[portscan] Alert error: {r}")

    # Flip is_new=False
    if new_finding_ids:
        await mark_findings_notified(new_finding_ids)

    # Summary
    await notify_port_scan_summary(
        program_id   = program_id,
        targets      = run.targets,
        new_findings = run.new_findings,
        by_severity  = dict(sev_counter),
        run_id       = run.run_id,
    )

    run.finished_at = datetime.now(timezone.utc)
    run.success     = len(run.errors) == 0
    await save_port_scan_run(run)

    elapsed = (run.finished_at - run.started_at).total_seconds()
    logger.success(
        f"[portscan] ✓ {program_id} | "
        f"ips={run.targets} | ports={run.ports_found} | "
        f"new={run.new_findings} | elapsed={elapsed:.1f}s | "
        f"🚨crit={sev_counter.get('critical', 0)} "
        f"🔴high={sev_counter.get('high', 0)} "
        f"🟡med={sev_counter.get('medium', 0)}"
    )
    return run


# ─────────────────────────────────────────────────────────────────────────────
# All-programs orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def scan_all_programs(scanner: PortScanner) -> List[PortScanRun]:
    programs = await mongo_ops.list_active_programs()
    if not programs:
        logger.warning("[portscan] No active programs in DB.")
        return []

    logger.info(f"[portscan] Starting port scan for {len(programs)} program(s)")
    runs = []
    for program in programs:
        try:
            run = await scan_program(program.program_id, scanner)
            runs.append(run)
        except Exception as exc:
            logger.exception(f"[portscan] Fatal error on {program.program_id}: {exc}")

    return runs


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-IP test (no DB write)
# ─────────────────────────────────────────────────────────────────────────────

async def scan_single_ip(ip: str, skip_nmap: bool = False) -> None:
    """Dev/debug — scan one IP, print results, no DB write."""
    from models import Asset, InterestLevel

    scanner = _build_scanner(skip_nmap=skip_nmap)
    fake_asset = Asset(
        domain     = ip,
        program_id = "__test__",
        ip_addresses = [ip],
    )

    print(f"\n  {'━' * 56}")
    print(f"  Port Scan: {ip}")
    print(f"  {'━' * 56}\n")

    found = 0
    async for finding in scanner.scan([fake_asset], "__test__", "test_run"):
        found += 1
        sev = finding.severity.value
        svc = finding.service or "unknown"
        prd = f"  ({finding.product})" if finding.product else ""
        print(
            f"  [{sev.upper():8}]  {finding.ip}:{finding.port}/{finding.protocol}"
            f"  {svc}{prd}"
        )
        print(f"             {finding.reason}")
        if finding.banner:
            preview = finding.banner[:120].replace("\n", " | ")
            print(f"             Banner: {preview}")
        print()

    if found == 0:
        print(f"  No open ports found on {ip}")
    else:
        print(f"  Total: {found} open port(s)")


def _build_scanner(skip_nmap: bool = False) -> PortScanner:
    return PortScanner(
        masscan_binary = settings.MASSCAN_PATH,
        nmap_binary    = settings.NMAP_PATH,
        ports          = settings.PORTSCAN_PORTS,
        masscan_rate   = settings.MASSCAN_RATE,
        nmap_timeout   = settings.NMAP_TIMEOUT,
        skip_nmap      = skip_nmap,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    program_id: Optional[str] = None,
    ip:         Optional[str] = None,
    skip_nmap:  bool          = False,
) -> None:
    configure_logging()

    logger.info("=" * 60)
    logger.info("  ZeroPoint Port Scanner — Module 7 Starting")
    logger.info("=" * 60)

    if ip:
        await scan_single_ip(ip, skip_nmap=skip_nmap)
        return

    await mongo_ops.ensure_indexes()
    await ensure_portscan_indexes()

    scanner = _build_scanner(skip_nmap=skip_nmap)

    try:
        if program_id:
            run = await scan_program(program_id, scanner)
            logger.success(
                f"[portscan] Done | "
                f"new_findings={run.new_findings} | total={run.ports_found}"
            )
        else:
            runs = await scan_all_programs(scanner)
            total_new = sum(r.new_findings for r in runs)
            logger.success(
                f"[portscan] All programs done | "
                f"runs={len(runs)} | total_new={total_new}"
            )

    except KeyboardInterrupt:
        logger.warning("[portscan] Interrupted by user (Ctrl+C)")
    except Exception as exc:
        logger.exception(f"[portscan] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[portscan] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint Port Scanner — Masscan + Nmap service discovery"
    )
    parser.add_argument("--program-id", type=str, default=None)
    parser.add_argument(
        "--ip", type=str, default=None,
        help="Quick-scan a single IP (no DB write). For testing.",
    )
    parser.add_argument(
        "--skip-nmap", action="store_true", default=False,
        help="Run Masscan discovery only — no Nmap service fingerprint.",
    )
    args = parser.parse_args()
    asyncio.run(main(program_id=args.program_id, ip=args.ip, skip_nmap=args.skip_nmap))