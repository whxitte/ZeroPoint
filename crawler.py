"""
ZeroPoint :: crawler.py
=======================
Module 4 Orchestrator — Crawler & JS Analysis Engine.

Pipeline per asset:
  1. Katana active crawl      → live endpoint discovery (JS-aware)
  2. Waybackurls / GAU        → historical URL harvest (parallel with Katana)
  3. Dedup + classify URLs    → endpoint_classifier tags interesting endpoints
  4. Upsert to `endpoints`    → dedup enforced via SHA-256 id
  5. JS file analysis         → fetch .js files, run regex + SecretFinder
  6. Upsert to `secrets`      → dedup enforced, is_new=True on first insert
  7. Alert immediately        → secrets always, interesting endpoints on new
  8. Stamp asset + save run   → last_crawled, CrawlRun audit record

Concurrency:
  Assets are processed in parallel batches (CRAWLER_PARALLEL_BATCHES).
  Within each asset, Katana + Wayback + GAU run simultaneously.
  JS analysis runs concurrently up to 10 parallel fetches per asset.

Usage:
    python3 crawler.py                              # all active programs
    python3 crawler.py --program-id shopify_h1     # single program
    python3 crawler.py --force                      # ignore recrawl interval
    python3 crawler.py --domain api.shopify.com    # quick single-domain test
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from loguru import logger

import db.mongo as mongo_ops
from config import settings
from core.alerts import (
    notify_crawl_summary,
    notify_interesting_endpoint,
    notify_secret,
)
from core.endpoint_classifier import endpoint_classifier
from db.crawler_ops import (
    bulk_upsert_endpoints,
    ensure_crawler_indexes,
    get_assets_to_crawl,
    mark_asset_crawled,
    mark_endpoints_notified,
    mark_secrets_notified,
    save_crawl_run,
    upsert_secret,
    make_endpoint_id,
)
from models import Asset, CrawlRun, CrawledEndpoint, InterestLevel, ProbeStatus
from modules.crawler import GauWorker, KatanaWorker, WaybackWorker
from modules.js_analyzer import analyze_js_url


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
        settings.LOG_FILE.replace(".log", "_crawler.log"),
        level="INFO",
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# URL normalisation & domain scoping
# ─────────────────────────────────────────────────────────────────────────────

def is_in_scope(url: str, root_domain: str) -> bool:
    """Only process URLs that belong to the target domain (no third-party leaks)."""
    try:
        host = urlparse(url.lower()).netloc.split(":")[0]
        return host == root_domain or host.endswith(f".{root_domain}")
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Single-asset crawl
# ─────────────────────────────────────────────────────────────────────────────

async def crawl_asset(
    asset:       Asset,
    run_id:      str,
    katana:      KatanaWorker,
    wayback:     Optional[WaybackWorker],
    gau:         Optional[GauWorker],
    js_semaphore: asyncio.Semaphore,
) -> Dict[str, int]:
    """
    Full crawl pipeline for a single asset.
    Returns stats dict: {endpoints, new_endpoints, interesting, js_files, secrets, new_secrets}
    """
    domain   = asset.domain
    prog_id  = asset.program_id
    stats    = Counter()

    # ── 1. Run all URL discovery workers in parallel ──────────────────────
    url_tasks = [katana.crawl(domain)]
    if wayback:
        url_tasks.append(wayback.crawl(domain))
    if gau:
        url_tasks.append(gau.crawl(domain))

    # Collect all URLs from all tools — deduplicate immediately
    all_urls: Set[str] = set()
    js_urls:  Set[str] = set()

    async def _drain(gen):
        async for url in gen:
            if url and is_in_scope(url, domain):
                all_urls.add(url)
                if endpoint_classifier.is_js_file(url):
                    js_urls.add(url)

    await asyncio.gather(*[_drain(gen) for gen in url_tasks], return_exceptions=True)

    logger.info(
        f"[crawler] {domain} | "
        f"urls={len(all_urls)} js={len(js_urls)}"
    )
    stats["endpoints"] = len(all_urls)
    stats["js_files"]  = len(js_urls)

    # ── 2. Classify and upsert endpoints ──────────────────────────────────
    endpoint_objects: List[CrawledEndpoint] = []
    for url in all_urls:
        if endpoint_classifier.is_noise(url):
            continue
        is_interesting, tags = endpoint_classifier.classify(url)
        parsed = urlparse(url)
        ep = CrawledEndpoint(
            endpoint_id    = make_endpoint_id(domain, url),
            program_id     = prog_id,
            domain         = domain,
            url            = url,
            url_path       = parsed.path,
            source         = "katana",
            is_interesting = is_interesting,
            interest_tags  = tags,
            crawl_run_id   = run_id,
        )
        endpoint_objects.append(ep)

    new_ep, _ = await bulk_upsert_endpoints(endpoint_objects)
    stats["new_endpoints"] = new_ep

    # Count interesting among the new ones
    interesting_new = [
        e for e in endpoint_objects if e.is_interesting
    ]
    stats["interesting"] = len(interesting_new)

    # ── 3. Alert on new interesting endpoints ────────────────────────────
    # Only alert on endpoints that were just inserted (is_new=True after upsert).
    # bulk_upsert_endpoints returns the new count but not which ones — we approximate
    # by only alerting on is_interesting endpoints from the current batch.
    # The notification semaphore in alerts.py caps concurrent connections to
    # NOTIFICATIONS_CONCURRENCY (default 5), preventing "Too many open files".
    if alert_tasks := [
        notify_interesting_endpoint(ep, prog_id) for ep in interesting_new
    ]:
        await asyncio.gather(*alert_tasks, return_exceptions=True)

    # ── 4. JS analysis — run concurrently (semaphore-limited) ────────────
    new_secret_ids: List[str] = []
    sev_counter: Counter = Counter()

    async def _analyze_one_js(js_url: str) -> None:
        async with js_semaphore:
            secrets = await analyze_js_url(
                url               = js_url,
                domain            = domain,
                program_id        = prog_id,
                crawl_run_id      = run_id,
                min_entropy       = settings.SECRET_MIN_ENTROPY,
                secretfinder_path = settings.SECRETFINDER_PATH,
            )
            for secret in secrets:
                stats["secrets"] += 1
                try:
                    is_new = await upsert_secret(secret)
                except Exception as exc:
                    logger.error(f"[crawler] Secret DB write failed: {exc}")
                    continue

                if is_new:
                    stats["new_secrets"] += 1
                    sev_key = secret.severity.value if hasattr(secret.severity, "value") else str(secret.severity)
                    sev_counter[sev_key] += 1
                    new_secret_ids.append(secret.secret_id)
                    # Immediate alert for every new secret
                    await notify_secret(secret, prog_id)

    if settings.CRAWLER_JS_ANALYSIS and js_urls:
        await asyncio.gather(
            *[_analyze_one_js(url) for url in js_urls],
            return_exceptions=True,
        )

    # ── 5. Mark secrets notified ─────────────────────────────────────────
    if new_secret_ids:
        await mark_secrets_notified(new_secret_ids)

    # ── 6. Stamp asset ───────────────────────────────────────────────────
    await mark_asset_crawled(domain, run_id)

    logger.success(
        f"[crawler] ✓ {domain} | "
        f"urls={stats['endpoints']} new_ep={stats['new_endpoints']} "
        f"interesting={stats['interesting']} js={stats['js_files']} "
        f"new_secrets={stats['new_secrets']}"
    )
    return dict(stats)


# ─────────────────────────────────────────────────────────────────────────────
# Program-level crawl orchestration
# ─────────────────────────────────────────────────────────────────────────────

async def crawl_program(
    program_id: str,
    force:      bool = False,
) -> CrawlRun:
    """Execute the full crawl pipeline for one program."""
    run = CrawlRun(
        run_id     = uuid.uuid4().hex,
        program_id = program_id,
        started_at = datetime.now(timezone.utc),
    )
    await save_crawl_run(run)

    logger.info(f"{'━' * 60}")
    logger.info(f"  Crawler | program={program_id} | run_id={run.run_id}")
    logger.info(f"{'━' * 60}")

    # ── Fetch qualifying assets ───────────────────────────────────────────
    assets = await get_assets_to_crawl(
        program_id          = program_id,
        min_interest        = settings.CRAWLER_MIN_INTEREST,
        recrawl_after_hours = 0 if force else settings.CRAWLER_RECRAWL_HOURS,
        limit               = 2000,
    )
    run.targets = len(assets)

    if not assets:
        logger.info(f"[crawler] No assets to crawl for {program_id}")
        run.finished_at = datetime.now(timezone.utc)
        run.success     = True
        await save_crawl_run(run)
        return run

    # ── Chunk into parallel batches ───────────────────────────────────────
    batch_size = settings.CRAWLER_BATCH_SIZE
    parallel   = max(1, settings.CRAWLER_PARALLEL_BATCHES)
    batches    = [assets[i: i + batch_size] for i in range(0, len(assets), batch_size)]
    logger.info(
        f"[crawler] {len(assets)} targets → {len(batches)} batch(es) × {batch_size} "
        f"| parallel={parallel}"
    )

    # Workers (shared across batches — stateless)
    katana = KatanaWorker(
        binary_path = settings.KATANA_PATH,
        depth       = settings.CRAWLER_DEPTH,
        parallelism = settings.CRAWLER_PARALLELISM,
        rate_limit  = settings.CRAWLER_RATE_LIMIT,
        timeout     = settings.CRAWLER_TIMEOUT,
    )
    wayback = WaybackWorker(binary_path=settings.WAYBACKURLS_PATH) if settings.CRAWLER_WAYBACK else None
    gau     = GauWorker(binary_path=settings.GAU_PATH) if settings.CRAWLER_GAU else None

    # JS analysis semaphore — cap concurrent HTTP fetches globally
    js_sem = asyncio.Semaphore(10)

    grand: Counter = Counter()
    sev_total: Counter = Counter()
    semaphore = asyncio.Semaphore(parallel)

    async def _run_batch(batch: List[Asset]) -> None:
        async with semaphore:
            tasks = [
                crawl_asset(asset, run.run_id, katana, wayback, gau, js_sem)
                for asset in batch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"[crawler] Asset error: {r}")
                    run.errors.append(str(r))
                elif isinstance(r, dict):
                    grand.update(r)

    await asyncio.gather(
        *[_run_batch(batch) for batch in batches],
        return_exceptions=True,
    )

    # ── Finalise run record ───────────────────────────────────────────────
    run.endpoints_found = grand.get("endpoints",     0)
    run.new_endpoints   = grand.get("new_endpoints", 0)
    run.js_files        = grand.get("js_files",      0)
    run.secrets_found   = grand.get("secrets",       0)
    run.new_secrets     = grand.get("new_secrets",   0)
    run.finished_at     = datetime.now(timezone.utc)
    run.success         = len(run.errors) == 0
    await save_crawl_run(run)

    # ── Summary digest ────────────────────────────────────────────────────
    await notify_crawl_summary(
        program_id    = program_id,
        targets       = run.targets,
        new_endpoints = run.new_endpoints,
        interesting   = grand.get("interesting", 0),
        new_secrets   = run.new_secrets,
        by_severity   = dict(sev_total),
    )

    elapsed = (run.finished_at - run.started_at).total_seconds()
    logger.success(
        f"[crawler] ✓ {program_id} | "
        f"endpoints={run.endpoints_found} new={run.new_endpoints} "
        f"js={run.js_files} secrets={run.secrets_found} "
        f"new_secrets={run.new_secrets} elapsed={elapsed:.1f}s"
    )
    return run


# ─────────────────────────────────────────────────────────────────────────────
# All-programs orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def crawl_all_programs(force: bool = False) -> List[CrawlRun]:
    programs = await mongo_ops.list_active_programs()
    if not programs:
        logger.warning("[crawler] No active programs in DB.")
        return []

    logger.info(f"[crawler] Starting crawl for {len(programs)} active program(s)")
    runs = []
    for program in programs:
        try:
            run = await crawl_program(program.program_id, force=force)
            runs.append(run)
        except Exception as exc:
            logger.exception(f"[crawler] Fatal error on program={program.program_id}: {exc}")

    return runs


# ─────────────────────────────────────────────────────────────────────────────
# Quick single-domain test (no DB write)
# ─────────────────────────────────────────────────────────────────────────────

async def crawl_single_domain(domain: str) -> None:
    """Dev/debug — crawl one domain, print results, no DB write."""
    import shutil

    # Pre-flight checks
    for tool, path in [("katana", settings.KATANA_PATH)]:
        if not shutil.which(path):
            logger.error(
                f"[crawler] {tool} not found at '{path}'\n"
                f"  Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )
            return

    logger.info(f"[crawler] Quick-crawl: {domain}")

    katana  = KatanaWorker(
        binary_path=settings.KATANA_PATH,
        depth=settings.CRAWLER_DEPTH,
        parallelism=settings.CRAWLER_PARALLELISM,
        rate_limit=settings.CRAWLER_RATE_LIMIT,
        timeout=settings.CRAWLER_TIMEOUT,
    )
    wayback = WaybackWorker(settings.WAYBACKURLS_PATH) if settings.CRAWLER_WAYBACK else None
    gau     = GauWorker(settings.GAU_PATH)             if settings.CRAWLER_GAU     else None

    all_urls: Set[str] = set()
    js_urls:  Set[str] = set()

    async def _collect(gen):
        async for url in gen:
            if url and is_in_scope(url, domain):
                all_urls.add(url)
                if endpoint_classifier.is_js_file(url):
                    js_urls.add(url)

    url_tasks = [katana.crawl(domain)]
    if wayback:
        url_tasks.append(wayback.crawl(domain))
    if gau:
        url_tasks.append(gau.crawl(domain))

    await asyncio.gather(*[_collect(gen) for gen in url_tasks], return_exceptions=True)

    # Classify and print
    interesting_count = 0
    print(f"\n  {'━' * 56}")
    print(f"  Domain: {domain}  |  URLs found: {len(all_urls)}  |  JS files: {len(js_urls)}")
    print(f"  {'━' * 56}\n")

    for url in sorted(all_urls):
        is_int, tags = endpoint_classifier.classify(url)
        if is_int:
            interesting_count += 1
            print(f"  🎯  [{', '.join(tags):30}]  {url}")

    print(f"\n  Total interesting: {interesting_count} / {len(all_urls)} URLs")

    # JS analysis
    if settings.CRAWLER_JS_ANALYSIS and js_urls:
        print(f"\n  {'━' * 56}")
        print(f"  JS Analysis: {len(js_urls)} file(s)")
        print(f"  {'━' * 56}\n")
        sem = asyncio.Semaphore(5)
        all_secrets = []

        async def _check_js(url: str):
            async with sem:
                return await analyze_js_url(
                    url               = url,
                    domain            = domain,
                    program_id        = "__test__",
                    crawl_run_id      = "test_run",
                    min_entropy       = settings.SECRET_MIN_ENTROPY,
                    secretfinder_path = settings.SECRETFINDER_PATH,
                )

        results = await asyncio.gather(*[_check_js(u) for u in js_urls], return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_secrets.extend(r)

        if all_secrets:
            print(f"\n  🔑 {len(all_secrets)} SECRET(S) FOUND:\n")
            for s in all_secrets:
                sev = s.severity.value if hasattr(s.severity, "value") else str(s.severity)
                val = s.secret_value
                safe = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "..."
                print(f"  [{sev.upper():8}]  {s.secret_type:30}  {safe}")
                print(f"             Source: {s.source_url[:100]}\n")
        else:
            logger.info(f"[crawler] No secrets found in {len(js_urls)} JS file(s)")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    program_id: Optional[str] = None,
    domain:     Optional[str] = None,
    force:      bool          = False,
) -> None:
    configure_logging()

    logger.info("=" * 60)
    logger.info("  ZeroPoint Crawler — Module 4 Starting")
    logger.info("=" * 60)

    if domain:
        await crawl_single_domain(domain)
        return

    await mongo_ops.ensure_indexes()
    await ensure_crawler_indexes()

    try:
        if program_id:
            run = await crawl_program(program_id, force=force)
            logger.success(
                f"[crawler] Done | "
                f"endpoints={run.endpoints_found} "
                f"new_secrets={run.new_secrets}"
            )
        else:
            runs = await crawl_all_programs(force=force)
            total_secrets  = sum(r.new_secrets   for r in runs)
            total_endpoints = sum(r.new_endpoints for r in runs)
            logger.success(
                f"[crawler] All programs done | "
                f"runs={len(runs)} "
                f"new_endpoints={total_endpoints} "
                f"new_secrets={total_secrets}"
            )

    except KeyboardInterrupt:
        logger.warning("[crawler] Interrupted by user (Ctrl+C)")
    except Exception as exc:
        logger.exception(f"[crawler] Fatal error: {exc}")
        sys.exit(1)
    finally:
        await mongo_ops.close_connection()
        logger.info("[crawler] Shutdown complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ZeroPoint Crawler — Endpoint discovery & JS secret analysis"
    )
    parser.add_argument(
        "--program-id", type=str, default=None,
        help="Crawl a specific program. Default: all active programs.",
    )
    parser.add_argument(
        "--domain", type=str, default=None,
        help="Quick-crawl a single domain (no DB write). For testing.",
    )
    parser.add_argument(
        "--force", action="store_true", default=False,
        help="Ignore recrawl interval — crawl all qualifying assets.",
    )
    args = parser.parse_args()

    asyncio.run(main(
        program_id = args.program_id,
        domain     = args.domain,
        force      = args.force,
    ))