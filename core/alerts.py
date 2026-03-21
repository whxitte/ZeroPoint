"""
ZeroPoint :: core/alerts.py
============================
Notification dispatcher for all ZeroPoint pipeline events.

Alert types:
  1. notify_new_assets()          — New subdomains from ingestion (Module 1)
  2. notify_high_value_probe()    — CRITICAL/HIGH interest assets from prober (Module 2)
  3. notify_probe_summary()       — End-of-run probe stats digest
  4. notify_finding()             — New Nuclei vulnerability finding (Module 3)
  5. notify_scan_summary()        — End-of-scan stats digest
  6. notify_secret()              — New JS secret discovered (Module 4)
  7. notify_interesting_endpoint()— New interesting endpoint found
  8. notify_crawl_summary()       — End-of-crawl stats digest

Only fires when warranted — never spam, always signal.
"""

from __future__ import annotations

import asyncio
import html as _html
from typing import Dict, List, Optional

import aiohttp
from loguru import logger

from config import settings
from models import InterestLevel, ProbeResult, UpsertResult


def _e(text: str) -> str:
    """
    Escape a string for safe embedding in Telegram HTML messages.
    Telegram HTML only supports <b>, <i>, <code>, <pre>, <a>.
    Any literal < > & in content must be escaped or Telegram returns 400.
    """
    return _html.escape(str(text), quote=False)


# ---------------------------------------------------------------------------
# Global notification semaphore
# ---------------------------------------------------------------------------
# Limits the number of concurrent outbound HTTPS connections to notification
# services (Discord + Telegram). Without this, mass crawl events (176
# interesting endpoints found at once) open hundreds of SSL connections
# simultaneously, exhausting the OS file descriptor limit (ulimit -n 1024).
#
# The semaphore is lazy-initialised on first use so it's always created in
# the correct event loop (avoids DeprecationWarning on Python 3.10+).
_notify_sem: Optional[asyncio.Semaphore] = None

def _get_notify_sem() -> asyncio.Semaphore:
    global _notify_sem
    if _notify_sem is None:
        _notify_sem = asyncio.Semaphore(settings.NOTIFICATIONS_CONCURRENCY)
    return _notify_sem



# ─────────────────────────────────────────────────────────────────────────────
# Notification dedup — 7-day re-alert suppression
# ─────────────────────────────────────────────────────────────────────────────

def _is_suppressed(finding) -> bool:
    """
    Return True if this finding should NOT generate an alert right now.
    A finding is suppressed when suppress_until is set and is in the future.
    This prevents re-alerts for the same finding every scan cycle.
    """
    from datetime import datetime, timezone
    suppress_until = getattr(finding, "suppress_until", None)
    if not suppress_until:
        return False
    now = datetime.now(timezone.utc)
    # suppress_until may be a datetime or a dict (from MongoDB)
    if hasattr(suppress_until, "tzinfo"):
        return suppress_until > now
    return False


# ---------------------------------------------------------------------------
# Color constants
# ---------------------------------------------------------------------------

_COLOR = {
    "new_asset":  0x00FF88,   # Bright green
    "critical":   0xFF0000,   # Red
    "high":       0xFF6600,   # Orange
    "medium":     0xFFCC00,   # Yellow
    "info":       0x5865F2,   # Discord blurple
    "summary":    0x00BFFF,   # Deep sky blue
}

_INTEREST_EMOJI = {
    InterestLevel.CRITICAL: "🚨",
    InterestLevel.HIGH:     "🔴",
    InterestLevel.MEDIUM:   "🟡",
    InterestLevel.LOW:      "🟢",
    InterestLevel.NOISE:    "⚫",
}


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------

async def _send_discord_embed(title: str, description: str, color: int, fields: list | None = None) -> None:
    """
    Post a single embed to the configured Discord webhook.
    Handles 429 rate-limit responses by respecting the retry_after value.
    The global notification semaphore caps concurrent outbound connections.
    """
    if not settings.DISCORD_WEBHOOK_URL:
        return

    embed: dict = {
        "title":       title,
        "description": description,
        "color":       color,
        "footer":      {"text": "ZeroPoint Recon Engine"},
    }
    if fields:
        embed["fields"] = fields

    payload = {"embeds": [embed]}

    max_retries = 3
    async with _get_notify_sem():
        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        settings.DISCORD_WEBHOOK_URL,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status in (200, 204):
                            return  # success

                        if resp.status == 429:
                            # Discord rate limit — read retry_after and sleep exactly that long
                            try:
                                data        = await resp.json()
                                retry_after = float(data.get("retry_after", 1.0))
                            except Exception:
                                retry_after = 1.0
                            logger.debug(
                                f"[discord] Rate limited (429) — sleeping {retry_after:.1f}s "
                                f"(attempt {attempt + 1}/{max_retries})"
                            )
                            await asyncio.sleep(retry_after + 0.1)
                            continue  # retry

                        body = await resp.text()
                        logger.warning(f"[discord] HTTP {resp.status}: {body[:200]}")
                        return  # don't retry non-429 errors

            except aiohttp.ClientError as exc:
                logger.error(f"[discord] Request failed: {exc}")
                return
            except Exception as exc:
                logger.error(f"[discord] Unexpected error: {exc}")
                return


async def _send_telegram_message(text: str) -> None:
    """
    Send an HTML-formatted message via Telegram Bot API.
    Handles:
      - 429 Too Many Requests → reads retry_after, sleeps, retries up to 3 times
      - 400 Bad Request       → falls back to plain-text (no parse_mode)
      - Timeout               → one retry
    The global notification semaphore caps concurrent outbound connections.
    """
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"

    async def _post(parse_mode: str) -> bool:
        """Returns True on success."""
        payload = {
            "chat_id":    settings.TELEGRAM_CHAT_ID,
            "text":       text,
            "parse_mode": parse_mode,
        }
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            return True

                        body_text = await resp.text()

                        if resp.status == 429:
                            # Rate limited — read retry_after and sleep
                            try:
                                data        = await resp.json(content_type=None)
                                retry_after = float(
                                    data.get("parameters", {}).get("retry_after", 3)
                                )
                            except Exception:
                                retry_after = 3.0
                            logger.debug(
                                f"[telegram] 429 — sleeping {retry_after:.1f}s "
                                f"(attempt {attempt + 1}/3)"
                            )
                            await asyncio.sleep(retry_after + 0.5)
                            continue

                        logger.warning(f"[telegram] HTTP {resp.status}: {body_text[:200]}")
                        return False

            except asyncio.TimeoutError:
                if attempt < 2:
                    await asyncio.sleep(1.0)
                    continue
                logger.warning("[telegram] Timed out after 3 attempts")
                return False
            except aiohttp.ClientError as exc:
                logger.error(f"[telegram] Request failed: {exc}")
                return False
            except Exception as exc:
                logger.error(f"[telegram] Unexpected error: {exc}")
                return False

        return False

    async with _get_notify_sem():
        # Try HTML first, fall back to plain text on parse error (400)
        success = await _post("HTML")
        if not success:
            # Strip HTML tags and retry as plain text
            import re
            plain = re.sub(r"<[^>]+>", "", text)
            await _post("")


async def _dispatch(discord_coro, telegram_coro) -> None:
    """Fire both channels concurrently, swallow individual failures."""
    results = await asyncio.gather(discord_coro, telegram_coro, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            logger.error(f"[alerts] Dispatch exception: {r}")


# ---------------------------------------------------------------------------
# Module 1: New asset notifications
# ---------------------------------------------------------------------------

async def notify_new_assets(results: List[UpsertResult]) -> None:
    """
    Dispatch notifications for all net-new assets discovered in an ingestion run.
    Batches multiple domains into a single message to avoid webhook spam.
    """
    new_assets = [r for r in results if r.is_new]
    if not new_assets:
        return

    by_program: Dict[str, List[UpsertResult]] = {}
    for r in new_assets:
        by_program.setdefault(r.program_id, []).append(r)

    for program_id, assets in by_program.items():
        count = len(assets)

        # Discord — plain text domain list (no markdown needed)
        discord_list = "\n".join(
            f"• {a.domain} [{a.source.value}]" for a in assets[:20]
        )
        if count > 20:
            discord_list += f"\n…and {count - 20} more."

        # Telegram — HTML with proper escaping on every dynamic value
        tg_lines = [
            f"<b>🔍 ZeroPoint — New Assets</b>",
            f"Program: <code>{_e(program_id)}</code>",
            f"New: <b>{count}</b>",
            "",
        ]
        for a in assets[:20]:
            tg_lines.append(f"• <code>{_e(a.domain)}</code> [{_e(a.source.value)}]")
        if count > 20:
            tg_lines.append(f"…and {count - 20} more.")

        await _dispatch(
            _send_discord_embed(
                title=f"🔍  {count} New Asset{'s' if count > 1 else ''} — {program_id}",
                description=discord_list,
                color=_COLOR["new_asset"],
            ),
            _send_telegram_message("\n".join(tg_lines)),
        )

        logger.info(f"[alerts] Notified {count} new asset(s) for {program_id}")


# ---------------------------------------------------------------------------
# Module 2: High-value probe notifications
# ---------------------------------------------------------------------------

async def notify_high_value_probe(probe: ProbeResult, program_id: str) -> None:
    """
    Fire an immediate, detailed alert for a single CRITICAL or HIGH asset.
    Called as soon as the Fingerprint engine classifies a result.
    Speed matters here — this is the first-mover advantage trigger.
    """
    level   = probe.interest_level
    emoji   = _INTEREST_EMOJI.get(level, "🔵")
    reasons = ", ".join(probe.interest_reasons[:5]) or "no specific reason"
    tech    = ", ".join(probe.technologies[:8]) or "unknown"
    color   = _COLOR.get(level.value, _COLOR["info"])

    # ── Discord embed (rich, detailed) ────────────────────────────────────
    fields = [
        {"name": "Domain",          "value": f"`{probe.domain}`",         "inline": True},
        {"name": "HTTP Status",     "value": str(probe.http_status or "—"), "inline": True},
        {"name": "Interest Level",  "value": f"{emoji} {level.value.upper()}", "inline": True},
        {"name": "Tech Stack",      "value": tech or "—",                  "inline": False},
        {"name": "Why Flagged",     "value": reasons,                      "inline": False},
    ]
    if probe.http_title:
        fields.append({"name": "Title", "value": probe.http_title[:100], "inline": False})
    if probe.redirect_url:
        fields.append({"name": "Redirects To", "value": probe.redirect_url[:120], "inline": False})

    discord_task = _send_discord_embed(
        title=f"{emoji}  {level.value.upper()} Target — {probe.domain}",
        description=f"Program: `{program_id}`  |  Status: `{probe.http_status or 'N/A'}`",
        color=color,
        fields=fields,
    )

    # ── Telegram message (concise, actionable) ────────────────────────────
    tg_lines = [
        f"<b>{emoji} ZeroPoint — {_e(level.value.upper())} Target</b>",
        f"",
        f"<b>Domain:</b>  <code>{_e(probe.domain)}</code>",
        f"<b>Program:</b> <code>{_e(program_id)}</code>",
        f"<b>Status:</b>  <code>{probe.http_status or 'N/A'}</code>",
        f"<b>Tech:</b>    {_e(tech)}",
        f"<b>Why:</b>     {_e(reasons)}",
    ]
    if probe.http_title:
        tg_lines.append(f"<b>Title:</b>   {_e(probe.http_title[:100])}")

    telegram_task = _send_telegram_message("\n".join(tg_lines))

    await _dispatch(discord_task, telegram_task)
    logger.log(
        "SUCCESS" if level == InterestLevel.CRITICAL else "INFO",
        f"[alerts] {level.value.upper()} asset flagged: {probe.domain} "
        f"| reasons={probe.interest_reasons}",
    )


async def notify_probe_summary(
    program_id:   str,
    total_probed: int,
    alive:        int,
    dead:         int,
    critical:     int,
    high:         int,
    medium:       int,
) -> None:
    """
    Send an end-of-run digest summarising what the prober found.
    Only sent if there are CRITICAL or HIGH findings to report.
    """
    if critical + high == 0:
        return

    summary = (
        f"Program `{program_id}` probe complete.\n\n"
        f"**Probed:** {total_probed}  |  **Alive:** {alive}  |  **Dead:** {dead}\n"
        f"🚨 Critical: **{critical}**  |  🔴 High: **{high}**  |  🟡 Medium: {medium}"
    )

    tg_summary = (
        f"<b>📊 ZeroPoint — Probe Summary</b>\n"
        f"Program: <code>{program_id}</code>\n\n"
        f"Probed: {total_probed} | Alive: {alive} | Dead: {dead}\n"
        f"🚨 Critical: <b>{critical}</b> | 🔴 High: <b>{high}</b> | 🟡 Medium: {medium}"
    )

    await _dispatch(
        _send_discord_embed(
            title=f"📊  Probe Summary — {program_id}",
            description=summary,
            color=_COLOR["summary"],
        ),
        _send_telegram_message(tg_summary),
    )


# ---------------------------------------------------------------------------
# Module 3: Vulnerability finding notifications
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "critical": 0xFF0000,   # Red
    "high":     0xFF6600,   # Orange
    "medium":   0xFFCC00,   # Yellow
    "low":      0x00CC44,   # Green
    "info":     0x5865F2,   # Blue
    "unknown":  0x888888,   # Grey
}

_SEV_EMOJI = {
    "critical": "🚨",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
    "unknown":  "⚪",
}


async def notify_finding(finding, program_id: str) -> None:
    """
    Fire an IMMEDIATE rich alert for a single new Nuclei finding.
    Suppressed if the same finding was already alerted within the last 7 days.
    """
    if _is_suppressed(finding):
        logger.debug(f"[alerts] Suppressed (within 7-day window): {getattr(finding, 'template_id', '')}")
        return
    sev   = finding.severity.lower() if hasattr(finding.severity, "lower") else str(finding.severity)
    emoji = _SEV_EMOJI.get(sev, "⚪")
    color = _SEV_COLOR.get(sev, 0x888888)

    refs      = " | ".join(finding.reference[:3]) if finding.reference else "—"
    tags      = ", ".join(finding.tags[:8])        if finding.tags      else "—"
    extracted = "\n".join(f"  `{r}`" for r in finding.extracted_results[:5]) or "—"

    # ── Discord: rich embed with all PoC context ──────────────────────────
    fields = [
        {"name": "Template",    "value": f"`{finding.template_id}`",              "inline": True},
        {"name": "Severity",    "value": f"{emoji} `{sev.upper()}`",              "inline": True},
        {"name": "Program",     "value": f"`{program_id}`",                       "inline": True},
        {"name": "Matched At",  "value": finding.matched_at[:120],                "inline": False},
        {"name": "Tags",        "value": tags,                                    "inline": False},
        {"name": "References",  "value": refs[:300],                              "inline": False},
    ]
    if finding.extracted_results:
        fields.append({"name": "Extracted", "value": extracted[:400], "inline": False})
    if finding.description:
        fields.append({"name": "Description", "value": finding.description[:300], "inline": False})
    if finding.curl_command:
        # Truncate curl command for Discord — full cmd is in DB
        fields.append({
            "name": "PoC (curl)",
            "value": f"```\n{finding.curl_command[:800]}\n```",
            "inline": False,
        })

    discord_coro = _send_discord_embed(
        title=f"{emoji}  {sev.upper()} — {finding.template_name}",
        description=f"**Domain:** `{finding.domain}`",
        color=color,
        fields=fields,
    )

    # ── Telegram: concise but complete ────────────────────────────────────
    tg_lines = [
        f"<b>{emoji} ZeroPoint — {_e(sev.upper())} Finding</b>",
        f"",
        f"<b>Template:</b>  <code>{_e(finding.template_id)}</code>",
        f"<b>Name:</b>      {_e(finding.template_name)}",
        f"<b>Domain:</b>    <code>{_e(finding.domain)}</code>",
        f"<b>Program:</b>   <code>{_e(program_id)}</code>",
        f"<b>Matched:</b>   {_e(finding.matched_at[:100])}",
    ]
    if finding.description:
        tg_lines.append(f"<b>Desc:</b>      {_e(finding.description[:200])}")
    if finding.reference:
        tg_lines.append(f"<b>Ref:</b>       {_e(finding.reference[0][:100])}")

    telegram_coro = _send_telegram_message("\n".join(tg_lines))

    await _dispatch(discord_coro, telegram_coro)
    logger.log(
        "SUCCESS" if sev == "critical" else "INFO",
        f"[alerts] Finding alert sent | {sev.upper()} | {finding.template_id} | {finding.domain}",
    )


async def notify_scan_summary(
    program_id:   str,
    targets:      int,
    new_findings: int,
    by_severity:  dict,   # {"critical": 2, "high": 5, ...}
    scan_run_id:  str,
) -> None:
    """
    End-of-scan digest. Only sent when there are new findings.
    """
    if new_findings == 0:
        return

    crit = by_severity.get("critical", 0)
    high = by_severity.get("high",     0)
    med  = by_severity.get("medium",   0)
    low  = by_severity.get("low",      0)

    body = (
        f"**Program:** `{program_id}`\n"
        f"**Targets scanned:** {targets}\n"
        f"**New findings:** **{new_findings}**\n\n"
        f"🚨 Critical: **{crit}**  |  🔴 High: **{high}**  "
        f"|  🟡 Medium: {med}  |  🟢 Low: {low}"
    )

    tg_body = (
        f"<b>🏁 ZeroPoint — Scan Complete</b>\n"
        f"Program: <code>{program_id}</code>\n"
        f"Targets: {targets} | New findings: <b>{new_findings}</b>\n"
        f"🚨 {crit} critical | 🔴 {high} high | 🟡 {med} medium | 🟢 {low} low"
    )

    await _dispatch(
        _send_discord_embed(
            title=f"🏁  Scan Summary — {program_id}",
            description=body,
            color=_COLOR["summary"],
        ),
        _send_telegram_message(tg_body),
    )
    logger.info(f"[alerts] Scan summary sent | program={program_id} new={new_findings}")


# ---------------------------------------------------------------------------
# Module 4: Crawler — secret and endpoint alert dispatchers
# ---------------------------------------------------------------------------

_SECRET_SEV_COLOR = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFCC00,
    "info":     0x5865F2,
}

_SECRET_SEV_EMOJI = {
    "critical": "🔑",
    "high":     "🔐",
    "medium":   "🔓",
    "info":     "🔵",
}


async def notify_secret(secret, program_id: str) -> None:
    """
    Immediate alert for a newly discovered secret/credential.
    Suppressed if already alerted within the last 7 days.
    """
    if _is_suppressed(secret):
        logger.debug(f"[alerts] Suppressed secret: {getattr(secret, 'secret_type', '')}")
        return
    sev   = secret.severity.value if hasattr(secret.severity, "value") else str(secret.severity)
    emoji = _SECRET_SEV_EMOJI.get(sev, "🔐")
    color = _SECRET_SEV_COLOR.get(sev, 0x888888)

    # Redact the middle of the secret value for safe logging
    val   = secret.secret_value
    safe_val = (val[:6] + "..." + val[-4:]) if len(val) > 12 else val[:4] + "..."

    fields = [
        {"name": "Secret Type",  "value": f"`{secret.secret_type}`",   "inline": True},
        {"name": "Severity",     "value": f"{emoji} `{sev.upper()}`",  "inline": True},
        {"name": "Program",      "value": f"`{program_id}`",           "inline": True},
        {"name": "Domain",       "value": f"`{secret.domain}`",        "inline": False},
        {"name": "Source URL",   "value": secret.source_url[:120],     "inline": False},
        {"name": "Value (partial)", "value": f"`{safe_val}`",          "inline": False},
        {"name": "Tool",         "value": secret.tool,                 "inline": True},
    ]
    if secret.context:
        fields.append({"name": "Context", "value": f"```\n{secret.context[:300]}\n```", "inline": False})

    discord_coro = _send_discord_embed(
        title=f"{emoji}  SECRET FOUND — {secret.secret_type.upper()}",
        description=f"**Domain:** `{secret.domain}`  |  **Type:** `{secret.secret_type}`",
        color=color,
        fields=fields,
    )

    tg_lines = [
        f"<b>{emoji} ZeroPoint — SECRET FOUND</b>",
        f"",
        f"<b>Type:</b>     <code>{_e(secret.secret_type)}</code>",
        f"<b>Severity:</b> <code>{_e(sev.upper())}</code>",
        f"<b>Domain:</b>   <code>{_e(secret.domain)}</code>",
        f"<b>Program:</b>  <code>{_e(program_id)}</code>",
        f"<b>URL:</b>      {_e(secret.source_url[:100])}",
        f"<b>Value:</b>    <code>{_e(safe_val)}</code>",
    ]

    await _dispatch(discord_coro, _send_telegram_message("\n".join(tg_lines)))
    logger.success(f"[alerts] Secret alert | {sev.upper()} | {secret.secret_type} | {secret.domain}")


async def notify_interesting_endpoint(endpoint, program_id: str) -> None:
    """
    Alert for a newly discovered interesting endpoint (login, API, upload, admin).
    Less urgent than secrets — batched if many arrive at once.
    `endpoint` is a CrawledEndpoint model instance.
    """
    tags_str = ", ".join(endpoint.interest_tags[:6]) or "—"
    fields   = [
        {"name": "Domain",   "value": f"`{endpoint.domain}`",  "inline": True},
        {"name": "Program",  "value": f"`{program_id}`",       "inline": True},
        {"name": "Source",   "value": endpoint.source,         "inline": True},
        {"name": "Tags",     "value": tags_str,                "inline": False},
        {"name": "URL",      "value": endpoint.url[:200],      "inline": False},
    ]

    discord_coro = _send_discord_embed(
        title=f"🕷️  New Interesting Endpoint — `{endpoint.domain}`",
        description=f"Tags: `{tags_str}`",
        color=_COLOR["info"],
        fields=fields,
    )

    tg_body = (
        f"<b>🕷️ ZeroPoint — Interesting Endpoint</b>\n"
        f"Domain: <code>{endpoint.domain}</code>\n"
        f"Tags: <code>{tags_str}</code>\n"
        f"URL: {endpoint.url[:150]}"
    )

    await _dispatch(discord_coro, _send_telegram_message(tg_body))


async def notify_crawl_summary(
    program_id:      str,
    targets:         int,
    new_endpoints:   int,
    interesting:     int,
    new_secrets:     int,
    by_severity:     dict,
) -> None:
    """End-of-crawl digest. Only fires when there are new secrets or interesting endpoints."""
    if new_secrets + new_endpoints == 0:
        return

    crit = by_severity.get("critical", 0)
    high = by_severity.get("high",     0)
    med  = by_severity.get("medium",   0)

    body = (
        f"**Program:** `{program_id}`\n"
        f"**Targets crawled:** {targets}\n"
        f"**New endpoints:** {new_endpoints}  |  **Interesting:** {interesting}\n"
        f"**New secrets:** **{new_secrets}**\n"
        f"🔑 Critical: **{crit}**  |  🔐 High: **{high}**  |  🔓 Medium: {med}"
    )

    tg_body = (
        f"<b>🕷️ ZeroPoint — Crawl Summary</b>\n"
        f"Program: <code>{program_id}</code>\n"
        f"Crawled: {targets} | New endpoints: {new_endpoints} | Interesting: {interesting}\n"
        f"Secrets: <b>{new_secrets}</b> | 🔑 {crit} crit | 🔐 {high} high | 🔓 {med} med"
    )

    await _dispatch(
        _send_discord_embed(
            title=f"🕷️  Crawl Summary — {program_id}",
            description=body,
            color=_COLOR["summary"],
        ),
        _send_telegram_message(tg_body),
    )
    logger.info(f"[alerts] Crawl summary sent | program={program_id} secrets={new_secrets}")


# ---------------------------------------------------------------------------
# Module 6: GitHub OSINT alert dispatchers
# ---------------------------------------------------------------------------

_GH_SEV_COLOR = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFCC00,
    "info":     0x5865F2,
}

_GH_SEV_EMOJI = {
    "critical": "🔑",
    "high":     "🔐",
    "medium":   "🔓",
    "info":     "🔍",
}


async def notify_github_leak(leak, program_id: str) -> None:
    """
    Immediate alert for a GitHub credential leak. Suppressed within 7-day window.
    This is the highest-signal alert — leaked production credentials are often valid.
    """
    if _is_suppressed(leak):
        logger.debug(f"[alerts] Suppressed github leak: {getattr(leak, 'match_type', '')}")
        return
    sev   = leak.severity.value if hasattr(leak.severity, "value") else str(leak.severity)
    emoji = _GH_SEV_EMOJI.get(sev, "🔐")
    color = _GH_SEV_COLOR.get(sev, 0x888888)

    # Redact middle of the match value
    val      = leak.match_value
    safe_val = (val[:6] + "..." + val[-4:]) if len(val) > 12 else val[:4] + "..."

    fields = [
        {"name": "Match Type",   "value": f"`{leak.match_type}`",      "inline": True},
        {"name": "Severity",     "value": f"{emoji} `{sev.upper()}`",  "inline": True},
        {"name": "Program",      "value": f"`{program_id}`",           "inline": True},
        {"name": "Repository",   "value": f"[{leak.repo_full_name}]({leak.repo_url})", "inline": False},
        {"name": "File",         "value": f"`{leak.file_path}`",       "inline": False},
        {"name": "Value",        "value": f"`{safe_val}`",             "inline": True},
    ]
    if leak.match_context:
        fields.append({
            "name":  "Context",
            "value": f"```\n{leak.match_context[:300]}\n```",
            "inline": False,
        })
    fields.append({"name": "View File", "value": leak.file_url[:200], "inline": False})

    discord_coro = _send_discord_embed(
        title=f"{emoji}  GITHUB LEAK — {leak.match_type.upper()}",
        description=f"**Repo:** `{leak.repo_full_name}`  |  **Domain:** `{leak.domain}`",
        color=color,
        fields=fields,
    )

    tg_lines = [
        f"<b>{emoji} ZeroPoint — GITHUB LEAK</b>",
        f"",
        f"<b>Type:</b>    <code>{_e(leak.match_type)}</code>",
        f"<b>Sev:</b>     <code>{_e(sev.upper())}</code>",
        f"<b>Domain:</b>  <code>{_e(leak.domain)}</code>",
        f"<b>Repo:</b>    {_e(leak.repo_full_name)}",
        f"<b>File:</b>    <code>{_e(leak.file_path)}</code>",
        f"<b>Value:</b>   <code>{_e(safe_val)}</code>",
        f"<b>URL:</b>     {_e(leak.file_url[:120])}",
    ]

    await _dispatch(discord_coro, _send_telegram_message("\n".join(tg_lines)))
    logger.success(
        f"[alerts] GitHub leak | {sev.upper()} | {leak.match_type} | "
        f"{leak.repo_full_name}/{leak.file_path}"
    )


async def notify_github_summary(
    program_id: str,
    new_leaks:  int,
    by_severity: dict,
    run_id:     str,
) -> None:
    """End-of-run digest for GitHub OSINT. Only fires when new leaks found."""
    if new_leaks == 0:
        return

    crit = by_severity.get("critical", 0)
    high = by_severity.get("high",     0)
    med  = by_severity.get("medium",   0)

    body = (
        f"**Program:** `{program_id}`\n"
        f"**New GitHub leaks:** **{new_leaks}**\n\n"
        f"🔑 Critical: **{crit}**  |  🔐 High: **{high}**  |  🔓 Medium: {med}"
    )

    tg_body = (
        f"<b>🐙 ZeroPoint — GitHub OSINT Complete</b>\n"
        f"Program: <code>{program_id}</code>\n"
        f"New leaks: <b>{new_leaks}</b>\n"
        f"🔑 {crit} critical | 🔐 {high} high | 🔓 {med} medium"
    )

    await _dispatch(
        _send_discord_embed(
            title=f"🐙  GitHub OSINT — {program_id}",
            description=body,
            color=_COLOR["summary"],
        ),
        _send_telegram_message(tg_body),
    )
    logger.info(f"[alerts] GitHub summary sent | program={program_id} new={new_leaks}")

# ---------------------------------------------------------------------------
# Module 7: Port Scanner alert dispatchers
# ---------------------------------------------------------------------------

_PORT_SEV_COLOR = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFCC00,
    "info":     0x5865F2,
}

_PORT_SEV_EMOJI = {
    "critical": "🚨",
    "high":     "🔴",
    "medium":   "🟡",
    "info":     "🔵",
}


async def notify_port_finding(finding, program_id: str) -> None:
    """
    Immediate alert for a newly discovered open port / exposed service.
    Fires for CRITICAL and HIGH severity findings only.
    `finding` is a PortFinding model instance.
    """
    sev   = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    emoji = _PORT_SEV_EMOJI.get(sev, "🔵")
    color = _PORT_SEV_COLOR.get(sev, 0x888888)

    svc_str = finding.service or "unknown"
    prd_str = f" ({finding.product})" if finding.product else ""

    fields = [
        {"name": "IP:Port",   "value": f"`{finding.ip}:{finding.port}/{finding.protocol}`", "inline": True},
        {"name": "Service",   "value": f"`{svc_str}{prd_str}`",                              "inline": True},
        {"name": "Severity",  "value": f"{emoji} `{sev.upper()}`",                          "inline": True},
        {"name": "Domain",    "value": f"`{finding.domain}`",                                "inline": True},
        {"name": "Program",   "value": f"`{program_id}`",                                   "inline": True},
        {"name": "Reason",    "value": finding.reason or "—",                               "inline": False},
    ]
    if finding.banner:
        fields.append({
            "name":  "Banner",
            "value": f"```\n{finding.banner[:400]}\n```",
            "inline": False,
        })

    discord_coro = _send_discord_embed(
        title=f"{emoji}  EXPOSED PORT — {finding.ip}:{finding.port}",
        description=f"**Domain:** `{finding.domain}`  |  **Service:** `{svc_str}`",
        color=color,
        fields=fields,
    )

    tg_lines = [
        f"<b>{emoji} ZeroPoint — EXPOSED PORT</b>",
        f"",
        f"<b>IP:Port:</b>  <code>{_e(finding.ip)}:{finding.port}/{finding.protocol}</code>",
        f"<b>Service:</b>  {_e(svc_str)}{_e(prd_str)}",
        f"<b>Domain:</b>   <code>{_e(finding.domain)}</code>",
        f"<b>Program:</b>  <code>{_e(program_id)}</code>",
        f"<b>Severity:</b> <code>{_e(sev.upper())}</code>",
        f"<b>Reason:</b>   {_e(finding.reason or '—')}",
    ]
    if finding.banner:
        tg_lines.append(f"<b>Banner:</b>   <code>{_e(finding.banner[:200])}</code>")

    await _dispatch(discord_coro, _send_telegram_message("\n".join(tg_lines)))
    logger.log(
        "SUCCESS" if sev == "critical" else "INFO",
        f"[alerts] Port finding alert | {sev.upper()} | "
        f"{finding.ip}:{finding.port}/{finding.protocol} | {finding.domain}",
    )


async def notify_port_scan_summary(
    program_id:   str,
    targets:      int,
    new_findings: int,
    by_severity:  dict,
    run_id:       str,
) -> None:
    """End-of-scan digest. Only fires when there are new findings."""
    if new_findings == 0:
        return

    crit = by_severity.get("critical", 0)
    high = by_severity.get("high",     0)
    med  = by_severity.get("medium",   0)

    body = (
        f"**Program:** `{program_id}`\n"
        f"**IPs scanned:** {targets}\n"
        f"**New open ports:** **{new_findings}**\n\n"
        f"🚨 Critical: **{crit}**  |  🔴 High: **{high}**  |  🟡 Medium: {med}"
    )

    tg_body = (
        f"<b>🔌 ZeroPoint — Port Scan Complete</b>\n"
        f"Program: <code>{program_id}</code>\n"
        f"IPs: {targets} | New ports: <b>{new_findings}</b>\n"
        f"🚨 {crit} critical | 🔴 {high} high | 🟡 {med} medium"
    )

    await _dispatch(
        _send_discord_embed(
            title=f"🔌  Port Scan Summary — {program_id}",
            description=body,
            color=_COLOR["summary"],
        ),
        _send_telegram_message(tg_body),
    )
    logger.info(f"[alerts] Port scan summary sent | program={program_id} new={new_findings}")


# ---------------------------------------------------------------------------
# Module 8: Google Dork Engine alert dispatchers
# ---------------------------------------------------------------------------

_DORK_SEV_COLOR = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFCC00,
    "info":     0x5865F2,
}

_DORK_SEV_EMOJI = {
    "critical": "🔍",
    "high":     "🔴",
    "medium":   "🟡",
    "info":     "🔵",
}


async def notify_dork_finding(finding, program_id: str) -> None:
    """
    Immediate alert for a newly discovered dork result.
    Fires for CRITICAL and HIGH severity results only.
    `finding` is a DorkResult model instance.
    """
    sev      = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    emoji    = _DORK_SEV_EMOJI.get(sev, "🔍")
    color    = _DORK_SEV_COLOR.get(sev, 0x888888)
    cat_str  = finding.dork_category.replace("_", " ").title()

    fields = [
        {"name": "Category",  "value": f"`{cat_str}`",          "inline": True},
        {"name": "Severity",  "value": f"{emoji} `{sev.upper()}`", "inline": True},
        {"name": "Program",   "value": f"`{program_id}`",        "inline": True},
        {"name": "Domain",    "value": f"`{finding.domain}`",    "inline": True},
        {"name": "URL",       "value": finding.url[:200],        "inline": False},
        {"name": "Why",       "value": finding.reason,           "inline": False},
    ]
    if finding.title:
        fields.append({"name": "Title", "value": finding.title[:120], "inline": False})
    if finding.snippet:
        fields.append({"name": "Snippet", "value": finding.snippet[:300], "inline": False})
    fields.append({"name": "Query", "value": f"`{finding.dork_query[:200]}`", "inline": False})

    discord_coro = _send_discord_embed(
        title=f"{emoji}  DORK FINDING — {cat_str}",
        description=f"**Domain:** `{finding.domain}`",
        color=color,
        fields=fields,
    )

    tg_lines = [
        f"<b>{emoji} ZeroPoint — DORK FINDING</b>",
        f"",
        f"<b>Category:</b> {_e(cat_str)}",
        f"<b>Severity:</b> <code>{_e(sev.upper())}</code>",
        f"<b>Domain:</b>   <code>{_e(finding.domain)}</code>",
        f"<b>Program:</b>  <code>{_e(program_id)}</code>",
        f"<b>URL:</b>      {_e(finding.url[:150])}",
        f"<b>Why:</b>      {_e(finding.reason)}",
    ]
    if finding.title:
        tg_lines.append(f"<b>Title:</b>    {_e(finding.title[:100])}")

    await _dispatch(discord_coro, _send_telegram_message("\n".join(tg_lines)))
    logger.log(
        "SUCCESS" if sev == "critical" else "INFO",
        f"[alerts] Dork alert | {sev.upper()} | {finding.dork_category} | {finding.url[:80]}",
    )


async def notify_dork_summary(
    program_id:   str,
    new_findings: int,
    by_severity:  dict,
    run_id:       str,
) -> None:
    """End-of-run digest for Google Dork scans. Only fires when new findings exist."""
    if new_findings == 0:
        return

    crit = by_severity.get("critical", 0)
    high = by_severity.get("high",     0)
    med  = by_severity.get("medium",   0)

    body = (
        f"**Program:** `{program_id}`\n"
        f"**New dork findings:** **{new_findings}**\n\n"
        f"🔍 Critical: **{crit}**  |  🔴 High: **{high}**  |  🟡 Medium: {med}"
    )

    tg_body = (
        f"<b>🔍 ZeroPoint — Dork Scan Complete</b>\n"
        f"Program: <code>{program_id}</code>\n"
        f"New findings: <b>{new_findings}</b>\n"
        f"🔍 {crit} critical | 🔴 {high} high | 🟡 {med} medium"
    )

    await _dispatch(
        _send_discord_embed(
            title=f"🔍  Dork Summary — {program_id}",
            description=body,
            color=_COLOR["summary"],
        ),
        _send_telegram_message(tg_body),
    )
    logger.info(f"[alerts] Dork summary sent | program={program_id} new={new_findings}")