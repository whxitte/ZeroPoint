"""
ZeroPoint :: core/alerts.py
============================
Notification dispatcher for all ZeroPoint pipeline events.

Alert types:
  1. notify_new_assets()      — New subdomains from ingestion (Module 1)
  2. notify_high_value_probe()— CRITICAL/HIGH interest assets from prober (Module 2)
  3. notify_probe_summary()   — End-of-run stats digest

Only fires when warranted — never spam, always signal.
"""

from __future__ import annotations

import asyncio
import html
from typing import Dict, List

import aiohttp
from loguru import logger

from config import settings
from models import InterestLevel, ProbeResult, UpsertResult


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
    """Post a single embed to the configured Discord webhook."""
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

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                settings.DISCORD_WEBHOOK_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status not in (200, 204):
                    body = await resp.text()
                    logger.warning(f"Discord webhook returned {resp.status}: {body[:200]}")
    except aiohttp.ClientError as exc:
        logger.error(f"Discord notification failed: {exc}")


async def _send_telegram_message(text: str) -> None:
    """Send an HTML-formatted message via Telegram Bot API."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id":    settings.TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "HTML",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.warning(f"Telegram API returned {resp.status}: {body[:200]}")
    except aiohttp.ClientError as exc:
        logger.error(f"Telegram notification failed: {exc}")


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

    # Group by program for clean per-program messages
    by_program: Dict[str, List[UpsertResult]] = {}
    for r in new_assets:
        by_program.setdefault(r.program_id, []).append(r)

    for program_id, assets in by_program.items():
        count       = len(assets)
        domain_list = "\n".join(
            f"• `{a.domain}` [{a.source.value}]" for a in assets[:20]
        )
        if count > 20:
            domain_list += f"\n…and {count - 20} more."

        telegram_domain_list = "\n".join(
            f"• <code>{html.escape(a.domain)}</code> [{html.escape(a.source.value)}]" for a in assets[:20]
        )
        if count > 20:
            telegram_domain_list += f"\n…and {count - 20} more."



        await _dispatch(
            _send_discord_embed(
                title=f"🔍  {count} New Asset{'s' if count > 1 else ''} — {program_id}",
                description=domain_list, # Discord can handle unformatted backticks
                color=_COLOR["new_asset"],
            ),
            _send_telegram_message(
                f"<b>🔍 ZeroPoint — New Assets</b>\n"
                f"Program: <code>{program_id}</code>\n"
                f"New: <b>{count}</b>\n\n"
                + telegram_domain_list
            ),
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
        f"<b>{emoji} ZeroPoint — {level.value.upper()} Target</b>",
        f"",
        f"<b>Domain:</b>  <code>{probe.domain}</code>",
        f"<b>Program:</b> <code>{program_id}</code>",
        f"<b>Status:</b>  <code>{probe.http_status or 'N/A'}</code>",
        f"<b>Tech:</b>    {tech}",
        f"<b>Why:</b>     {reasons}",
    ]
    if probe.http_title:
        tg_lines.append(f"<b>Title:</b>   {probe.http_title[:100]}")

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
    This is the money alert — CRITICAL/HIGH fire the moment Nuclei reports them.

    `finding` is a Finding model instance (typed loosely to avoid circular import).
    """
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
        f"<b>{emoji} ZeroPoint — {sev.upper()} Finding</b>",
        f"",
        f"<b>Template:</b>  <code>{finding.template_id}</code>",
        f"<b>Name:</b>      {finding.template_name}",
        f"<b>Domain:</b>    <code>{finding.domain}</code>",
        f"<b>Program:</b>   <code>{program_id}</code>",
        f"<b>Matched:</b>   {finding.matched_at[:100]}",
    ]
    if finding.description:
        tg_lines.append(f"<b>Desc:</b>      {finding.description[:200]}")
    if finding.reference:
        tg_lines.append(f"<b>Ref:</b>       {finding.reference[0][:100]}")

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
