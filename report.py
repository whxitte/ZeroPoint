"""
ZeroPoint :: report.py
=======================
Reporting Engine — generates a clean, self-contained HTML report from all
ZeroPoint findings for a given program.

The report is designed for bug bounty submission review:
  - All findings sorted by severity (CRITICAL → INFO)
  - Each section corresponds to one ZeroPoint module
  - Raw HTTP request/response (PoC) included for Nuclei findings
  - Self-contained single HTML file — no external dependencies
  - Dark theme, ready to screenshot for a report

Usage:
    python3 report.py --program-id shopify_h1
    python3 report.py --program-id shopify_h1 --output reports/shopify_2026.html
    python3 report.py --program-id shopify_h1 --severity critical,high
    python3 report.py --program-id shopify_h1 --new-only
"""

from __future__ import annotations

import argparse
import asyncio
import html as _html
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from loguru import logger

import db.mongo as mongo_ops
from config import settings


# ─────────────────────────────────────────────────────────────────────────────
# Data fetchers — pull from each collection
# ─────────────────────────────────────────────────────────────────────────────

# Maximum docs per section — keeps report size sane and avoids Atlas timeouts
_REPORT_LIMIT = 1000
_BATCH_SIZE   = 200   # fetch 200 docs per network round-trip (avoids 30s socket timeout)


async def _fetch_collection(
    collection: str,
    query:      dict,
    sort:       list,
    limit:      int = _REPORT_LIMIT,
) -> List[dict]:
    """
    Safe cursor helper for Atlas free-tier M0.

    Two layers of protection against the 30s socketTimeoutMS:
      1. max_time_ms(90_000) — tells the SERVER to abort after 90s.
         This prevents the cursor from running forever server-side.
      2. batch_size(200) — fetches 200 docs per network round trip.
         Without this, Motor tries to retrieve the entire result set
         in one call which can exceed the socket timeout for large collections.

    The socketTimeoutMS in db/mongo.py is now 120s to give headroom.
    """
    col  = mongo_ops.get_db()[collection]
    docs = []
    cursor = (
        col.find(query)
           .sort(sort)
           .limit(limit)
           .batch_size(_BATCH_SIZE)
           .max_time_ms(90_000)
    )
    async for doc in cursor:
        doc.pop("_id", None)
        docs.append(doc)
    return docs


async def fetch_program(program_id: str) -> Optional[dict]:
    col = mongo_ops.get_db()["programs"]
    doc = await col.find_one({"program_id": program_id})
    if doc:
        doc.pop("_id", None)
    return doc


async def fetch_findings(program_id: str, severities: List[str], new_only: bool) -> List[dict]:
    query: dict = {"program_id": program_id}
    if severities:
        query["severity"] = {"$in": severities}
    if new_only:
        query["is_new"] = True
    return await _fetch_collection(
        "findings", query, [("severity", 1), ("first_seen", -1)]
    )


async def fetch_secrets(program_id: str, new_only: bool) -> List[dict]:
    query: dict = {"program_id": program_id}
    if new_only:
        query["is_new"] = True
    return await _fetch_collection(
        "secrets", query, [("severity", 1), ("first_seen", -1)]
    )


async def fetch_github_leaks(program_id: str, new_only: bool) -> List[dict]:
    query: dict = {"program_id": program_id}
    if new_only:
        query["is_new"] = True
    return await _fetch_collection(
        "github_leaks", query, [("severity", 1), ("first_seen", -1)]
    )


async def fetch_dork_results(program_id: str, new_only: bool) -> List[dict]:
    query: dict = {"program_id": program_id}
    if new_only:
        query["is_new"] = True
    return await _fetch_collection(
        "dork_results", query, [("severity", 1), ("first_seen", -1)]
    )


async def fetch_port_findings(program_id: str, new_only: bool) -> List[dict]:
    query: dict = {"program_id": program_id}
    if new_only:
        query["is_new"] = True
    return await _fetch_collection(
        "port_findings", query, [("severity", 1), ("first_seen", -1)]
    )


async def fetch_endpoints(program_id: str) -> List[dict]:
    return await _fetch_collection(
        "endpoints",
        {"program_id": program_id, "is_interesting": True},
        [("first_seen", -1)],
        limit=500,
    )


async def fetch_assets_summary(program_id: str) -> dict:
    col   = mongo_ops.get_db()["assets"]
    # Use count_documents with no cursor — fast index-only operations
    total = await col.count_documents({"program_id": program_id})
    alive = await col.count_documents({"program_id": program_id, "probe_status": "alive"})
    crit  = await col.count_documents({"program_id": program_id, "interest_level": "critical"})
    high  = await col.count_documents({"program_id": program_id, "interest_level": "high"})
    return {"total": total, "alive": alive, "critical": crit, "high": high}


# ─────────────────────────────────────────────────────────────────────────────
# Severity ordering for sorting
# ─────────────────────────────────────────────────────────────────────────────

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

SEV_COLOR = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#44cc44",
    "info":     "#4488ff",
    "unknown":  "#888888",
}

SEV_BG = {
    "critical": "rgba(255,68,68,0.12)",
    "high":     "rgba(255,136,0,0.12)",
    "medium":   "rgba(255,204,0,0.10)",
    "low":      "rgba(68,204,68,0.10)",
    "info":     "rgba(68,136,255,0.10)",
    "unknown":  "rgba(136,136,136,0.10)",
}

SEV_EMOJI = {
    "critical": "🚨",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
    "unknown":  "⚪",
}


def _e(text) -> str:
    """HTML-escape a value."""
    return _html.escape(str(text or ""), quote=True)


def _sev(doc: dict, field: str = "severity") -> str:
    return str(doc.get(field, "unknown")).lower()


def _sort_by_sev(docs: List[dict], field: str = "severity") -> List[dict]:
    return sorted(docs, key=lambda d: SEV_ORDER.get(_sev(d, field), 99))


def _fmt_date(dt) -> str:
    if not dt:
        return "—"
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    return str(dt)[:19]


# ─────────────────────────────────────────────────────────────────────────────
# HTML builder
# ─────────────────────────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, "#888")
    emoji = SEV_EMOJI.get(sev, "⚪")
    return (
        f'<span class="badge" style="background:{color}22;color:{color};'
        f'border:1px solid {color}44">{emoji} {sev.upper()}</span>'
    )


def _section_header(title: str, count: int, icon: str = "🔍") -> str:
    return f"""
    <div class="section-header">
        <span class="section-icon">{icon}</span>
        <span class="section-title">{_e(title)}</span>
        <span class="section-count">{count}</span>
    </div>"""


def _empty_section(msg: str = "No findings in this category.") -> str:
    return f'<div class="empty-section">✓ {_e(msg)}</div>'


def _finding_card(doc: dict) -> str:
    sev       = _sev(doc)
    color     = SEV_COLOR.get(sev, "#888")
    bg        = SEV_BG.get(sev, "rgba(136,136,136,0.1)")
    template  = _e(doc.get("template_name") or doc.get("template_id", ""))
    domain    = _e(doc.get("domain", ""))
    matched   = _e(doc.get("matched_at", ""))
    desc      = _e(doc.get("description", ""))
    tags      = ", ".join(doc.get("tags", [])[:8])
    refs      = doc.get("reference", [])
    curl      = _e(doc.get("curl_command", ""))
    req       = _e(doc.get("request", ""))
    confirmed = doc.get("confirmed", True)
    conf_tag  = "✓ Confirmed" if confirmed else "⚠ Unconfirmed"
    conf_col  = "#44cc44" if confirmed else "#ff8800"

    refs_html = ""
    if refs:
        ref_links = " ".join(
            f'<a href="{_e(r)}" target="_blank" rel="noopener">{_e(r[:60])}</a>'
            for r in refs[:3]
        )
        refs_html = f'<div class="card-field"><span class="field-label">References</span>{ref_links}</div>'

    poc_html = ""
    if curl:
        poc_html = f'<details class="poc-block"><summary>🔧 PoC (curl command)</summary><pre class="code-block">{curl}</pre></details>'
    if req:
        poc_html += f'<details class="poc-block"><summary>📡 Raw Request</summary><pre class="code-block">{req[:2000]}</pre></details>'

    return f"""
    <div class="finding-card" style="border-left:3px solid {color};background:{bg}">
        <div class="card-header">
            {_severity_badge(sev)}
            <span class="card-title">{template}</span>
            <span class="card-conf" style="color:{conf_col}">{conf_tag}</span>
        </div>
        <div class="card-field"><span class="field-label">Domain</span><code>{domain}</code></div>
        <div class="card-field"><span class="field-label">Matched At</span><code>{matched}</code></div>
        {f'<div class="card-field"><span class="field-label">Description</span>{desc}</div>' if desc else ""}
        {f'<div class="card-field"><span class="field-label">Tags</span><span class="tag-list">{_e(tags)}</span></div>' if tags else ""}
        {refs_html}
        {poc_html}
    </div>"""


def _secret_card(doc: dict) -> str:
    sev   = _sev(doc)
    color = SEV_COLOR.get(sev, "#888")
    bg    = SEV_BG.get(sev, "rgba(136,136,136,0.1)")
    val   = str(doc.get("secret_value", ""))
    safe  = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "..."
    ctx   = _e(doc.get("context", ""))
    line  = doc.get("line_number")
    tool  = _e(doc.get("tool", ""))

    return f"""
    <div class="finding-card" style="border-left:3px solid {color};background:{bg}">
        <div class="card-header">
            {_severity_badge(sev)}
            <span class="card-title">🔑 {_e(doc.get("secret_type", ""))}</span>
        </div>
        <div class="card-field"><span class="field-label">Domain</span><code>{_e(doc.get("domain",""))}</code></div>
        <div class="card-field"><span class="field-label">Source</span><a href="{_e(doc.get("source_url",""))}" target="_blank" rel="noopener"><code>{_e(doc.get("source_url",""))[:100]}</code></a></div>
        <div class="card-field"><span class="field-label">Value (partial)</span><code class="secret-val">{_e(safe)}</code></div>
        {f'<div class="card-field"><span class="field-label">Line</span>{line}</div>' if line else ""}
        {f'<div class="card-field"><span class="field-label">Tool</span>{tool}</div>' if tool else ""}
        {f'<details class="poc-block"><summary>Context</summary><pre class="code-block">{ctx}</pre></details>' if ctx else ""}
    </div>"""


def _leak_card(doc: dict) -> str:
    sev   = _sev(doc)
    color = SEV_COLOR.get(sev, "#888")
    bg    = SEV_BG.get(sev, "rgba(136,136,136,0.1)")
    val   = str(doc.get("match_value", ""))
    safe  = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "..."
    ctx   = _e(doc.get("match_context", ""))

    return f"""
    <div class="finding-card" style="border-left:3px solid {color};background:{bg}">
        <div class="card-header">
            {_severity_badge(sev)}
            <span class="card-title">🐙 {_e(doc.get("match_type",""))}</span>
        </div>
        <div class="card-field"><span class="field-label">Repository</span><a href="{_e(doc.get("repo_url",""))}" target="_blank" rel="noopener">{_e(doc.get("repo_full_name",""))}</a></div>
        <div class="card-field"><span class="field-label">File</span><a href="{_e(doc.get("file_url",""))}" target="_blank" rel="noopener"><code>{_e(doc.get("file_path",""))}</code></a></div>
        <div class="card-field"><span class="field-label">Value (partial)</span><code class="secret-val">{_e(safe)}</code></div>
        {f'<details class="poc-block"><summary>Context</summary><pre class="code-block">{ctx}</pre></details>' if ctx else ""}
    </div>"""


def _dork_card(doc: dict) -> str:
    sev   = _sev(doc)
    color = SEV_COLOR.get(sev, "#888")
    bg    = SEV_BG.get(sev, "rgba(136,136,136,0.1)")
    return f"""
    <div class="finding-card" style="border-left:3px solid {color};background:{bg}">
        <div class="card-header">
            {_severity_badge(sev)}
            <span class="card-title">🔍 {_e(doc.get("dork_category","").replace("_"," ").title())}</span>
        </div>
        <div class="card-field"><span class="field-label">URL</span><a href="{_e(doc.get("url",""))}" target="_blank" rel="noopener"><code>{_e(doc.get("url",""))[:120]}</code></a></div>
        {f'<div class="card-field"><span class="field-label">Title</span>{_e(doc.get("title",""))}</div>' if doc.get("title") else ""}
        <div class="card-field"><span class="field-label">Reason</span>{_e(doc.get("reason",""))}</div>
        {f'<div class="card-field"><span class="field-label">Query</span><code>{_e(doc.get("dork_query",""))}</code></div>' if doc.get("dork_query") else ""}
        {f'<div class="card-field"><span class="field-label">Snippet</span><em>{_e(doc.get("snippet","")[:200])}</em></div>' if doc.get("snippet") else ""}
    </div>"""


def _port_card(doc: dict) -> str:
    sev   = _sev(doc)
    color = SEV_COLOR.get(sev, "#888")
    bg    = SEV_BG.get(sev, "rgba(136,136,136,0.1)")
    banner = _e(doc.get("banner", ""))
    return f"""
    <div class="finding-card" style="border-left:3px solid {color};background:{bg}">
        <div class="card-header">
            {_severity_badge(sev)}
            <span class="card-title">🔌 {_e(doc.get("ip",""))}:{doc.get("port","")}/{_e(doc.get("protocol","tcp"))}</span>
        </div>
        <div class="card-field"><span class="field-label">Domain</span><code>{_e(doc.get("domain",""))}</code></div>
        <div class="card-field"><span class="field-label">Service</span>{_e(doc.get("service","unknown"))} {_e(doc.get("product",""))}</div>
        <div class="card-field"><span class="field-label">Reason</span>{_e(doc.get("reason",""))}</div>
        {f'<details class="poc-block"><summary>Banner</summary><pre class="code-block">{banner[:500]}</pre></details>' if banner else ""}
    </div>"""


def _endpoint_row(doc: dict) -> str:
    tags = ", ".join(doc.get("interest_tags", [])[:5])
    return (
        f'<tr>'
        f'<td><a href="{_e(doc.get("url",""))}" target="_blank" rel="noopener">'
        f'<code>{_e(doc.get("url",""))[:100]}</code></a></td>'
        f'<td>{_e(tags)}</td>'
        f'<td>{_e(doc.get("source",""))}</td>'
        f'</tr>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# Full report renderer
# ─────────────────────────────────────────────────────────────────────────────

def render_report(
    program:      dict,
    assets:       dict,
    findings:     List[dict],
    secrets:      List[dict],
    leaks:        List[dict],
    dorks:        List[dict],
    ports:        List[dict],
    endpoints:    List[dict],
    generated_at: str,
    new_only:     bool,
) -> str:

    prog_id   = program.get("program_id", "unknown")
    prog_name = program.get("name", prog_id)
    domains   = ", ".join(program.get("domains", []))

    # Summary counts
    findings_by_sev = Counter(_sev(f) for f in findings)
    secrets_by_sev  = Counter(_sev(s) for s in secrets)
    leaks_by_sev    = Counter(_sev(l) for l in leaks)
    dorks_by_sev    = Counter(_sev(d) for d in dorks)
    ports_by_sev    = Counter(_sev(p) for p in ports)

    total_critical = sum([
        findings_by_sev.get("critical", 0), secrets_by_sev.get("critical", 0),
        leaks_by_sev.get("critical", 0), dorks_by_sev.get("critical", 0),
        ports_by_sev.get("critical", 0),
    ])
    total_high = sum([
        findings_by_sev.get("high", 0), secrets_by_sev.get("high", 0),
        leaks_by_sev.get("high", 0), dorks_by_sev.get("high", 0),
        ports_by_sev.get("high", 0),
    ])
    total_medium = sum([
        findings_by_sev.get("medium", 0), secrets_by_sev.get("medium", 0),
        leaks_by_sev.get("medium", 0), dorks_by_sev.get("medium", 0),
        ports_by_sev.get("medium", 0),
    ])

    # Sort all sections by severity
    findings  = _sort_by_sev(findings)
    secrets   = _sort_by_sev(secrets)
    leaks     = _sort_by_sev(leaks)
    dorks     = _sort_by_sev(dorks)
    ports     = _sort_by_sev(ports)

    # Build section HTML — each card gets a data-sev attribute for JS filtering
    def _finding_card_tagged(doc):
        return _finding_card(doc).replace(
            'class="finding-card"',
            f'class="finding-card" data-sev="{_sev(doc)}" data-section="vulns"', 1
        )
    def _secret_card_tagged(doc):
        return _secret_card(doc).replace(
            'class="finding-card"',
            f'class="finding-card" data-sev="{_sev(doc)}" data-section="secrets"', 1
        )
    def _leak_card_tagged(doc):
        return _leak_card(doc).replace(
            'class="finding-card"',
            f'class="finding-card" data-sev="{_sev(doc)}" data-section="leaks"', 1
        )
    def _dork_card_tagged(doc):
        return _dork_card(doc).replace(
            'class="finding-card"',
            f'class="finding-card" data-sev="{_sev(doc)}" data-section="dorks"', 1
        )
    def _port_card_tagged(doc):
        return _port_card(doc).replace(
            'class="finding-card"',
            f'class="finding-card" data-sev="{_sev(doc)}" data-section="ports"', 1
        )

    findings_html = "".join(_finding_card_tagged(f) for f in findings) or _empty_section("No Nuclei findings.")
    secrets_html  = "".join(_secret_card_tagged(s) for s in secrets)   or _empty_section("No JS secrets found.")
    leaks_html    = "".join(_leak_card_tagged(l) for l in leaks)        or _empty_section("No GitHub leaks found.")
    dorks_html    = "".join(_dork_card_tagged(d) for d in dorks)        or _empty_section("No dork results.")
    ports_html    = "".join(_port_card_tagged(p) for p in ports)        or _empty_section("No exposed ports found.")
    ep_rows       = "".join(_endpoint_row(e) for e in endpoints)

    filter_note = '<div class="filter-note">⚠ Showing new findings only (is_new=True)</div>' if new_only else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZeroPoint Report — {_e(prog_name)}</title>
<style>
  :root {{
    --bg:       #0d1117;
    --bg2:      #161b22;
    --bg3:      #21262d;
    --border:   #30363d;
    --text:     #c9d1d9;
    --text2:    #8b949e;
    --accent:   #58a6ff;
    --crit:     #ff4444;
    --high:     #ff8800;
    --med:      #ffcc00;
    --low:      #44cc44;
    --info:     #4488ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 0 0 80px 0;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1px 6px;
    font-size: 12px;
    font-family: "SF Mono", "Cascadia Code", monospace;
    word-break: break-all;
  }}
  pre.code-block {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    overflow-x: auto;
    font-size: 12px;
    font-family: "SF Mono", "Cascadia Code", monospace;
    white-space: pre-wrap;
    word-break: break-all;
    margin-top: 8px;
  }}
  /* ── Header ─────────────────────────────────────────────────────────── */
  .header {{
    background: linear-gradient(135deg, #0d1117 0%, #1a1f2e 100%);
    border-bottom: 1px solid var(--border);
    padding: 36px 60px 28px;
  }}
  .header-logo {{
    font-size: 11px;
    color: var(--text2);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }}
  .header-title {{
    font-size: 28px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
  }}
  .header-meta {{
    color: var(--text2);
    font-size: 13px;
    margin-top: 8px;
  }}

  /* ── Tab bar (replaces old stats-bar) ───────────────────────────────── */
  .tab-bar {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 60px;
    display: flex;
    gap: 0;
    align-items: stretch;
    overflow-x: auto;
    position: sticky;
    top: 0;
    z-index: 100;
  }}
  .tab {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 14px 20px 12px;
    cursor: pointer;
    border-bottom: 3px solid transparent;
    transition: all 0.15s ease;
    min-width: 70px;
    white-space: nowrap;
    user-select: none;
    position: relative;
  }}
  .tab:hover {{
    background: var(--bg3);
    border-bottom-color: var(--border);
  }}
  .tab.active {{
    border-bottom-color: var(--accent);
    background: transparent;
  }}
  .tab.active .tab-num {{ color: #fff; }}
  .tab-num {{
    font-size: 22px;
    font-weight: 700;
    line-height: 1;
    transition: color 0.15s;
  }}
  .tab-label {{
    font-size: 10px;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-top: 3px;
  }}
  .tab-num.c-all    {{ color: var(--text); }}
  .tab-num.c-crit   {{ color: var(--crit); }}
  .tab-num.c-high   {{ color: var(--high); }}
  .tab-num.c-med    {{ color: var(--med);  }}
  .tab-num.c-plain  {{ color: var(--text); }}
  .tab-divider {{
    width: 1px;
    background: var(--border);
    margin: 10px 0;
    align-self: stretch;
  }}

  /* Active tab indicator pill */
  .tab.active::after {{
    content: "";
    position: absolute;
    bottom: -1px;
    left: 0;
    right: 0;
    height: 3px;
    background: var(--accent);
    border-radius: 2px 2px 0 0;
  }}
  /* Non-clickable stat items — shown in tab bar for context but don't filter */
  .tab.stat-only {{
    cursor: default;
    opacity: 0.7;
  }}
  .tab.stat-only:hover {{
    background: transparent;
    border-bottom-color: transparent;
  }}

  /* ── Active filter badge ──────────────────────────────────────────────── */
  .active-filter-bar {{
    background: rgba(88,166,255,0.08);
    border-bottom: 1px solid rgba(88,166,255,0.2);
    padding: 8px 60px;
    font-size: 12px;
    color: var(--accent);
    display: none;
    align-items: center;
    gap: 10px;
  }}
  .active-filter-bar.visible {{ display: flex; }}
  .clear-filter {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 8px;
    cursor: pointer;
    color: var(--text2);
    font-size: 11px;
  }}
  .clear-filter:hover {{ color: #fff; }}

  /* ── Main content ─────────────────────────────────────────────────────── */
  .main {{ padding: 0 60px; max-width: 1200px; }}
  .section {{ margin-top: 36px; }}
  .section.hidden {{ display: none; }}
  .section-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
  }}
  .section-icon  {{ font-size: 18px; }}
  .section-title {{ font-size: 16px; font-weight: 600; color: #fff; flex: 1; }}
  .section-count {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2px 10px;
    font-size: 12px;
    color: var(--text2);
  }}

  /* ── Finding cards ───────────────────────────────────────────────────── */
  .finding-card {{
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 12px;
    border: 1px solid var(--border);
    transition: opacity 0.1s;
  }}
  .finding-card.filtered-out {{ display: none; }}
  .card-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    flex-wrap: wrap;
  }}
  .card-title {{
    font-weight: 600;
    color: #fff;
    font-size: 14px;
    flex: 1;
  }}
  .card-conf {{ font-size: 11px; font-weight: 600; }}
  .badge {{
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    white-space: nowrap;
  }}
  .card-field {{
    display: flex;
    gap: 10px;
    margin-bottom: 6px;
    align-items: baseline;
    flex-wrap: wrap;
  }}
  .field-label {{
    color: var(--text2);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    min-width: 90px;
    flex-shrink: 0;
  }}
  .tag-list {{ color: var(--text2); font-size: 12px; }}
  .secret-val {{ color: #ff8800; }}
  .poc-block {{
    margin-top: 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
  }}
  .poc-block summary {{
    padding: 8px 12px;
    cursor: pointer;
    color: var(--accent);
    font-size: 12px;
    user-select: none;
  }}
  .poc-block summary:hover {{ color: #fff; }}
  .empty-section {{
    color: var(--text2);
    padding: 20px;
    background: var(--bg2);
    border-radius: 8px;
    border: 1px solid var(--border);
    text-align: center;
  }}
  .no-results-msg {{
    color: var(--text2);
    padding: 16px 20px;
    background: var(--bg2);
    border-radius: 8px;
    border: 1px solid var(--border);
    text-align: center;
    display: none;
    font-size: 13px;
  }}
  .filter-note {{
    background: rgba(255,136,0,0.1);
    border: 1px solid rgba(255,136,0,0.3);
    border-radius: 6px;
    padding: 10px 16px;
    margin: 20px 0;
    color: #ff8800;
    font-size: 13px;
  }}
  /* ── Endpoint table ──────────────────────────────────────────────────── */
  .ep-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin-top: 8px;
  }}
  .ep-table th, .ep-table td {{
    border: 1px solid var(--border);
    padding: 8px 12px;
    text-align: left;
  }}
  .ep-table th {{
    background: var(--bg3);
    color: var(--text2);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .ep-table tr:hover td {{ background: var(--bg3); }}
  .footer {{
    margin-top: 60px;
    padding: 30px 60px;
    border-top: 1px solid var(--border);
    color: var(--text2);
    font-size: 12px;
    text-align: center;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-logo">ZeroPoint — Bug Bounty Reconnaissance Report</div>
  <div class="header-title">{_e(prog_name)}</div>
  <div class="header-meta">
    Program ID: <code>{_e(prog_id)}</code> &nbsp;|&nbsp;
    Domains: <code>{_e(domains)}</code> &nbsp;|&nbsp;
    Generated: {_e(generated_at)}
  </div>
</div>

<!-- Clickable Tab Bar -->
<div class="tab-bar" id="tabBar">
  <div class="tab active" data-tab="all" onclick="setTab('all')">
    <span class="tab-num c-all">ALL</span>
    <span class="tab-label">Overview</span>
  </div>
  <div class="tab-divider"></div>
  <div class="tab" data-tab="critical" onclick="setTab('critical')">
    <span class="tab-num c-crit">{total_critical}</span>
    <span class="tab-label">Critical</span>
  </div>
  <div class="tab" data-tab="high" onclick="setTab('high')">
    <span class="tab-num c-high">{total_high}</span>
    <span class="tab-label">High</span>
  </div>
  <div class="tab" data-tab="medium" onclick="setTab('medium')">
    <span class="tab-num c-med">{total_medium}</span>
    <span class="tab-label">Medium</span>
  </div>
  <div class="tab-divider"></div>
  <div class="tab-divider"></div>
  <div class="tab stat-only" title="Total assets discovered">
    <span class="tab-num c-plain">{assets.get("total",0)}</span>
    <span class="tab-label">Assets</span>
  </div>
  <div class="tab stat-only" title="Assets responding to HTTP">
    <span class="tab-num c-plain">{assets.get("alive",0)}</span>
    <span class="tab-label">Alive</span>
  </div>
  <div class="tab" data-tab="vulns" onclick="setTab('vulns')">
    <span class="tab-num c-plain">{len(findings)}</span>
    <span class="tab-label">Vulns</span>
  </div>
  <div class="tab" data-tab="secrets" onclick="setTab('secrets')">
    <span class="tab-num c-plain">{len(secrets)}</span>
    <span class="tab-label">JS Secrets</span>
  </div>
  <div class="tab" data-tab="leaks" onclick="setTab('leaks')">
    <span class="tab-num c-plain">{len(leaks)}</span>
    <span class="tab-label">GH Leaks</span>
  </div>
  <div class="tab" data-tab="dorks" onclick="setTab('dorks')">
    <span class="tab-num c-plain">{len(dorks)}</span>
    <span class="tab-label">Dork Hits</span>
  </div>
  <div class="tab" data-tab="ports" onclick="setTab('ports')">
    <span class="tab-num c-plain">{len(ports)}</span>
    <span class="tab-label">Open Ports</span>
  </div>
  <div class="tab" data-tab="endpoints" onclick="setTab('endpoints')">
    <span class="tab-num c-plain">{len(endpoints)}</span>
    <span class="tab-label">Endpoints</span>
  </div>
</div>

<!-- Active filter indicator -->
<div class="active-filter-bar" id="filterBar">
  <span id="filterLabel">Showing: ALL</span>
  <span class="clear-filter" onclick="setTab('all')">✕ Clear filter</span>
</div>

<div class="main">
{filter_note}

<div class="section" id="sec-vulns" data-section="vulns">
  {_section_header("Nuclei Vulnerability Findings", len(findings), "🎯")}
  <div class="no-results-msg" id="no-vulns">No findings match the current filter.</div>
  {findings_html}
</div>

<div class="section" id="sec-secrets" data-section="secrets">
  {_section_header("JS Secrets & Credentials", len(secrets), "🔑")}
  <div class="no-results-msg" id="no-secrets">No secrets match the current filter.</div>
  {secrets_html}
</div>

<div class="section" id="sec-leaks" data-section="leaks">
  {_section_header("GitHub OSINT Leaks", len(leaks), "🐙")}
  <div class="no-results-msg" id="no-leaks">No leaks match the current filter.</div>
  {leaks_html}
</div>

<div class="section" id="sec-dorks" data-section="dorks">
  {_section_header("Google Dork Exposures", len(dorks), "🔍")}
  <div class="no-results-msg" id="no-dorks">No dork results match the current filter.</div>
  {dorks_html}
</div>

<div class="section" id="sec-ports" data-section="ports">
  {_section_header("Exposed Ports & Services", len(ports), "🔌")}
  <div class="no-results-msg" id="no-ports">No port findings match the current filter.</div>
  {ports_html}
</div>

<div class="section" id="sec-endpoints" data-section="endpoints">
  {_section_header("Interesting Endpoints", len(endpoints), "🕷️")}
  {'<table class="ep-table"><thead><tr><th>URL</th><th>Tags</th><th>Source</th></tr></thead><tbody>' + ep_rows + '</tbody></table>' if endpoints else _empty_section("No interesting endpoints.")}
</div>

</div><!-- /main -->

<div class="footer">
  ZeroPoint v1.0 &nbsp;|&nbsp; {_e(prog_name)} &nbsp;|&nbsp; {_e(generated_at)}<br>
  <span style="color:#444">This report is confidential and intended for authorized security research only.</span>
</div>

<script>
// ─── Tab logic ────────────────────────────────────────────────────────────────
// Maps tab name → what to show/hide
const SECTION_MAP = {{
  all:       null,                        // show everything
  critical:  {{ sev: "critical" }},       // filter by severity across all sections
  high:      {{ sev: "high" }},
  medium:    {{ sev: "medium" }},
  vulns:     {{ section: "vulns" }},
  secrets:   {{ section: "secrets" }},
  leaks:     {{ section: "leaks" }},
  dorks:     {{ section: "dorks" }},
  ports:     {{ section: "ports" }},
  endpoints: {{ section: "endpoints" }},
}};

const SECTION_IDS = ["vulns","secrets","leaks","dorks","ports","endpoints"];

function setTab(tabName) {{
  // Update tab button styles
  document.querySelectorAll(".tab").forEach(t => {{
    t.classList.toggle("active", t.dataset.tab === tabName);
  }});

  const rule = SECTION_MAP[tabName];
  const filterBar  = document.getElementById("filterBar");
  const filterLabel = document.getElementById("filterLabel");

  if (tabName === "all") {{
    // Show everything
    SECTION_IDS.forEach(id => {{
      const sec = document.getElementById("sec-" + id);
      if (sec) sec.classList.remove("hidden");
    }});
    document.querySelectorAll(".finding-card").forEach(c => c.classList.remove("filtered-out"));
    document.querySelectorAll(".no-results-msg").forEach(m => m.style.display = "none");
    filterBar.classList.remove("visible");
    return;
  }}

  filterBar.classList.add("visible");

  if (rule.sev) {{
    // Severity filter — show all sections, hide non-matching cards
    const sev = rule.sev;
    filterLabel.textContent = "Showing: " + sev.toUpperCase() + " severity across all modules";

    SECTION_IDS.forEach(secId => {{
      const sec = document.getElementById("sec-" + secId);
      if (!sec) return;
      sec.classList.remove("hidden");
      const cards = sec.querySelectorAll(".finding-card");
      let visible = 0;
      cards.forEach(card => {{
        const match = card.dataset.sev === sev;
        card.classList.toggle("filtered-out", !match);
        if (match) visible++;
      }});
      // Show "no results" msg if section has cards but all filtered
      const noMsg = document.getElementById("no-" + secId);
      if (noMsg) {{
        noMsg.style.display = (cards.length > 0 && visible === 0) ? "block" : "none";
      }}
    }});

  }} else if (rule.section) {{
    // Section filter — show only that section
    const target = rule.section;
    filterLabel.textContent = "Showing: " + document.querySelector('[data-tab="' + tabName + '"] .tab-label').textContent;

    SECTION_IDS.forEach(secId => {{
      const sec = document.getElementById("sec-" + secId);
      if (!sec) return;
      if (secId === target) {{
        sec.classList.remove("hidden");
        sec.querySelectorAll(".finding-card").forEach(c => c.classList.remove("filtered-out"));
        const noMsg = document.getElementById("no-" + secId);
        if (noMsg) noMsg.style.display = "none";
      }} else {{
        sec.classList.add("hidden");
      }}
    }});
  }}
}}

// Keyboard shortcut: Escape to clear filter
document.addEventListener("keydown", e => {{
  if (e.key === "Escape") setTab("all");
}});
</script>

</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def generate_report(
    program_id: str,
    output:     Optional[str] = None,
    severities: Optional[List[str]] = None,
    new_only:   bool = False,
) -> str:
    """Generate a full HTML report for a program. Returns the output path."""
    logger.info(f"[report] Generating report for {program_id}...")

    await mongo_ops.ensure_indexes()

    # Fetch all data
    program = await fetch_program(program_id)
    if not program:
        logger.error(f"[report] Program '{program_id}' not found in DB.")
        sys.exit(1)

    sev_filter = severities or []

    # Fetch sequentially — avoids overwhelming Atlas free tier M0 with
    # 7 concurrent cursors, which causes socket timeout errors on large collections.
    # Each fetch completes before the next starts, keeping network load predictable.
    logger.info("[report] Fetching findings...")
    findings  = await fetch_findings(program_id, sev_filter, new_only)
    logger.info("[report] Fetching JS secrets...")
    secrets   = await fetch_secrets(program_id, new_only)
    logger.info("[report] Fetching GitHub leaks...")
    leaks     = await fetch_github_leaks(program_id, new_only)
    logger.info("[report] Fetching dork results...")
    dorks     = await fetch_dork_results(program_id, new_only)
    logger.info("[report] Fetching port findings...")
    ports     = await fetch_port_findings(program_id, new_only)
    logger.info("[report] Fetching endpoints...")
    endpoints = await fetch_endpoints(program_id)
    logger.info("[report] Fetching asset summary...")
    assets    = await fetch_assets_summary(program_id)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    logger.info(
        f"[report] Data fetched | "
        f"findings={len(findings)} secrets={len(secrets)} leaks={len(leaks)} "
        f"dorks={len(dorks)} ports={len(ports)} endpoints={len(endpoints)}"
    )

    html = render_report(
        program      = program,
        assets       = assets,
        findings     = findings,
        secrets      = secrets,
        leaks        = leaks,
        dorks        = dorks,
        ports        = ports,
        endpoints    = endpoints,
        generated_at = generated_at,
        new_only     = new_only,
    )

    # Determine output path
    if not output:
        os.makedirs("reports", exist_ok=True)
        safe_id = program_id.replace("/", "_")
        ts      = datetime.now().strftime("%Y%m%d_%H%M")
        output  = f"reports/{safe_id}_{ts}.html"

    with open(output, "w", encoding="utf-8") as f:
        f.write(html)

    size_kb = os.path.getsize(output) // 1024
    logger.success(
        f"[report] ✓ Report saved: {output}  ({size_kb} KB)\n"
        f"  Open in browser: file://{os.path.abspath(output)}"
    )
    return output


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZeroPoint Reporting Engine — generate HTML report from all findings"
    )
    parser.add_argument("--program-id", required=True, help="Program ID to report on")
    parser.add_argument("--output", default=None, help="Output file path (default: reports/<id>_<ts>.html)")
    parser.add_argument(
        "--severity", default=None,
        help="Comma-separated severity filter for Nuclei findings, e.g. critical,high"
    )
    parser.add_argument(
        "--new-only", action="store_true", default=False,
        help="Only include findings with is_new=True"
    )
    args = parser.parse_args()

    logger.remove()
    logger.add(sys.stderr, level="INFO", colorize=True,
               format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}")

    severities = [s.strip() for s in args.severity.split(",")] if args.severity else []

    try:
        await generate_report(
            program_id = args.program_id,
            output     = args.output,
            severities = severities,
            new_only   = args.new_only,
        )
    finally:
        await mongo_ops.close_connection()


if __name__ == "__main__":
    asyncio.run(main())