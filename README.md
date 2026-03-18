# ZeroPoint — Enterprise Bug Bounty Automation Framework
### Module 1: The Ingestion Engine

---

```
 ______               ____        _       _
|___  /              |  _ \      (_)     | |
   / / ___ _ __ ___  | |_) | ___  _ _ __ | |_
  / / / _ \ '__/ _ \ |  __/ / _ \| | '_ \| __|
 / /_|  __/ | | (_) || |   | (_) | | | | | |_
/_____\___|_|  \___/ |_|    \___/|_|_| |_|\__|
                  State-Aware Recon Engine
```

## Architecture Overview

```
ingestor.py (Orchestrator)
    │
    ├─► modules/recon.py          ← asyncio.gather runs all tools in parallel
    │       ├── Subfinder          (subprocess, JSON output)
    │       ├── crt.sh             (aiohttp, CT logs)
    │       └── Shodan             (SDK in executor, DNS API)
    │
    ├─► db/mongo.py               ← Motor async driver, state-tracking upserts
    │       ├── ensure_indexes()
    │       ├── upsert_asset()     ← THE core state logic (is_new flag)
    │       └── bulk_upsert_assets()
    │
    └─► core/alerts.py            ← Discord + Telegram notifications
            └── notify_new_assets() ← fires ONLY on is_new=True assets
```

## The State Tracking Secret

Every discovered subdomain goes through this upsert logic:

```
domain found?
├── NO  → Insert: is_new=True, status="new", first_seen=NOW
│                 ↳ TRIGGERS notification to Discord/Telegram
└── YES → Update: is_new=False, status="active", last_seen=NOW
                  ↳ No noise. Silent update.

A "Net new assets: 0" in the ingester's summary means all discovered domains already existed in the database and were updated, not newly inserted.
```

This is what makes ZeroPoint smart — **you only get alerted when something is genuinely new**.

---

## Quick Start

### 1. Prerequisites

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # pulls ~/.nuclei-templates automatically

go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest

# Optional but recommended — SecretFinder
git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
pip install jsbeautifier requests

# Install Python deps
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — set MONGODB_URI, SHODAN_API_KEY, DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

# --- API Keys and Notification Setup ---
# SHODAN_API_KEY: Obtain from shodan.io. Required for Shodan module.
# DISCORD_WEBHOOK_URL: Create a webhook in your Discord server settings. Ensure it's a valid webhook URL.
# TELEGRAM_BOT_TOKEN:
#   1. Talk to @BotFather on Telegram, send /newbot, and follow instructions.
#   2. BotFather will give you an HTTP API token (e.g., 123456:ABC-DEF...).
# TELEGRAM_CHAT_ID:
#   1. Start a conversation with your new bot.
#   2. In your web browser, go to https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
#      (replace <YOUR_BOT_TOKEN> with your bot's token).
#   3. Look for "chat":{"id":...}. The number is your TELEGRAM_CHAT_ID.
#   (For group/channel IDs, add the bot to the group/channel, send a message, then check getUpdates. IDs are often negative).

# --- Advanced Reconnaissance Settings ---
# CRTSH_TIMEOUT: (default: 60) Timeout for crt.sh queries. Increased from default to handle slow responses.
# crt.sh Retries: (Automatic) The system automatically retries crt.sh requests on 429 (rate limit), 404 (not found), and 503 (service unavailable) HTTP errors with exponential back-off, enhancing resilience.

# --- Subfinder Configuration (Optional but Recommended) ---
# To enhance subdomain discovery, configure API keys for various services
# that Subfinder integrates with.
# For example, create a ~/.config/subfinder/provider-config.yaml file:
```

### 3. Seed your first program

```bash
# Seed a private program
python ingestor.py --seed-program example.com --program-id my_target

# Seed from a public platform
python ingestor.py \
  --seed-program target.com \
  --program-id h1_target \
  --platform hackerone \
  --program-name "Target VRP"
```

### 4. Run

```bash
# Run against all active programs
python ingestor.py

# Run against one specific program
python ingestor.py --program-id my_target

# Seed AND immediately run
python ingestor.py --seed-program example.com --program-id my_target --run-after-seed
```


### 4.1 Probe Targets

```bash
python3 prober.py --program-id shopify_h1

# Force re-probe target: Ignores last_probed timestamp and probe_status conditions to re-scan all assets.
python3 prober.py --program-id shopify_h1 --force
```

### 4.2 Scan Targets

```bash
# Module 3 — scan all CRITICAL/HIGH assets for a specific program
python3 scanner.py --program-id shopify_h1

# Module 3 — scan all active programs in DB
python3 scanner.py

# Module 3 — force rescan everything (ignores the 72h rescan interval)
python3 scanner.py --program-id shopify_h1 --force

# Module 3 — override severity for this run only
python3 scanner.py --program-id shopify_h1 --severity critical,high

# Module 3 — quick test on a single domain (no DB write, still fires alerts)
python3 scanner.py --domain juice-shop.herokuapp.com --severity critical,high,medium
```
---

## Directory Structure

```
zeropoint/
├── .env.example                      ← Template for secrets
├── .env                              ← Your actual secrets (git-ignored)
├── requirements.txt
├── config.py                         ← All settings via pydantic-settings
├── models.py                         ← Pydantic schemas (Asset, Program, ...)
├── ingestor.py                       ← CLI entry point + orchestrator
│
├── db/
│   ├── __init__.py
│   └── mongo.py                      ← All MongoDB/Motor operations
│
├── modules/
│   ├── __init__.py
│   └── recon.py                      ← Subfinder, crt.sh, Shodan wrappers
│
├── core/
│   ├── __init__.py
│   └── alerts.py                     ← Discord + Telegram notifications
│
└── logs/
    └── zeropoint.log                 ← Rotating logs (auto-created)
```

---

## MongoDB Schema

### `assets` collection

| Field            | Type       | Description                                   |
|------------------|------------|-----------------------------------------------|
| `domain`         | string     | **Unique PK** — the discovered subdomain      |
| `program_id`     | string     | Parent program reference                      |
| `sources`        | array      | `["subfinder", "crtsh", "shodan"]`            |
| `ip_addresses`   | array      | Resolved IPs (from Shodan)                    |
| `is_new`         | boolean    | **True only on first insertion** — alert flag |
| `status`         | string     | `new` / `active` / `stale`                    |
| `first_seen`     | datetime   | Set-on-insert, never overwritten              |
| `last_seen`      | datetime   | Updated on every run                          |
| `http_status`    | int        | Populated by httpx module (Module 2)          |
| `technologies`   | array      | Populated by httpx module (Module 2)          |
| `open_ports`     | array      | Populated by httpx module (Module 2)          |

### `programs` collection

| Field        | Type     | Description                          |
|--------------|----------|--------------------------------------|
| `program_id` | string   | Unique slug, e.g. `hackerone_google` |
| `name`       | string   | Human-readable name                  |
| `platform`   | string   | `hackerone`, `bugcrowd`, etc.        |
| `domains`    | array    | Root in-scope domains                |
| `wildcards`  | array    | Wildcard entries, e.g. `*.target.com`|
| `is_active`  | boolean  | Controls whether engine processes it |

---

## Pipeline Roadmap

| Module | Status | Description                              |
|--------|--------|------------------------------------------|
| 1      | ✅ Done | Ingestion Engine (this module)           |
| 2      | 🔜 Next | Enrichment Engine (httpx fingerprinting) |
| 3      | 🔜     | Vuln Scanner (Nuclei, Dalfox)            |
| 4      | 🔜     | JS Harvester (Katana, SecretFinder)      |
| 5      | 🔜     | Scheduler (APScheduler / Celery)         |

---

## Quick reference

| Intent | Command |
|--------|---------|
| Run all active programs	      | python3 ingestor.py |
| Run a specific program	      | python3 ingestor.py --program-id <program-id> |
| Seed a new program	      | python3 ingestor.py --seed-program <program-name> |
| Seed and run immediately	      | python3 ingestor.py --seed-program <program-name> --run-after-seed |
| Force re-probe a program    | python3 prober.py --program-id <program-id> --force |

---

## Coding Standards

- **Pydantic v2** for all data schemas — malformed data is rejected at the boundary
- **Loguru** for structured, rotated logs — no bare `print()` anywhere
- **Type hints** on every function signature
- **Motor** (not PyMongo) for all DB I/O — fully async, never blocks the event loop
- **Asyncio.gather** for parallel tool execution
- **Semaphore** to bound concurrency — prevents WAF bans
- **Jitter** on all network requests — randomises timing signatures
- **Modular design** — swap any tool wrapper without touching other modules

---

### Full three-module pipeline — complete reference
```
┌─────────────────────────────────────────────────────────────────┐
│  MODULE 1 — Ingestion (find subdomains)                         │
│  python3 ingestor.py --program-id shopify_h1                    │
│                                                                 │
│  What it does:                                                  │
│    • Runs Subfinder, crt.sh, Shodan in parallel                 │
│    • Upserts every subdomain into MongoDB `assets`              │
│    • Sets is_new=True on first-ever seen domains                │
│    • Fires Discord/Telegram alert for NEW subdomains only       │
│                                                                 │
│  MongoDB writes:  assets collection                             │
│  Alert trigger:   is_new=True (new subdomain discovered)        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  MODULE 2 — Prober (HTTP probe + fingerprint)                   │
│  python3 prober.py --program-id shopify_h1                      │
│                                                                 │
│  What it does:                                                  │
│    • Reads probe_status=not_probed assets from DB               │
│    • Runs httpx in batches, streams JSON results                │
│    • FingerprintClassifier assigns interest_level               │
│    • Writes http_status, tech_stack, title, cdn back to DB      │
│    • Fires alert for CRITICAL/HIGH interest assets              │
│                                                                 │
│  MongoDB writes:  assets.probe_status, assets.interest_level    │
│  Alert trigger:   interest_level = CRITICAL or HIGH             │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  MODULE 3 — Scanner (Nuclei vulnerability scan)                 │
│  python3 scanner.py --program-id shopify_h1                     │
│                                                                 │
│  What it does:                                                  │
│    • Reads interest_level=HIGH/CRITICAL + probe_status=alive    │
│    • Groups assets by tech stack, builds targeted template tags │
│    • Runs Nuclei, streams JSONL findings live                   │
│    • SHA-256 dedup — same vuln never alerts twice               │
│    • Writes findings to `findings` collection in MongoDB        │
│    • Fires immediate alert for EVERY new finding                │
│    • Sends end-of-run summary digest                            │
│                                                                 │
│  MongoDB writes:  findings collection, assets.last_scanned      │
│  Alert trigger:   every new unique finding (all severities)     │
└─────────────────────────────────────────────────────────────────┘
```
---
### Recommended run order for a program
```
# First time setup — seed your target program
python3 seed_programs.py

# Step 1 — discover all subdomains
python3 ingestor.py --program-id shopify_h1

# Step 2 — probe and fingerprint everything found
python3 prober.py --program-id shopify_h1

# Step 3 — scan everything classified as HIGH or CRITICAL
python3 scanner.py --program-id shopify_h1

# crawl endpoints + find secrets
python3 crawler.py  --program-id shopify_h1   
```
---

### 24/7 continuous monitoring (cron setup)
Run all three on a schedule so new assets are automatically discovered, probed, and scanned without you touching anything:
```bash
# Edit crontab
crontab -e

# Add these three lines:

# Module 1 — rediscover subdomains every hour
0 * * * * cd /home/sethu/PROJECTS/ZeroPoint && python3 ingestor.py >> logs/cron.log 2>&1

# Module 2 — reprobe all assets every 2 hours
30 */2 * * * cd /home/sethu/PROJECTS/ZeroPoint && python3 prober.py >> logs/cron.log 2>&1

# Module 3 — scan HIGH/CRITICAL assets every 6 hours
0 */6 * * * cd /home/sethu/PROJECTS/ZeroPoint && python3 scanner.py >> logs/cron.log 2>&1
```
---
### All CLI flags for all three modules
```
# ── Module 1 ──────────────────────────────────────────────────
python3 ingestor.py                              # all active programs
python3 ingestor.py --program-id shopify_h1      # single program
python3 ingestor.py --domain shopify.com --program-id shopify_h1  # single domain

# ── Module 2 ──────────────────────────────────────────────────
python3 prober.py                               # all active programs
python3 prober.py --program-id shopify_h1       # single program
python3 prober.py --force                       # re-probe even recently probed assets
python3 prober.py --domain api.shopify.com      # quick single-domain probe (no DB write)

# ── Module 3 ──────────────────────────────────────────────────
python3 scanner.py                              # all active programs
python3 scanner.py --program-id shopify_h1      # single program
python3 scanner.py --force                      # ignore 72h rescan interval
python3 scanner.py --severity critical,high     # tighten severity filter for this run
python3 scanner.py --domain target.com          # quick test, no DB write, still alerts

# ── Module 4 ──────────────────────────────────────────────────
python3 crawler.py --domain example.com             # Quick test on one domain (no DB write)
python3 crawler.py --program-id shopify_h1          # Crawl a specific program
python3 crawler.py --program-id shopify_h1 --force  # Force re-crawl (ignore 48h interval)
python3 crawler.py                                  # All programs

# ── Module 5 ──────────────────────────────────────────────────

python3 run.py --program-id shopify_h1                          # Full pipeline for one program (all 4 modules in sequence)
python3 run.py                                                  # Full pipeline for ALL programs in DB
python3 run.py --program-id shopify_h1 --modules ingest,probe   # Specific modules only
python3 run.py --program-id shopify_h1 --skip scan,crawl        # Skip modules
python3 run.py --program-id shopify_h1 --force                  # Force re-run (ignore all intervals)
python3 run.py --program-id shopify_h1 --severity critical,high # Override Nuclei severity for this run
python3 run.py --program-id shopify_h1 --dry-run                # Preview without executing
python3 run.py --program-id shopify_h1 --stop-on-error          # Abort pipeline if any module fails

```

## Daemon mode — 24/7 autonomous monitoring:
```bash
# Start daemon (all programs, all modules on schedule)
python3 run.py --daemon

# Daemon for one program only
python3 run.py --daemon --program-id shopify_h1

# Daemon with custom intervals
python3 run.py --daemon --ingest-interval 1800 --scan-interval 3600

# Ctrl+C or SIGTERM shuts down cleanly after current module finishes
```

### How the daemon schedules modules

Each module runs on its own independent timer — a slow crawl never delays the next ingestion:
```
Time 0h:   ingest ▶ probe ▶ scan ▶ crawl   ← all run immediately on startup
Time 1h:   ingest ▶ probe                   ← ingest interval hit
Time 2h:   ingest ▶ probe                   ← both hit
Time 6h:   ingest ▶ probe ▶ scan            ← scan interval hit
Time 12h:  ingest ▶ probe ▶ scan ▶ crawl   ← all hit again
```

New subdomain discovered at hour 1 → probed at hour 2 → scanned at hour 6 → crawled at hour 12. Maximum time from discovery to first vuln scan: **6 hours**. On a first-come-first-served bug bounty program, that's your competitive edge.

### Full 5-module system — everything you have
```
Module 1  ingestor.py  — find subdomains (Subfinder + crt.sh + Shodan)
Module 2  prober.py    — HTTP probe + fingerprint (httpx)
Module 3  scanner.py   — vuln scan (Nuclei)
Module 4  crawler.py   — endpoint discovery + JS secrets (Katana + waybackurls)
Module 5  run.py       — orchestrates all four, manual + daemon mode
```