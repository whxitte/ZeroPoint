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
|--------|--------|------------------------------------------|
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
