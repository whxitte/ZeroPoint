# ZeroPoint — Enterprise Bug Bounty Automation Framework

```
 ______               ____        _       _
|___  /              |  _ \      (_)     | |
   / / ___ _ __ ___  | |_) | ___  _ _ __ | |_
  / / / _ \ '__/ _ \ |  __/ / _ \| | '_ \| __|
 / /_|  __/ | | (_) || |   | (_) | | | | | |_
/_____\___|_|  \___/ |_|    \___/|_|_| |_|\__|
                  State-Aware Recon Engine
```

An autonomous, modular bug bounty pipeline that discovers assets, fingerprints infrastructure, detects vulnerabilities, and alerts you in real time — for $0 infrastructure cost.

---

## What ZeroPoint Does

Every hour it finds new subdomains. Every 2 hours it probes them. Every 6 hours it runs Nuclei and searches GitHub for leaked credentials. Every 12 hours it crawls endpoints and extracts JS secrets. Every 24 hours it scans open ports and finds Google-indexed exposures. It alerts via Discord/Telegram the moment anything new is found — and never re-alerts for the same finding within 7 days.

---

## Architecture

```
run.py  ← Single entry point: manual one-shot or 24/7 daemon
   │
   ├── Module 1  ingestor.py      Subdomain discovery
   │              ├── Subfinder   (subprocess, JSON)
   │              ├── crt.sh      (aiohttp, CT logs)
   │              └── Shodan      (SDK in thread executor)
   │
   ├── Module 2  prober.py        HTTP probe & fingerprint
   │              └── httpx       (subprocess, JSONL stream)
   │                  └── FingerprintClassifier → CRITICAL/HIGH/MEDIUM/LOW/NOISE
   │
   ├── Module 3  scanner.py       Vulnerability scanner
   │              └── Nuclei      (subprocess, JSONL stream)
   │                  └── Tech stack → smart template tag selection
   │
   ├── Module 4  crawler.py       Endpoint & secret discovery
   │              ├── Katana      (active crawl, JS-aware)
   │              ├── waybackurls (historical URLs)
   │              ├── gau         (AlienVault + Wayback + CommonCrawl)
   │              └── JS Analyzer (25 regex patterns + SecretFinder)
   │
   ├── Module 5  run.py           Pipeline orchestrator
   │              ├── Manual mode  (one-shot, any subset of modules)
   │              └── Daemon mode  (independent async loop per module)
   │
   ├── Module 6  github_osint.py  GitHub credential scanner
   │              └── 40+ dork queries → leaked .env, passwords, API keys
   │
   ├── Module 7  port_scanner.py  Port & service discovery
   │              ├── Masscan     (fast sweep, CIDR-aware)
   │              └── Nmap        (service fingerprint, banner grab)
   │
   ├── Module 8  google_dork.py   Google-indexed exposure finder
   │              └── Custom Search API → .env files, SQL dumps, admin panels
   │
   ├── Module 9  asn_mapper.py    Company IP range discovery
   │              └── BGPView API → IP → ASN → all CIDR prefixes
   │
   ├── report.py                  Tabbed HTML report generator
   └── serve.py                   REST API server (FastAPI)
```

### State-Tracking Core

Every subdomain upsert follows this logic:

```
domain found?
├── NO  → Insert: is_new=True, first_seen=NOW
│                 ↳ Fires Discord/Telegram alert immediately
└── YES → Update: last_seen=NOW (silent — no duplicate alert)

Finding alerted?
└── mark_*_notified() sets suppress_until = now + 7 days
    ↳ Same finding won't re-alert for a full week
```

SHA-256 deduplication keys (`finding_id`, `secret_id`, `leak_id`, etc.) guarantee the same vulnerability can never produce a duplicate DB document or alert across any number of scan runs.

---

## Module Status

| # | Module | File | Default Schedule | What It Finds |
|---|--------|------|-----------------|---------------|
| 1 | Ingestion | `ingestor.py` | Every 1h | New subdomains via Subfinder + crt.sh + Shodan |
| 2 | Prober | `prober.py` | Every 2h | HTTP status, tech stack, interest classification |
| 3 | Scanner | `scanner.py` | Every 6h | Nuclei vulnerabilities (tech-targeted templates) |
| 4 | Crawler | `crawler.py` | Every 12h | Endpoints, JS secrets, historical URLs |
| 5 | Orchestrator | `run.py` | Continuous | Chains all modules, manual + daemon |
| 6 | GitHub OSINT | `github_osint.py` | Every 6h | Leaked credentials in public repos |
| 7 | Port Scanner | `port_scanner.py` | Every 24h | Exposed Redis/MongoDB/Docker/K8s/ES |
| 8 | Google Dork | `google_dork.py` | Every 24h | Indexed .env files, SQL dumps, admin panels |
| 9 | ASN Mapper | `asn_mapper.py` | Every 24h | Company-owned IP ranges via BGPView |
| — | Reporter | `report.py` | On demand | Tabbed HTML report across all collections |
| — | API Server | `serve.py` | On demand | REST API for dashboards and integrations |

---

## Quick Start

### 1. Install Go Tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
nuclei -update-templates
```

### 2. System Tools

```bash
sudo apt install masscan nmap

# Allow masscan without sudo (run once)
sudo setcap cap_net_raw+ep $(which masscan)
```

### 3. Python Environment

```bash
git clone https://github.com/whxitte/ZeroPoint.git
cd ZeroPoint
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional but recommended: SecretFinder for deeper JS analysis
git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
pip install jsbeautifier requests lxml
```

### 4. Configure `.env`

```bash
cp .env.example .env
```

Minimum required settings:

```env
# MongoDB Atlas free tier (https://cloud.mongodb.com)
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=zeropoint

# At least one notification channel
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=-1001234567890
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Required for Module 1 (Shodan) and Module 6 (GitHub OSINT)
SHODAN_API_KEY=your_key
GITHUB_TOKEN=ghp_your_token   # needs public_repo scope
```

Optional:
```env
# Module 8 — Google Dork (100 free queries/day)
GOOGLE_API_KEY=AIzaSy...
GOOGLE_CSE_ID=abc123...

# Module 4 — Deeper JS analysis
SECRETFINDER_PATH=/opt/SecretFinder/SecretFinder.py
```

### 5. Seed Your First Program

```bash
python3 seed_programs.py

# Or via CLI:
python3 ingestor.py --seed-program target.com --program-id target_h1 --platform hackerone
```

---

## Running ZeroPoint

### Manual One-Shot

```bash
# Full 9-module pipeline for one program
python3 run.py --program-id target_h1

# Specific modules
python3 run.py --program-id target_h1 --modules ingest,probe,scan

# Skip modules
python3 run.py --program-id target_h1 --skip crawl,dork

# Force re-run (ignore all rescan intervals)
python3 run.py --program-id target_h1 --force

# Preview what would run without executing
python3 run.py --program-id target_h1 --dry-run

# All active programs
python3 run.py
```

### 24/7 Daemon

```bash
# All programs, all modules on schedule
python3 run.py --daemon

# Single program only
python3 run.py --daemon --program-id target_h1

# Custom intervals (seconds)
python3 run.py --daemon --ingest-interval 1800 --scan-interval 3600
```

Each module runs on its own independent async timer — a slow 4-hour crawl never delays the next hourly ingestion run.

### Individual Module CLI (Recommended First-Time Order)

```bash
python3 ingestor.py --program-id target_h1      # discover subdomains
python3 prober.py   --program-id target_h1      # probe + fingerprint
python3 scanner.py  --program-id target_h1      # Nuclei vuln scan
python3 crawler.py  --program-id target_h1      # crawl endpoints + JS
python3 github_osint.py --program-id target_h1  # search GitHub for leaks
python3 asn_mapper.py   --program-id target_h1  # map company IP ranges
python3 port_scanner.py --program-id target_h1  # scan open ports
python3 google_dork.py  --program-id target_h1  # find indexed exposures
python3 report.py       --program-id target_h1  # generate HTML report
```

### Quick Single-Target Tests (No DB Write)

```bash
python3 prober.py      --domain target.com
python3 scanner.py     --domain target.com --severity critical,high,medium
python3 crawler.py     --domain target.com
python3 github_osint.py --domain target.com
python3 asn_mapper.py  --domain target.com
python3 port_scanner.py --ip 1.2.3.4
python3 google_dork.py  --domain target.com
```

---

## HTML Report

Generates a self-contained dark-theme HTML file with clickable tabs:

```bash
python3 report.py --program-id target_h1
# → reports/target_h1_20260322_1430.html

python3 report.py --program-id target_h1 --new-only        # unreviewed only
python3 report.py --program-id target_h1 --severity critical,high
```

The tab bar lets you filter instantly:

- **ALL** — complete overview (default)
- **Critical / High / Medium** — severity filter across all modules
- **Vulns / JS Secrets / GH Leaks / Dork Hits / Open Ports / Endpoints** — per-module view

Press `Escape` to clear any active filter.

---

## REST API

```bash
python3 serve.py
# → Swagger UI at http://localhost:8000/api/docs
# → ReDoc at http://localhost:8000/api/redoc

python3 get_api_key.py   # print/rotate your API key
```

All endpoints require `X-API-Key: zp_...` or `Authorization: Bearer <jwt>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/token` | Exchange API key for JWT |
| GET | `/api/v1/programs/` | List programs |
| GET | `/api/v1/assets/?program_id=X` | List assets |
| GET | `/api/v1/assets/stats` | Asset counts by interest level |
| GET | `/api/v1/findings/?program_id=X` | Nuclei findings |
| GET | `/api/v1/findings/{id}` | Full finding with raw PoC |
| GET | `/api/v1/leaks/?program_id=X` | GitHub leaks |
| GET | `/api/v1/portfindings/?program_id=X` | Port scan results |
| GET | `/api/v1/portfindings/critical` | CRITICAL exposed services only |
| GET | `/api/v1/dorks/?program_id=X` | Google dork results |
| GET | `/api/v1/health` | DB connectivity check |

---

## Directory Structure

```
ZeroPoint/
├── config.py             ← All settings (pydantic-settings + .env)
├── models.py             ← Pydantic v2 schemas for all 9 modules
│
├── ingestor.py           ← Module 1
├── prober.py             ← Module 2
├── scanner.py            ← Module 3
├── crawler.py            ← Module 4
├── run.py                ← Module 5 (orchestrator + daemon)
├── github_osint.py       ← Module 6
├── port_scanner.py       ← Module 7
├── google_dork.py        ← Module 8
├── asn_mapper.py         ← Module 9
│
├── report.py             ← HTML report generator
├── serve.py              ← FastAPI server
├── seed_programs.py      ← Program setup utility
├── get_api_key.py        ← API key management
│
├── modules/              ← Tool wrappers
│   ├── recon.py          (Subfinder, crt.sh, Shodan)
│   ├── prober.py         (httpx)
│   ├── nuclei.py         (Nuclei)
│   ├── crawler.py        (Katana, waybackurls, gau)
│   ├── js_analyzer.py    (regex + SecretFinder)
│   ├── github_osint.py   (GitHub Search API)
│   ├── port_scanner.py   (Masscan + Nmap)
│   ├── dorker.py         (Google/Brave/SerpAPI)
│   └── asn_mapper.py     (BGPView)
│
├── core/
│   ├── alerts.py         (Discord + Telegram dispatchers)
│   ├── fingerprint.py    (Interest level classifier)
│   └── endpoint_classifier.py (Shannon entropy + URL rules)
│
├── db/
│   ├── mongo.py          (Core: programs, assets, findings indexes)
│   ├── scanner_ops.py    (Module 3 DB ops)
│   ├── crawler_ops.py    (Module 4 DB ops)
│   ├── github_ops.py     (Module 6 DB ops)
│   ├── portscan_ops.py   (Module 7 DB ops)
│   ├── dork_ops.py       (Module 8 DB ops)
│   └── asn_ops.py        (Module 9 DB ops)
│
├── api/
│   ├── main.py           (FastAPI app + rate limiting)
│   ├── auth.py           (JWT + API key auth)
│   ├── deps.py           (Shared dependencies)
│   └── routes/           (programs, assets, findings, leaks, ports, dorks)
│
├── tests/
│   ├── test_ingestion.py
│   ├── test_prober.py
│   ├── test_scanner.py
│   └── test_crawler.py
│
├── reports/              ← Generated HTML reports
└── logs/                 ← Rotating log files
```

---

## MongoDB Collections

| Collection | Dedup Key | What's Stored |
|------------|-----------|---------------|
| `programs` | `program_id` | Bug bounty program config |
| `assets` | `domain` | Every subdomain + probe data + interest level |
| `findings` | `sha256(template+domain+matched_at)` | Nuclei vulnerability findings |
| `endpoints` | `sha256(domain+url_path)` | Crawled interesting URLs |
| `secrets` | `sha256(type+domain+value[:32])` | JS secrets and credentials |
| `github_leaks` | `sha256(repo+file+type+value[:32])` | GitHub OSINT results |
| `port_findings` | `sha256(ip+port+protocol)` | Open ports and services |
| `dork_results` | `sha256(domain+category+url[:80])` | Google dork results |
| `asn_info` | `(program_id, asn_number)` | Company ASNs and IP prefixes |
| `tenants` | `tenant_id` | API key hashes (multi-tenant SaaS) |

---

## Notification System

Both Discord (rich embeds) and Telegram (HTML) receive every alert simultaneously.

| Event | Trigger |
|-------|---------|
| New subdomain | First-ever discovery of a domain |
| CRITICAL/HIGH asset | Prober classifies a target as high-value |
| Nuclei finding | Every new unique vulnerability (all severities) |
| JS secret | Every new credential found in JavaScript |
| GitHub leak | Every new leaked credential in a public repo |
| Exposed port | Every new CRITICAL/HIGH port finding |
| Dork finding | Every new CRITICAL/HIGH Google-indexed exposure |
| End-of-run summaries | After each module completes a run |

**7-day suppression**: After alerting, `suppress_until = now + 7 days` is set. The same finding is silently skipped until the window expires, preventing alert floods.

---

## Google Dork Setup (Module 8)

1. [console.cloud.google.com](https://console.cloud.google.com) → enable **Custom Search API** → create API key
2. [cse.google.com/cse](https://cse.google.com/cse) → create engine → **Search the entire web** → copy `cx` ID
3. Add to `.env`:
   ```env
   GOOGLE_API_KEY=AIzaSy...
   GOOGLE_CSE_ID=abc123...
   ```

Free tier: 100 queries/day. Alternatives: SerpAPI (100/month free), Brave Search ($5 free credit).

---

## Subfinder API Keys (Boosts Module 1)

More keys = more subdomains. Create `~/.config/subfinder/provider-config.yaml`:

```yaml
shodan:
  - YOUR_SHODAN_API_KEY
github:
  - YOUR_GITHUB_TOKEN
virustotal:
  - YOUR_VT_KEY
censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET
```

---

## Unit Tests

```bash
pytest tests/ -v                    # all tests
pytest tests/test_scanner.py -v    # specific module
```

All tests are network-free and database-free.

---

## Daily Workflow

```bash
# Start the daemon — this is all you need
python3 run.py --daemon

# When an alert fires — investigate that target
python3 scanner.py --domain flagged.target.com --severity critical,high

# Add a new program and immediately run everything
python3 ingestor.py --seed-program newprogram.com --program-id newprog_h1
python3 run.py --program-id newprog_h1 --force

# Generate a submission-ready report
python3 report.py --program-id newprog_h1
# → Open reports/newprog_h1_*.html in browser
```

---

## All CLI Flags — Complete Reference

### Module 1 — Ingestion (`ingestor.py`)
```bash
python3 ingestor.py                                        # all active programs
python3 ingestor.py --program-id shopify_h1               # single program
python3 ingestor.py --seed-program example.com \
  --program-id my_target --platform hackerone \
  --program-name "Example Corp" --run-after-seed          # seed + run immediately
```

### Module 2 — Prober (`prober.py`)
```bash
python3 prober.py                                          # all active programs
python3 prober.py --program-id shopify_h1                 # single program
python3 prober.py --program-id shopify_h1 --force         # re-probe even recent assets
python3 prober.py --domain api.shopify.com                 # quick test (no DB write)
```

### Module 3 — Scanner (`scanner.py`)
```bash
python3 scanner.py                                         # all active programs
python3 scanner.py --program-id shopify_h1                # single program
python3 scanner.py --program-id shopify_h1 --force        # ignore 72h rescan interval
python3 scanner.py --program-id shopify_h1 --severity critical,high
python3 scanner.py --domain juice-shop.herokuapp.com \
  --severity critical,high,medium                          # quick test (no DB write, alerts fire)
```

### Module 4 — Crawler (`crawler.py`)
```bash
python3 crawler.py                                         # all active programs
python3 crawler.py --program-id shopify_h1                # single program
python3 crawler.py --program-id shopify_h1 --force        # ignore 48h recrawl interval
python3 crawler.py --domain gitlab.com                     # quick test (no DB write)
```

### Module 5 — Orchestrator (`run.py`)
```bash
python3 run.py                                             # all programs, all modules
python3 run.py --program-id shopify_h1                    # single program, all modules
python3 run.py --program-id shopify_h1 --modules ingest,probe,scan
python3 run.py --program-id shopify_h1 --skip crawl,dork
python3 run.py --program-id shopify_h1 --force            # ignore all intervals
python3 run.py --program-id shopify_h1 --severity critical,high
python3 run.py --program-id shopify_h1 --dry-run          # preview, no execution
python3 run.py --program-id shopify_h1 --stop-on-error

# Daemon mode
python3 run.py --daemon
python3 run.py --daemon --program-id shopify_h1
python3 run.py --daemon --ingest-interval 1800 --probe-interval 3600 \
  --scan-interval 10800 --crawl-interval 21600 \
  --github-interval 10800 --portscan-interval 43200 \
  --dork-interval 43200 --asn-interval 43200
```

### Module 6 — GitHub OSINT (`github_osint.py`)
```bash
python3 github_osint.py                                    # all active programs
python3 github_osint.py --program-id shopify_h1           # single program
python3 github_osint.py --domain shopify.com               # quick test (no DB write)
```

### Module 7 — Port Scanner (`port_scanner.py`)
```bash
python3 port_scanner.py                                    # all active programs
python3 port_scanner.py --program-id shopify_h1           # single program
python3 port_scanner.py --ip 1.2.3.4                      # quick test (no DB write)
python3 port_scanner.py --ip 1.2.3.4 --skip-nmap          # masscan discovery only
```

### Module 8 — Google Dork (`google_dork.py`)
```bash
python3 google_dork.py                                     # all active programs
python3 google_dork.py --program-id shopify_h1            # single program
python3 google_dork.py --domain shopify.com                # quick test (no DB write)
```

### Module 9 — ASN Mapper (`asn_mapper.py`)
```bash
python3 asn_mapper.py                                      # all active programs
python3 asn_mapper.py --program-id shopify_h1             # single program
python3 asn_mapper.py --domain shopify.com                 # quick test (no DB write)
```

### Reporting (`report.py`)
```bash
python3 report.py --program-id shopify_h1                 # full report
python3 report.py --program-id shopify_h1 --new-only      # unreviewed findings only
python3 report.py --program-id shopify_h1 --severity critical,high
python3 report.py --program-id shopify_h1 \
  --output reports/shopify_submission.html
```

### API Server (`serve.py`)
```bash
python3 serve.py                                           # default 0.0.0.0:8000
python3 serve.py --port 9000
python3 serve.py --reload                                  # hot-reload (dev mode)
python3 serve.py --host 127.0.0.1                          # localhost only
python3 get_api_key.py                                     # show API key
python3 get_api_key.py --rotate                            # generate new key
```

---

## Pipeline Architecture — Data Flow

```
                    ╔══════════════════════════════════════╗
                    ║          run.py  (Module 5)          ║
                    ║   Independent async loop per module  ║
                    ╚══════════════╤═══════════════════════╝
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
    Every 1h                  Every 2h                 Every 6h
          │                        │                        │
    ┌─────▼──────┐          ┌──────▼─────┐          ┌──────▼─────┐
    │ MODULE 1   │          │ MODULE 2   │          │ MODULE 3   │
    │ Ingestor   │──────────▶  Prober   │──────────▶  Scanner  │
    │            │  new      │            │  alive+   │            │
    │ Subfinder  │  assets   │ httpx      │  interest │ Nuclei     │
    │ crt.sh     │  ▼DB      │ Wappalyzer │  ▼DB      │ tech tags  │
    │ Shodan     │           │ Classifier │           │ CVE lookup │
    └────────────┘           └────────────┘           └──────┬─────┘
                                                             │findings
                                                             ▼DB
          ┌────────────────────────┬────────────────────────┐
          │                        │                        │
    Every 12h                 Every 6h                Every 24h
          │                        │                        │
    ┌─────▼──────┐          ┌──────▼─────┐          ┌──────▼─────┐
    │ MODULE 4   │          │ MODULE 6   │          │ MODULE 7   │
    │ Crawler    │          │ GitHub     │          │ Port Scan  │
    │            │          │ OSINT      │          │            │
    │ Katana     │          │            │          │ Masscan    │
    │ wayback    │          │ 40+ dorks  │          │ Nmap -sV   │
    │ gau        │          │ API keys   │          │ banners    │
    │ JS secrets │          │ .env leaks │          │ services   │
    └─────┬──────┘          └──────┬─────┘          └──────┬─────┘
          │endpoints                │leaks                  │ports
          ▼DB                      ▼DB                    ▼DB
          │
          │         Every 24h              Every 24h
          │       ┌──────▼─────┐        ┌──────▼─────┐
          │       │ MODULE 8   │        │ MODULE 9   │
          │       │ Dork Engine│        │ ASN Mapper │
          │       │            │        │            │
          │       │ Google CSE │        │ ipinfo.io  │
          │       │ Brave API  │        │ RIPE Stat  │
          │       │ SerpAPI    │        │ IP ranges  │
          │       └──────┬─────┘        └──────┬─────┘
          │              │dorks                │prefixes
          │              ▼DB                  ▼DB (→ Module 7)
          │
          └──────────────────────────────────────┐
                                                 │
                                          ┌──────▼──────┐
                                          │  MongoDB     │
                                          │  Atlas M0    │
                                          │  (free tier) │
                                          └──────┬──────┘
                                                 │
                              ┌──────────────────┴──────────────────┐
                              │                                      │
                       ┌──────▼──────┐                      ┌───────▼─────┐
                       │ core/alerts  │                      │  report.py  │
                       │             │                      │             │
                       │ Discord     │                      │ Tabbed HTML │
                       │ Telegram    │                      │ Critical/   │
                       │ 7-day dedup │                      │ High/Medium │
                       └─────────────┘                      └─────────────┘
```

**State tracking at every stage:**
- Every domain: `is_new=True` on first insert → alert fires → `is_new=False`
- Every finding: `suppress_until = now + 7 days` after alert → no re-alert
- SHA-256 dedup keys: same vuln on same endpoint = same DB document forever

---

## Performance Notes

- **Atlas M0 free tier**: Large collection queries can take 30–90 seconds. The 120s `socketTimeoutMS` in `db/mongo.py` gives them room to complete. Compound indexes on `(program_id, severity, first_seen)` make report queries fast.
- **Rate limiting**: All tools use configurable delays. Nuclei defaults to 50 req/sec. BGPView and GitHub API calls have their own `rate_delay` settings.
- **Concurrency**: All 9 modules run independent async loops in daemon mode — a slow crawl never delays the next hourly ingestion.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Async | asyncio, Motor (async MongoDB driver) |
| Data validation | Pydantic v2 |
| Database | MongoDB Atlas M0 (free tier) |
| Logging | Loguru |
| HTTP client | aiohttp |
| API framework | FastAPI + uvicorn |
| Rate limiting | slowapi |
| Recon | Subfinder, httpx, Nuclei, Katana, waybackurls, gau |
| Port scanning | Masscan + Nmap |
| JS analysis | Custom regex (25 patterns) + SecretFinder |
| Notifications | Discord Webhooks + Telegram Bot API |