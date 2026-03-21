# ZeroPoint — Complete Testing Guide

---

## Phase 1 — Individual Module Tests

### Module 1 — Ingestion
```bash
# Quick single-domain (no DB write for domain test, DB write for program)
python3 ingestor.py --domain gitlab.com --program-id gitlab_h1   # seeds + runs
python3 ingestor.py --program-id gitlab_h1                        # full run

# Expected: subdomains discovered, upserted to MongoDB, Discord/Telegram alert for new ones
```

### Module 2 — Prober
```bash
python3 prober.py --domain gitlab.com             # no DB write
python3 prober.py --program-id gitlab_h1          # full program probe
python3 prober.py --program-id gitlab_h1 --force  # re-probe all regardless of last_probed

# Expected: http_status, tech stack, interest_level written to assets collection
# CRITICAL/HIGH interest_level assets trigger immediate alert
```

### Module 3 — Scanner
```bash
# Quick test — no DB write, alerts still fire
python3 scanner.py --domain juice-shop.herokuapp.com --severity critical,high,medium

# Full program
python3 scanner.py --program-id gitlab_h1
python3 scanner.py --program-id gitlab_h1 --force              # ignore 72h interval
python3 scanner.py --program-id gitlab_h1 --severity critical,high

# Expected: findings in `findings` collection, alert per new finding (all severities)
```

### Module 4 — Crawler
```bash
python3 crawler.py --domain gitlab.com             # no DB write
python3 crawler.py --program-id gitlab_h1
python3 crawler.py --program-id gitlab_h1 --force  # ignore 48h interval

# Expected: endpoints in `endpoints`, secrets in `secrets`, alerts fire for each
```

### Module 6 — GitHub OSINT
```bash
# Add to .env first: GITHUB_TOKEN=ghp_... (public_repo scope)
python3 github_osint.py --domain shopify.com     # no DB write
python3 github_osint.py --program-id shopify_h1
```

### Module 7 — Port Scanner
```bash
# One-time setup (allows masscan without sudo):
sudo setcap cap_net_raw+ep $(which masscan)

python3 port_scanner.py --ip 1.2.3.4             # no DB write
python3 port_scanner.py --ip 1.2.3.4 --skip-nmap # masscan only, faster
python3 port_scanner.py --program-id gitlab_h1
```

### Module 8 — Google Dork
```bash
# Setup in .env: GOOGLE_API_KEY + GOOGLE_CSE_ID (or SERPAPI_KEY or BRAVE_SEARCH_API_KEY)
python3 google_dork.py --domain gitlab.com        # no DB write
python3 google_dork.py --program-id gitlab_h1
```

### Module 9 — ASN Mapper
```bash
# Uses ipinfo.io + RIPE Stat (both free, no auth required)
python3 asn_mapper.py --domain gitlab.com         # no DB write
python3 asn_mapper.py --program-id gitlab_h1
# Expected: company-owned IP ranges stored in asn_info collection
# These are automatically picked up by Module 7 on the next port scan run
```

### Reporting
```bash
python3 report.py --program-id gitlab_h1
python3 report.py --program-id gitlab_h1 --new-only
python3 report.py --program-id gitlab_h1 --severity critical,high
# Opens: reports/gitlab_h1_<timestamp>.html
# Tabs: ALL | Critical | High | Medium | Vulns | JS Secrets | GH Leaks | Dork Hits | Open Ports | Endpoints
# Non-clickable stats: Assets | Alive
```

---

## Phase 2 — Orchestrator Tests

```bash
# 1. Dry-run — preview without executing
python3 run.py --program-id gitlab_h1 --dry-run

# 2. Single module via orchestrator
python3 run.py --program-id gitlab_h1 --modules ingest
python3 run.py --program-id gitlab_h1 --modules probe
python3 run.py --program-id gitlab_h1 --modules scan

# 3. Module chains
python3 run.py --program-id gitlab_h1 --modules ingest,probe
python3 run.py --program-id gitlab_h1 --modules ingest,probe,scan
python3 run.py --program-id gitlab_h1 --modules asn,portscan   # ASN feeds port scanner

# 4. Full 9-module pipeline
python3 run.py --program-id gitlab_h1

# 5. Skip modules
python3 run.py --program-id gitlab_h1 --skip crawl,dork,asn

# 6. Force re-run everything
python3 run.py --program-id gitlab_h1 --force

# 7. All active programs
python3 run.py

# 8. Daemon mode — run 5 minutes then Ctrl+C
python3 run.py --daemon --program-id gitlab_h1
```

---

## Phase 3 — Database Verification

```bash
python3 - << 'EOF'
import asyncio
import db.mongo as mongo

async def check():
    await mongo._get_client().admin.command("ping")
    db = mongo.get_db()
    print(f"  assets:         {await db.assets.count_documents({})}")
    print(f"  findings:       {await db.findings.count_documents({})}")
    print(f"  endpoints:      {await db.endpoints.count_documents({})}")
    print(f"  secrets:        {await db.secrets.count_documents({})}")
    print(f"  github_leaks:   {await db.github_leaks.count_documents({})}")
    print(f"  port_findings:  {await db.port_findings.count_documents({})}")
    print(f"  dork_results:   {await db.dork_results.count_documents({})}")
    print(f"  asn_info:       {await db.asn_info.count_documents({})}")
    print(f"  scan_runs:      {await db.scan_runs.count_documents({})}")
    print(f"  crawl_runs:     {await db.crawl_runs.count_documents({})}")
    await mongo.close_connection()

asyncio.run(check())
EOF
```

---

## Phase 4 — REST API Tests

```bash
# Start the server
python3 serve.py --reload

# Get your API key
python3 get_api_key.py

# Health check (no auth)
curl http://localhost:8000/api/v1/health

# List programs
curl http://localhost:8000/api/v1/programs/ -H "X-API-Key: zp_..."

# Assets for a program
curl "http://localhost:8000/api/v1/assets/?program_id=gitlab_h1&probe_status=alive" \
  -H "X-API-Key: zp_..."

# Critical findings
curl "http://localhost:8000/api/v1/findings/?program_id=gitlab_h1&severity=critical" \
  -H "X-API-Key: zp_..."

# Port scan results
curl "http://localhost:8000/api/v1/portfindings/critical?program_id=gitlab_h1" \
  -H "X-API-Key: zp_..."

# Interactive docs
open http://localhost:8000/api/docs
```

---

## Phase 5 — Unit Tests

```bash
pytest tests/ -v
pytest tests/test_ingestion.py -v
pytest tests/test_prober.py -v
pytest tests/test_scanner.py -v
pytest tests/test_crawler.py -v
```

All tests are network-free and database-free.

---

## Recommended First-Run Sequence

```bash
# 1. Verify MongoDB is reachable
python3 -c "import asyncio; import db.mongo as m; asyncio.run(m._get_client().admin.command('ping')); print('MongoDB OK')"

# 2. Seed your target program
python3 seed_programs.py   # edit this file first with your targets

# 3. Run the full pipeline once manually in order
python3 ingestor.py    --program-id target_h1   # ~5 min — find subdomains
python3 prober.py      --program-id target_h1   # ~10 min — probe + fingerprint
python3 asn_mapper.py  --program-id target_h1   # ~2 min — map IP ranges
python3 port_scanner.py --program-id target_h1  # ~15 min — scan ports
python3 scanner.py     --program-id target_h1   # ~30 min — Nuclei vuln scan
python3 crawler.py     --program-id target_h1   # ~20 min — crawl + JS secrets
python3 github_osint.py --program-id target_h1  # ~5 min — GitHub search
python3 google_dork.py  --program-id target_h1  # ~5 min — Google dork

# 4. Review your findings
python3 report.py --program-id target_h1
open reports/target_h1_*.html

# 5. Start the daemon for continuous monitoring
python3 run.py --daemon --program-id target_h1
```

---

## Project Status

| Module | Status | What It Does |
|--------|--------|--------------|
| M1 — Ingestion | ✅ Complete | Subfinder + crt.sh + Shodan |
| M2 — Prober | ✅ Complete | httpx + tech fingerprinting |
| M3 — Scanner | ✅ Complete | Nuclei with smart template selection |
| M4 — Crawler | ✅ Complete | Katana + waybackurls + JS secrets |
| M5 — Orchestrator | ✅ Complete | Manual + 24/7 daemon |
| M6 — GitHub OSINT | ✅ Complete | 40+ credential leak queries |
| M7 — Port Scanner | ✅ Complete | Masscan + Nmap two-phase |
| M8 — Google Dork | ✅ Complete | 39 templates, 3 API providers |
| M9 — ASN Mapper | ✅ Complete | ipinfo.io + RIPE Stat |
| Reporter | ✅ Complete | Tabbed HTML, severity filter |
| SaaS REST API | ✅ Complete | FastAPI, JWT, multi-tenant |
| 7-day alert dedup | ✅ Complete | suppress_until on all findings |