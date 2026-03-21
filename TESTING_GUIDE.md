# complete testing sequence

---

## Phase 1 — Individual Module Tests

### Module 1 — Ingestion
```bash
# Quick single-domain test
python3 ingestor.py --domain gitlab.com --program-id gitlab_h1

# Full program run
python3 ingestor.py --program-id gitlab_h1

# Expected: subdomains discovered, upserted to MongoDB, Discord/Telegram alert for any new ones
```

### Module 2 — Prober
```bash
# Quick single-domain test (no DB write)
python3 prober.py --domain gitlab.com

# Full program probe
python3 prober.py --program-id gitlab_h1

# Expected: HTTP status, tech stack, titles written to assets. CRITICAL/HIGH interest_level assets trigger alert
```

### Module 3 — Scanner
```bash
# Quick single-domain test (no DB write, fires alerts)
python3 scanner.py --domain juice-shop.herokuapp.com --severity critical,high,medium

# Full program scan
python3 scanner.py --program-id gitlab_h1

# Force rescan (ignore 72h interval)
python3 scanner.py --program-id gitlab_h1 --force

# Expected: Nuclei findings stored in `findings` collection, immediate alert per new finding
```

### Module 4 — Crawler
```bash
# Quick single-domain test (no DB write)
python3 crawler.py --domain gitlab.com

# Full program crawl
python3 crawler.py --program-id gitlab_h1

# Expected: endpoints in `endpoints` collection, secrets in `secrets` collection, alerts fire
```

---

## Phase 2 — Orchestrator Tests

```bash
# 1. Dry-run first — see what would run without executing
python3 run.py --program-id gitlab_h1 --dry-run

# 2. Single module through orchestrator
python3 run.py --program-id gitlab_h1 --modules ingest

# 3. Two modules chained
python3 run.py --program-id gitlab_h1 --modules ingest,probe

# 4. Three modules chained
python3 run.py --program-id gitlab_h1 --modules ingest,probe,scan

# 5. Full pipeline — all 4 modules
python3 run.py --program-id gitlab_h1

# 6. Skip a module
python3 run.py --program-id gitlab_h1 --skip crawl

# 7. Force re-run everything
python3 run.py --program-id gitlab_h1 --force

# 8. All active programs
python3 run.py

# 9. Daemon mode — let it run 5 minutes then Ctrl+C
python3 run.py --daemon --program-id gitlab_h1
```

---

## Phase 3 — Database Verification

After running the pipeline, verify data is landing correctly in MongoDB. You can check via MongoDB Atlas UI or:

```bash
# Quick Python check — run from your ZeroPoint directory
python3 - << 'EOF'
import asyncio
import db.mongo as mongo
from config import settings

async def check():
    await mongo._get_client().admin.command("ping")
    db = mongo.get_db()

    assets    = await db.assets.count_documents({})
    findings  = await db.findings.count_documents({})
    endpoints = await db.endpoints.count_documents({})
    secrets   = await db.secrets.count_documents({})
    runs      = await db.scan_runs.count_documents({})
    crawls    = await db.crawl_runs.count_documents({})

    print(f"  assets:    {assets}")
    print(f"  findings:  {findings}")
    print(f"  endpoints: {endpoints}")
    print(f"  secrets:   {secrets}")
    print(f"  scan_runs: {runs}")
    print(f"  crawl_runs:{crawls}")
    await mongo.close_connection()

asyncio.run(check())
EOF
```

---

## Phase 4 — Unit Tests

```bash
# Run all tests
pytest tests/ -v

# Run by module
pytest tests/test_ingestion.py -v
pytest tests/test_prober.py -v
pytest tests/test_scanner.py -v
pytest tests/test_crawler.py -v
```

---

## Test Github 

```bash
# Add to .env first:
GITHUB_TOKEN=ghp_your_token_here   # needs public_repo scope

# Quick test — no DB write, prints results live:
python3 github_osint.py --domain shopify.com

# Run through the orchestrator as Module 6:
python3 run.py --program-id shopify_h1 --modules github

# Launch the API server:
python3 serve.py --reload
# → Open http://localhost:8000/api/docs
```

## Is the project complete?

The **core pipeline** is complete. Here's the honest picture:

```
✅ Module 1 — Ingestion         (Subfinder + crt.sh + Shodan)
✅ Module 2 — Prober            (httpx fingerprinting)
✅ Module 3 — Scanner           (Nuclei vuln scan)
✅ Module 4 — Crawler           (Katana + Wayback + JS secrets)
✅ Module 5 — Orchestrator      (manual + daemon mode)
```

**What's NOT built** (you chose to skip these earlier):

| Feature | Value | Effort |
|---|---|---|
| **Scope Manager** | Auto-pull programs from HackerOne/Bugcrowd APIs. When a program adds a new wildcard, it triggers an immediate pipeline run. This is the "first-come-first-served" multiplier. | Medium |
| **Reporting Engine** | Generate a clean HTML report per program: all findings sorted by severity, all secrets, all interesting endpoints. Ready to review before submitting. | Medium |
| **Notification dedup window** | If the same secret/finding fires on every crawl run, you'll get flooded. A "don't re-alert for 7 days" window. | Small |
| **HTTPX re-probe on new Nuclei findings** | When Nuclei finds something interesting, immediately re-probe that specific asset to capture any changes. | Small |

The project is **production-ready as-is**. The scope manager and reporting engine are useful but you can hunt without them. Test everything above first, then tell me which of those four you want next if any.