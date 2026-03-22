# ZeroPoint — Engineering Reference

> ZeroPoint is a professional-grade, autonomous bug bounty framework for 24/7 reconnaissance and vulnerability detection at $0 infrastructure cost. It orchestrates Subfinder, httpx, Nuclei, Katana, Masscan, and six other tools into a state-aware MongoDB-backed pipeline that identifies new assets, fingerprints tech stacks, discovers secrets, and executes targeted vulnerability strikes.

---

## The Completed Architecture

| Module | Component | Schedule | Engineering Highlight |
|--------|-----------|----------|-----------------------|
| 1 | Ingestion | Every 1h | Parallel Subfinder + crt.sh + Shodan with SHA-256 state-tracking (`is_new` flag) |
| 2 | Prober | Every 2h | httpx streaming + Wappalyzer fingerprinting → CRITICAL/HIGH/MEDIUM/LOW/NOISE classification |
| 3 | Scanner | Every 6h | Tech-stack-derived Nuclei template tags — targeted scan, not spray-and-pray |
| 4 | Crawler | Every 12h | Katana + waybackurls + gau for URL discovery; Shannon Entropy filtering for JS secrets |
| 5 | Orchestrator | Continuous | Independent async loop per module — slow crawl never delays urgent ingestion |
| 6 | GitHub OSINT | Every 6h | 40+ BGP dork queries via GitHub Search API for leaked credentials |
| 7 | Port Scanner | Every 24h | Masscan at 1000 pps for discovery → Nmap -sV for service fingerprint |
| 8 | Google Dork | Every 24h | 39 templates across 7 categories; Google CSE / Brave / SerpAPI providers |
| 9 | ASN Mapper | Every 24h | ipinfo.io (IP→ASN) + RIPE Stat (ASN→prefixes) — finds company-owned IP ranges |
| — | Reporter | On demand | Self-contained tabbed HTML report with severity filtering and 7-day suppression window |
| — | SaaS API | On demand | FastAPI + JWT auth + tenant isolation + rate limiting (slowapi) |

---

## Module 5: The Watchtower (Pipeline Orchestrator)

`PipelineDaemon` in `run.py` gives each module its own independent `asyncio` loop running concurrently via `asyncio.gather`. This is the critical architectural decision: a 4-hour crawl run (Module 4) cannot delay the next 1-hour ingestion cycle (Module 1) from catching a brand-new subdomain the moment it goes live.

```python
# Each module: independent async loop, independent timer
await asyncio.gather(
    self._run_module_loop("ingest"),   # fires every 1h regardless
    self._run_module_loop("probe"),    # fires every 2h regardless
    self._run_module_loop("scan"),     # fires every 6h regardless
    self._run_module_loop("crawl"),    # fires every 12h regardless
    ...
)
```

Within each module loop, programs are processed sequentially (one at a time), but module loops never block each other.

---

## Strategic Engineering Decisions

### Deduplication via SHA-256 Fingerprints

Every finding type has a deterministic dedup key:

| Collection | Key Components | Effect |
|------------|---------------|--------|
| `findings` | `template_id + domain + matched_at` | Same vuln on same endpoint = same document forever |
| `secrets` | `secret_type + domain + value[:32]` | Same credential discovered twice = no second alert |
| `endpoints` | `domain + url_path` | Query params stripped — `/api/users?page=1` = `/api/users?page=2` |
| `github_leaks` | `repo + file + match_type + value[:32]` | Same leak in same file = one alert, ever |
| `port_findings` | `ip + port + protocol` | Port re-discovered in next scan = silent update |
| `dork_results` | `domain + category + url[:80]` | Same URL from same dork type = one alert |

### 7-Day Alert Suppression

After an alert fires, `mark_*_notified()` sets:
```python
suppress_until = datetime.now(timezone.utc) + timedelta(days=7)
```
`core/alerts.py` checks `_is_suppressed(finding)` before every dispatch. The same finding never re-alerts within the 7-day window, preventing notification floods on recurring scan cycles.

### Smart Template Tag Selection (Module 3)

Rather than running all 9,000+ Nuclei templates against every host, the scanner maps detected technologies to relevant template tags:
```python
TECH_TAG_MAP = {
    "jenkins":    ["jenkins"],           # + CVE-2016-9299, CVE-2019-1003000
    "wordpress":  ["wordpress", "wp"],   # + CVE-2021-29447
    "graphql":    ["graphql"],
    ...
    "__default__": ["exposure", "misconfig", "takeover", "token", "default-login"],
}
```
This gives 10x faster scans and dramatically lower noise compared to full-library runs.

### Shannon Entropy for Secret Filtering

The JS analyzer uses Shannon entropy to separate real secrets from placeholder strings:
```python
shannon_entropy("YOUR_API_KEY_HERE")  → 3.2  # low → filtered out
shannon_entropy("sk_live_4xT9mK2p...") → 4.8  # high → kept as finding
```
Default threshold: `SECRET_MIN_ENTROPY=3.5`. Configurable in `.env`.

### Atlas M0 Compatibility

MongoDB Atlas free tier (M0) has a 30s `socketTimeoutMS` by default. ZeroPoint sets it to 120s and uses `.batch_size(200)` + `.max_time_ms(90_000)` on all report queries to prevent timeouts on large collections. Compound indexes `(program_id, severity, first_seen)` make report queries index-only.

### ASN Mapper API Selection

BGPView (`api.bgpview.io`) went offline permanently in 2024. ZeroPoint uses:
- **ipinfo.io** for IP→ASN resolution (50k free req/month, no auth)
- **RIPE Stat** for ASN→prefix lookup (unlimited, no auth)
- **RIPE Stat searchcomplete** for name-based ASN search when all IPs are CDN-proxied

### $0 Infrastructure

Everything runs in a single Python process sharing one Motor connection pool. No Celery, no Redis, no separate worker processes. The event loop handles all concurrency via asyncio. MongoDB Atlas M0 is the only external service.

---

## Module Status

| Component | Status | Notes |
|-----------|--------|-------|
| Ingestion (M1) | ✅ Active | Subfinder + crt.sh + Shodan |
| Prober (M2) | ✅ Active | httpx + FingerprintClassifier |
| Scanner (M3) | ✅ Active | Nuclei + smart template selection |
| Crawler (M4) | ✅ Active | Katana + waybackurls + JS secrets |
| Orchestrator (M5) | ✅ Active | Manual + 24/7 daemon |
| GitHub OSINT (M6) | ✅ Active | 40+ search queries per domain |
| Port Scanner (M7) | ✅ Active | Masscan → Nmap two-phase |
| Google Dork (M8) | ✅ Active | 39 templates, 3 API providers |
| ASN Mapper (M9) | ✅ Active | ipinfo.io + RIPE Stat |
| Reporter | ✅ Active | Tabbed HTML, severity filtering |
| SaaS REST API | ✅ Active | FastAPI, JWT, multi-tenant |
| Report | ✅ Active | 7-day dedup, tabbed HTML |

---

## Individual / Hacker Use (~60–70% Complete)

| Missing Feature            | Why It Matters |
|---------------------------|----------------|
| Scope Manager             | No HackerOne/Bugcrowd API sync. Users must manually add programs via `seed_programs.py`. A real product should auto-populate programs when a hunter adds their H1 username. |
| React Dashboard           | Current UI is a static HTML report generated on demand. A real product needs a live dashboard showing findings in real time. |
| User Onboarding Flow      | No signup page, no self-serve tenant creation, and no way for new users to get started without manually running `get_api_key.py`. |
| Billing                   | No Stripe integration, so you can’t charge users. |
| Program Isolation         | Tenant system exists in DB, but pipeline scripts (`ingestor.py`, `scanner.py`, etc.) don’t filter by tenant and run against all programs. |

---

## Commercial / Enterprise Use (~45% Complete)

| Missing Feature                  | Why It Matters |
|---------------------------------|----------------|
| Compliance / Audit Logs         | Enterprise buyers require SOC2-level audit trails. |
| Role-Based Access Control (RBAC)| Current model is one API key = full access. Enterprises need roles like admin, analyst, read-only, etc. |
| White-label / Custom Domains    | Companies want branded domains like `security.theirname.com`. |
| SLA + Reliability               | Atlas M0 free tier throttles under load. Enterprise requires M10+ with replicas and high availability. |
| Webhook Integrations            | Teams use tools like Jira, Slack, PagerDuty, ServiceNow — findings need to be pushed into workflows. |
| False Positive Management       | No way to mark findings as "accepted risk" or "false positive," which is essential for repeated scans. |