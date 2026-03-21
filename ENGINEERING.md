```
ZeroPoint is a professional-grade, autonomous bug bounty framework designed for 24/7 reconnaissance and vulnerability detection with $0 infrastructure cost. By orchestrating a modular stack—including Subfinder, httpx, Nuclei, and Katana—into a state-aware MongoDB-backed pipeline, ZeroPoint identifies new assets, fingerprints tech stacks, and executes targeted security strikes. The system prioritizes stealth and efficiency, utilizing Shannon Entropy for secret discovery and independent async scheduling to ensure continuous monitoring without resource contention.
```

### Module 5: The Watchtower (Pipeline Orchestrator)
Independent async loops for each module in PipelineDaemon is a high-level engineering choice; it ensures that a time-heavy Module 4 (Crawl) doesn't delay the mission-critical Module 1 (Ingest) from catching a brand-new subdomain the moment it goes live.

#### ZeroPoint: The Completed Architecture
| Module     | Component  | Schedule        | Engineering Highlight                                                                 |
|------------|-----------|-----------------|----------------------------------------------------------------------------------------|
| 1          | Ingestion | Every 1 Hour    | Parallel execution of Subfinder, Shodan, and crt.sh with state-aware "is_new" tracking |
| 2          | Prober    | Every 2 Hours   | Smart fingerprinting and interest classification (CRITICAL/HIGH/MEDIUM)              |
| 3          | Scanner   | Every 6 Hours   | Targeted Nuclei strikes using tech-stack-derived template tags to maximize signal    |
| 4          | Crawler   | Every 12 Hours  | Deep active and historical crawling for JS secrets with Shannon Entropy filtering    |
| 5          | Watchtower| Continuous      | Autonomous daemon managing independent duty cycles and graceful shutdowns            |
| 6          | github  | Every 6 Hours  | Leaked credentials on GitHub                          |
| 7          | portscan| Every 24 Hours  | Exposed Redis/MongoDB/Docker/K8s                                        |
| 8          | Google Dork| Every 24 Hours  | Indexed .env files, SQL dumps, keys                                        |

---

### Strategic Operational Insights

- The First-Mover Advantage: Your 1-hour ingestion cycle is aggressive but necessary. In modern bug bounty, the "time-to-duplicate" can be as low as 2–4 hours. By catching and fingerprinting assets every hour, you are significantly more likely to be the first person to report a vulnerability.

- Resource Optimization: By running everything in a single Python process sharing one MongoDB connection pool, you’ve eliminated the overhead of constant process spawning, making this framework perfectly suited for a $0 home lab or a small, free-tier VPS.

- Clean De-duplication: The SHA-256 fingerprinting for vulnerabilities (Module 3) and endpoints (Module 4) ensures that your Discord/Telegram notifications remain "high signal." You will only ever be alerted to something truly new.

### Modules status

| Component | Status     | Purpose                                      |
|-----------|------------|----------------------------------------------|
| Ingestion | ✅ Active  | Subdomain discovery via 3+ sources.          |
| Probing   | ✅ Active  | Liveness & Fingerprinting.                   |
| Scanning  | ✅ Active  | Targeted Nuclei strikes.                     |
| Crawling  | ✅ Active  | JS secret harvesting.                        |
| OSINT     | ✅ Active  | Continuous GitHub surveillance.              |
| SaaS API  | ✅ Active  | Multi-tenant REST backend.                   |