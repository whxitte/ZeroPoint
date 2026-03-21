# ZeroPoint REST API — Complete Guide

The ZeroPoint REST API exposes all pipeline data over HTTP. Use it to build dashboards, integrate with external tools, or query findings programmatically.

**Swagger UI (interactive):** `http://localhost:8000/api/docs`  
**ReDoc (clean reference):** `http://localhost:8000/api/redoc`  
**OpenAPI schema:** `http://localhost:8000/api/openapi.json`

FastAPI auto-generates docs from route decorators, Pydantic models, and docstrings — no separate documentation to maintain.

---

## 1. Start the API Server

```bash
python3 serve.py                    # default: 0.0.0.0:8000
python3 serve.py --reload           # hot-reload for development
python3 serve.py --port 9000        # custom port
python3 serve.py --host 127.0.0.1   # localhost only (more secure)
```

---

## 2. Get Your API Key

On first start, the server creates a default tenant and prints the key. If you missed it:

```bash
python3 get_api_key.py          # show current key (from .env) or create one
python3 get_api_key.py --rotate # generate a new key (invalidates old one)
```

Add to `.env`:
```env
ZEROPOINT_API_KEY=zp_your_key_here
```

---

## 3. Authentication

All endpoints except `/api/v1/health` require authentication.

### Method A — API Key (for scripts and curl)
```bash
curl http://localhost:8000/api/v1/programs/ \
  -H "X-API-Key: zp_your_key"
```

### Method B — JWT Bearer Token (for browsers and dashboards)
```bash
# Exchange API key for JWT
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "default", "api_key": "zp_your_key"}'

# Use the JWT
curl http://localhost:8000/api/v1/programs/ \
  -H "Authorization: Bearer eyJhbGci..."
```

JWT tokens expire after 24 hours (configurable: `API_TOKEN_EXPIRE_MINUTES` in `.env`).

---

## 4. Endpoints Reference

### System

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/health` | None | DB connectivity check |
| POST | `/api/v1/auth/token` | None | Exchange API key for JWT |

```bash
curl http://localhost:8000/api/v1/health
# → {"status": "ok", "db": "connected", "version": "1.0.0"}
```

---

### Programs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/programs/` | List all active programs |
| POST | `/api/v1/programs/` | Create a program |
| GET | `/api/v1/programs/{program_id}` | Get one program |
| DELETE | `/api/v1/programs/{program_id}` | Deactivate a program |

```bash
# List
curl http://localhost:8000/api/v1/programs/ -H "X-API-Key: zp_..."

# Create
curl -X POST http://localhost:8000/api/v1/programs/ \
  -H "X-API-Key: zp_..." -H "Content-Type: application/json" \
  -d '{"program_id": "tesla_h1", "name": "Tesla", "platform": "hackerone",
       "domains": ["tesla.com"], "wildcards": ["*.tesla.com"]}'
```

---

### Assets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets/` | List assets with filters |
| GET | `/api/v1/assets/stats` | Count by interest level |

Query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `program_id` | string | **Required** |
| `interest_level` | string | `critical`, `high`, `medium`, `low`, `noise` |
| `probe_status` | string | `alive`, `dead`, `not_probed` |
| `limit` | int | Default: 100, max: 1000 |
| `skip` | int | Pagination offset |

```bash
curl "http://localhost:8000/api/v1/assets/?program_id=shopify_h1&interest_level=critical&probe_status=alive" \
  -H "X-API-Key: zp_..."

curl "http://localhost:8000/api/v1/assets/stats?program_id=shopify_h1" \
  -H "X-API-Key: zp_..."
```

---

### Findings (Nuclei)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/findings/` | List findings |
| GET | `/api/v1/findings/stats/summary` | Count by severity |
| GET | `/api/v1/findings/{finding_id}` | Full finding with raw PoC |

Query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `program_id` | string | **Required** |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `is_new` | bool | Only unreviewed findings |
| `limit` | int | Default: 50, max: 500 |
| `skip` | int | Offset |

```bash
curl "http://localhost:8000/api/v1/findings/?program_id=shopify_h1&severity=critical&is_new=true" \
  -H "X-API-Key: zp_..."

# Full PoC (includes raw HTTP request/response)
curl "http://localhost:8000/api/v1/findings/abc123..." -H "X-API-Key: zp_..."

curl "http://localhost:8000/api/v1/findings/stats/summary?program_id=shopify_h1" \
  -H "X-API-Key: zp_..."
```

---

### GitHub Leaks

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/leaks/` | List GitHub OSINT leaks |
| GET | `/api/v1/leaks/stats` | Count by severity |

```bash
curl "http://localhost:8000/api/v1/leaks/?program_id=shopify_h1&severity=critical" \
  -H "X-API-Key: zp_..."

curl "http://localhost:8000/api/v1/leaks/?program_id=shopify_h1&match_type=env_file&is_new=true" \
  -H "X-API-Key: zp_..."
```

---

### Port Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/portfindings/` | List port scan results |
| GET | `/api/v1/portfindings/stats` | Count by severity + top services |
| GET | `/api/v1/portfindings/critical` | CRITICAL exposed services only |
| GET | `/api/v1/portfindings/{finding_id}` | Single port finding |

```bash
curl "http://localhost:8000/api/v1/portfindings/?program_id=shopify_h1&severity=critical" \
  -H "X-API-Key: zp_..."

# CRITICAL only — unauthenticated Redis, MongoDB, Docker API, Elasticsearch
curl "http://localhost:8000/api/v1/portfindings/critical?program_id=shopify_h1" \
  -H "X-API-Key: zp_..."
```

---

### Google Dork Results

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dorks/` | List dork results |
| GET | `/api/v1/dorks/stats` | Count by severity and category |
| GET | `/api/v1/dorks/exposed-files` | `.env`, `.sql`, backup files |
| GET | `/api/v1/dorks/{result_id}` | Single dork result |

```bash
curl "http://localhost:8000/api/v1/dorks/?program_id=shopify_h1&severity=critical" \
  -H "X-API-Key: zp_..."

curl "http://localhost:8000/api/v1/dorks/exposed-files?program_id=shopify_h1" \
  -H "X-API-Key: zp_..."
```

---

## 5. Python Client Example

```python
import httpx

BASE    = "http://localhost:8000/api/v1"
HEADERS = {"X-API-Key": "zp_your_key"}

# Critical findings
findings = httpx.get(
    f"{BASE}/findings/",
    params={"program_id": "shopify_h1", "severity": "critical"},
    headers=HEADERS,
).json()["findings"]

for f in findings:
    print(f"{f['severity'].upper()} | {f['template_id']} | {f['matched_at']}")

# CRITICAL exposed ports
ports = httpx.get(
    f"{BASE}/portfindings/critical",
    params={"program_id": "shopify_h1"},
    headers=HEADERS,
).json()["findings"]

for p in ports:
    print(f"{p['ip']}:{p['port']} — {p['service']} — {p['reason']}")
```

---

## 6. Multi-Tenancy (SaaS Mode)

Every document has a `tenant_id` field. For personal use it's always `"default"`. To onboard a client:

```python
import asyncio, hashlib, secrets
import motor.motor_asyncio
from config import settings

async def create_tenant(tenant_id: str, name: str):
    client  = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGODB_URI)
    db      = client[settings.MONGODB_DB]
    raw_key = f"zp_{secrets.token_urlsafe(32)}"
    await db["tenants"].insert_one({
        "tenant_id":    tenant_id,
        "name":         name,
        "api_key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "is_active":    True,
        "plan":         "professional",
    })
    print(f"API Key for {tenant_id}: {raw_key}")
    client.close()

asyncio.run(create_tenant("acme_corp", "Acme Corporation"))
```

Each tenant's API key scopes every query to their data only — they cannot see other tenants' programs, assets, or findings.

---

## 7. `.env` Config Reference

```env
# API server
API_HOST=0.0.0.0
API_PORT=8000
API_SECRET_KEY=change-me-before-exposing-to-network   # signs all JWTs
API_TOKEN_EXPIRE_MINUTES=1440                          # JWT TTL — 24h
API_CORS_ORIGINS=http://localhost:3000                 # dashboard origin

# Personal API key
ZEROPOINT_API_KEY=zp_your_key_here
```

> **Security**: Change `API_SECRET_KEY` before exposing the server to any network. Anyone with this key can forge JWT tokens.