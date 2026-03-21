# ZeroPoint REST API — Complete Guide

The ZeroPoint REST API exposes all pipeline data over HTTP. You can use it to build dashboards, integrate with other tools, or query findings programmatically.

**Swagger UI (interactive docs):** `http://localhost:8000/api/docs`  
**ReDoc (clean reference):** `http://localhost:8000/api/redoc`

FastAPI auto-generates these docs directly from the route code — every endpoint, parameter, and response schema is documented automatically. You don't maintain docs separately; the code is the docs.

---

## 1. Start the API Server

```bash
# Install deps first (one time):
pip install -r requirements.txt

# Start the server:
python3 serve.py

# Development mode (auto-restarts when you change code):
python3 serve.py --reload

# Custom port:
python3 serve.py --port 9000
```

The server starts at `http://0.0.0.0:8000` by default.

---

## 2. Get Your API Key

The API requires authentication. On **first start**, the server creates a default tenant and prints the API key to the console. If you missed it, run:

```bash
python3 get_api_key.py
```

If you've never set `ZEROPOINT_API_KEY` in your `.env`, the key was stored hashed and can't be recovered. Generate a new one:

```bash
python3 get_api_key.py --rotate
```

This prints your key and a `curl` command you can test immediately. Add the key to your `.env`:

```env
ZEROPOINT_API_KEY=zp_your_key_here
```

---

## 3. Authentication

Every endpoint (except `/api/v1/health`) requires authentication. Two methods:

### Method A — API Key (simplest, for scripts and curl)

Pass the key directly in the request header:

```bash
curl http://localhost:8000/api/v1/programs/ \
  -H "X-API-Key: zp_your_key_here"
```

### Method B — JWT Bearer Token (for dashboards and browsers)

Exchange your API key for a short-lived JWT token:

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "default", "api_key": "zp_your_key_here"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "tenant_id": "default"
}
```

Then use the JWT in subsequent requests:

```bash
curl http://localhost:8000/api/v1/programs/ \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

JWT tokens expire after 24 hours (configurable via `API_TOKEN_EXPIRE_MINUTES` in `.env`).

---

## 4. Authorize in Swagger UI

1. Open `http://localhost:8000/api/docs`
2. Click the **Authorize** button (top right, lock icon)
3. In the **HTTPBearer** field, paste your JWT token (just the token, not `Bearer `)
4. Click **Authorize** → **Close**
5. All subsequent requests from the UI will be authenticated

To get the JWT for Swagger UI:
- Use the `POST /api/v1/auth/token` endpoint directly in Swagger
- Or run the curl command from Section 3 above and copy the `access_token` value

---

## 5. Endpoints Reference

### System (no auth required)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health` | DB connectivity check |

```bash
curl http://localhost:8000/api/v1/health
```
```json
{"status": "ok", "db": "connected", "version": "1.0.0"}
```

---

### Auth

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/token` | Exchange API key for JWT |

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "default", "api_key": "zp_your_key"}'
```

---

### Programs

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/programs/` | List all active programs |
| POST | `/api/v1/programs/` | Create a new program |
| GET | `/api/v1/programs/{program_id}` | Get one program |
| DELETE | `/api/v1/programs/{program_id}` | Deactivate a program |

```bash
# List programs
curl http://localhost:8000/api/v1/programs/ \
  -H "X-API-Key: zp_your_key"

# Create a program
curl -X POST http://localhost:8000/api/v1/programs/ \
  -H "X-API-Key: zp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "program_id": "tesla_h1",
    "name": "Tesla",
    "platform": "hackerone",
    "domains": ["tesla.com"],
    "wildcards": ["*.tesla.com"]
  }'
```

---

### Assets

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/assets/` | List assets (filterable) |
| GET | `/api/v1/assets/stats` | Asset counts by interest level |
| GET | `/api/v1/assets/{domain}` | Get one asset's full details |

**Query parameters for listing:**

| Parameter | Type | Description |
|---|---|---|
| `program_id` | string | **Required.** Filter by program |
| `interest_level` | string | `critical`, `high`, `medium`, `low`, `noise` |
| `probe_status` | string | `alive`, `dead`, `not_probed` |
| `limit` | int | Results per page (default: 100, max: 1000) |
| `skip` | int | Offset for pagination |

```bash
# All alive HIGH/CRITICAL assets for shopify_h1
curl "http://localhost:8000/api/v1/assets/?program_id=shopify_h1&interest_level=high&probe_status=alive" \
  -H "X-API-Key: zp_your_key"

# Asset statistics
curl "http://localhost:8000/api/v1/assets/stats?program_id=shopify_h1" \
  -H "X-API-Key: zp_your_key"
```

---

### Findings (Nuclei)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/findings/` | List findings (filterable) |
| GET | `/api/v1/findings/stats/summary` | Count by severity |
| GET | `/api/v1/findings/{finding_id}` | Full finding with raw request/response PoC |

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `program_id` | string | **Required** |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `is_new` | bool | Only unreviewed findings |
| `limit` | int | Default: 50, max: 500 |
| `skip` | int | Pagination offset |

```bash
# New critical/high findings
curl "http://localhost:8000/api/v1/findings/?program_id=shopify_h1&severity=critical&is_new=true" \
  -H "X-API-Key: zp_your_key"

# Full PoC for a specific finding (includes raw HTTP request/response)
curl "http://localhost:8000/api/v1/findings/abc123def456..." \
  -H "X-API-Key: zp_your_key"

# Severity breakdown
curl "http://localhost:8000/api/v1/findings/stats/summary?program_id=shopify_h1" \
  -H "X-API-Key: zp_your_key"
```

---

### GitHub Leaks (OSINT)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/leaks/` | List leaked credentials found on GitHub |
| GET | `/api/v1/leaks/stats` | Count by severity |

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `program_id` | string | **Required** |
| `severity` | string | `critical`, `high`, `info` |
| `match_type` | string | `aws_access_key`, `env_file`, `password`, etc. |
| `is_new` | bool | Only unseen leaks |
| `limit` | int | Default: 50, max: 500 |

```bash
# Critical leaks only
curl "http://localhost:8000/api/v1/leaks/?program_id=shopify_h1&severity=critical" \
  -H "X-API-Key: zp_your_key"

# New .env file exposures specifically
curl "http://localhost:8000/api/v1/leaks/?program_id=shopify_h1&match_type=env_file&is_new=true" \
  -H "X-API-Key: zp_your_key"
```

---

## 6. Python Client Example

```python
import httpx

BASE = "http://localhost:8000/api/v1"
API_KEY = "zp_your_key_here"
HEADERS = {"X-API-Key": API_KEY}

# Get all critical findings
resp = httpx.get(
    f"{BASE}/findings/",
    params={"program_id": "shopify_h1", "severity": "critical"},
    headers=HEADERS,
)
findings = resp.json()["findings"]

for f in findings:
    print(f"{f['severity'].upper()} | {f['template_id']} | {f['matched_at']}")
```

---

## 7. Multi-Tenancy (SaaS Mode)

Every document in every collection has a `tenant_id` field. For personal use it's always `"default"`. When you onboard a client, create a tenant record with their own API key:

```python
# One-time setup per client (run in Python shell or a provisioning script)
import asyncio
import hashlib, secrets
import motor.motor_asyncio
from config import settings

async def create_tenant(tenant_id: str, name: str):
    client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGODB_URI)
    db = client[settings.MONGODB_DB]

    raw_key = f"zp_{secrets.token_urlsafe(32)}"
    hashed  = hashlib.sha256(raw_key.encode()).hexdigest()

    await db["tenants"].insert_one({
        "tenant_id":    tenant_id,
        "name":         name,
        "api_key_hash": hashed,
        "is_active":    True,
        "plan":         "professional",
    })
    print(f"Tenant: {tenant_id}")
    print(f"API Key: {raw_key}")
    client.close()

asyncio.run(create_tenant("acme_corp", "Acme Corporation"))
```

Once created, that tenant's API key authenticates them and automatically scopes every query to their data only. They cannot see your programs or any other tenant's data.

---

## 8. Config Reference

All API settings go in `.env`:

```env
# API server
API_HOST=0.0.0.0
API_PORT=8000
API_SECRET_KEY=change-me-to-something-secret-in-production
API_TOKEN_EXPIRE_MINUTES=1440          # JWT TTL — 24h default
API_CORS_ORIGINS=http://localhost:3000  # Allowed dashboard origins

# Your personal API key
ZEROPOINT_API_KEY=zp_your_key_here
```

**Important:** Change `API_SECRET_KEY` before exposing the server to a network. This key signs all JWTs — anyone with it can forge tokens.

---

## 9. About the Auto-Generated Docs

FastAPI builds the Swagger UI and OpenAPI schema automatically from:
- **Route decorators** (`@router.get(...)`, `@router.post(...)`)
- **Pydantic models** used as request bodies and responses
- **Docstrings** on route functions
- **Parameter type hints** and `Query(...)` annotations

You don't write separate documentation. When you add a new endpoint, it appears in Swagger immediately. The schema at `/api/openapi.json` can also be imported into Postman or any API testing tool.