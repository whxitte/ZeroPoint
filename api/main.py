"""
ZeroPoint :: api/main.py
=========================
REST API server — the SaaS foundation layer.

Start the API server:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

Or use the convenience script:
    python3 serve.py

Endpoints:
  POST   /api/v1/auth/token             — get JWT from API key
  GET    /api/v1/programs/              — list programs
  POST   /api/v1/programs/              — create program
  GET    /api/v1/programs/{id}          — get program
  DELETE /api/v1/programs/{id}          — deactivate program
  GET    /api/v1/assets/?program_id=X   — list assets
  GET    /api/v1/assets/stats           — asset statistics
  GET    /api/v1/findings/?program_id=X — list Nuclei findings
  GET    /api/v1/findings/{id}          — get finding with PoC
  GET    /api/v1/findings/stats/summary — severity breakdown
  GET    /api/v1/leaks/?program_id=X    — list GitHub leaks
  GET    /api/v1/leaks/stats            — leak statistics
  GET    /api/v1/health                 — health check

Authentication:
  All endpoints (except /health and /auth/token) require either:
    - Authorization: Bearer <jwt>
    - X-API-Key: <api_key>

  For personal use: set ZEROPOINT_API_KEY=your_key in .env
  For multi-tenant SaaS: create tenant records in the DB

Multi-tenancy:
  Every query is automatically filtered by tenant_id from the auth token.
  Tenants can only see their own programs, assets, and findings.
  tenant_id defaults to "default" for all existing data (backward compatible).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

import db.mongo as mongo_ops
from config import settings
from db.crawler_ops import ensure_crawler_indexes
from db.github_ops import ensure_github_indexes
from db.scanner_ops import ensure_scanner_indexes

from api.routes import auth, programs, assets, findings, leaks


# ─────────────────────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Bootstrap DB indexes on startup, close connection on shutdown."""
    logger.info("ZeroPoint API starting — bootstrapping DB indexes...")
    await mongo_ops.ensure_indexes()
    await ensure_scanner_indexes()
    await ensure_crawler_indexes()
    await ensure_github_indexes()
    await _ensure_default_tenant()
    logger.info("ZeroPoint API ready ✓")
    yield
    await mongo_ops.close_connection()
    logger.info("ZeroPoint API shutdown complete")


async def _ensure_default_tenant() -> None:
    """
    Create the default tenant on first start if it doesn't exist.
    Prints the API key to stdout so you can add it to your .env.
    """
    db  = mongo_ops.get_db()
    doc = await db["tenants"].find_one({"tenant_id": "default"})

    if not doc:
        from api.auth import generate_api_key, hash_api_key

        raw_key = os.environ.get("ZEROPOINT_API_KEY") or generate_api_key()
        hashed  = hash_api_key(raw_key)

        await db["tenants"].insert_one({
            "tenant_id":    "default",
            "name":         "Default (Personal)",
            "api_key_hash": hashed,
            "is_active":    True,
            "plan":         "personal",
        })

        if not os.environ.get("ZEROPOINT_API_KEY"):
            print("\n" + "=" * 60)
            print("  ZeroPoint API — Default tenant created")
            print(f"  API Key: {raw_key}")
            print("  Add to your .env: ZEROPOINT_API_KEY=" + raw_key)
            print("=" * 60 + "\n")
        else:
            logger.info("Default tenant created with API key from environment.")


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "ZeroPoint API",
    description = "Enterprise Bug Bounty Automation Platform — REST API",
    version     = "1.0.0",
    lifespan    = lifespan,
    docs_url    = "/api/docs",
    redoc_url   = "/api/redoc",
    openapi_url = "/api/openapi.json",
)

# CORS — allow the dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins     = [o.strip() for o in settings.API_CORS_ORIGINS.split(",")],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
PREFIX = "/api/v1"

app.include_router(auth.router,     prefix=PREFIX)
app.include_router(programs.router, prefix=PREFIX)
app.include_router(assets.router,   prefix=PREFIX)
app.include_router(findings.router, prefix=PREFIX)
app.include_router(leaks.router,    prefix=PREFIX)


@app.get("/api/v1/health", tags=["system"])
async def health():
    """Health check — confirms API and DB are reachable."""
    try:
        await mongo_ops._get_client().admin.command("ping")
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status":  "ok" if db_ok else "degraded",
        "db":      "connected" if db_ok else "unreachable",
        "version": "1.0.0",
    }