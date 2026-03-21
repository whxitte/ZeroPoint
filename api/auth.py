"""
ZeroPoint :: api/auth.py
=========================
Authentication for the REST API.

Two auth methods:
  1. JWT Bearer token  — for human users (dashboard, browser)
  2. API key           — for programmatic access (integrations, clients)

JWT flow:
  POST /api/v1/auth/token  { "tenant_id": "...", "api_key": "..." }
  → { "access_token": "<jwt>", "token_type": "bearer" }
  → Include as: Authorization: Bearer <jwt>

API key flow:
  Include as: X-API-Key: <raw_api_key>

For personal use: the default tenant's API key is shown at startup.
For SaaS clients: each tenant gets their own API key (stored hashed in DB).
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from loguru import logger

from config import settings


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

ALGORITHM = "HS256"

# Bearer token extractor (optional — falls back to API key if not present)
bearer_scheme = HTTPBearer(auto_error=False)


# ─────────────────────────────────────────────────────────────────────────────
# API key utilities
# ─────────────────────────────────────────────────────────────────────────────

def generate_api_key() -> str:
    """Generate a secure random API key."""
    return f"zp_{secrets.token_urlsafe(32)}"


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hash of an API key — stored in DB, never the raw key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# JWT utilities
# ─────────────────────────────────────────────────────────────────────────────

def create_access_token(tenant_id: str) -> str:
    """Create a signed JWT for a tenant."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.API_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub":        tenant_id,
        "exp":        expire,
        "iat":        datetime.now(timezone.utc),
        "token_type": "access",
    }
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[str]:
    """Decode a JWT and return the tenant_id, or None if invalid."""
    try:
        payload = jwt.decode(token, settings.API_SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Dependency: get current tenant_id from request
# ─────────────────────────────────────────────────────────────────────────────

async def get_current_tenant(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_api_key:   Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """
    FastAPI dependency that extracts and validates the caller's tenant_id.

    Priority:
      1. Bearer JWT token (Authorization: Bearer <token>)
      2. API key header  (X-API-Key: <key>)

    For personal/single-tenant use, this always returns "default".
    In production multi-tenant mode, validates against the DB.
    """
    # Try JWT first
    if credentials and credentials.credentials:
        tenant_id = decode_access_token(credentials.credentials)
        if tenant_id:
            return tenant_id
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Try API key
    if x_api_key:
        tenant_id = await _validate_api_key(x_api_key)
        if tenant_id:
            return tenant_id
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use 'Authorization: Bearer <token>' or 'X-API-Key: <key>'",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _validate_api_key(raw_key: str) -> Optional[str]:
    """
    Validate an API key against the database.
    Returns tenant_id on success, None on failure.
    """
    from db.mongo import get_db

    hashed = hash_api_key(raw_key)
    db     = get_db()

    doc = await db["tenants"].find_one({"api_key_hash": hashed, "is_active": True})
    if doc:
        return doc.get("tenant_id")

    # Fallback: accept the default API key from settings for personal use
    default_key = os.environ.get("ZEROPOINT_API_KEY")
    if default_key and raw_key == default_key:
        return "default"

    return None