"""ZeroPoint :: api/routes/auth.py — Authentication endpoints"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from api.auth import create_access_token, hash_api_key
from db.mongo import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class TokenRequest(BaseModel):
    tenant_id: str = "default"
    api_key:   str


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    tenant_id:    str


@router.post("/token", response_model=TokenResponse)
async def login(req: TokenRequest) -> TokenResponse:
    """
    Exchange an API key for a JWT access token.

    The JWT can then be used as: Authorization: Bearer <token>
    Token expires after API_TOKEN_EXPIRE_MINUTES (default: 24h).
    """
    db     = get_db()
    hashed = hash_api_key(req.api_key)

    doc = await db["tenants"].find_one({
        "tenant_id":    req.tenant_id,
        "api_key_hash": hashed,
        "is_active":    True,
    })

    if not doc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid tenant_id or api_key",
        )

    token = create_access_token(req.tenant_id)
    return TokenResponse(access_token=token, tenant_id=req.tenant_id)