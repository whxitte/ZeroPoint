"""ZeroPoint :: api/routes/crawler.py — Crawler & JS Analysis results"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from api.auth import get_current_tenant
from api.deps import verify_program_ownership
from db.mongo import get_db

router = APIRouter(tags=["crawler"])


@router.get("/secrets/", summary="List JS secrets for a program")
async def list_secrets(
    severity:   Optional[str]  = None,
    secret_type: Optional[str] = None,
    is_new:     Optional[bool] = None,
    limit:      int  = Query(default=50, le=500),
    skip:       int  = 0,
    program_id: str  = Depends(verify_program_ownership),
    tenant_id:  str  = Depends(get_current_tenant),
):
    col   = get_db()["secrets"]
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if severity:
        query["severity"] = severity
    if secret_type:
        query["secret_type"] = secret_type
    if is_new is not None:
        query["is_new"] = is_new

    secrets = []
    cursor = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        secrets.append(doc)

    total = await col.count_documents(query)
    return {"secrets": secrets, "total": total}


@router.get("/endpoints/", summary="List crawled endpoints for a program")
async def list_endpoints(
    is_interesting: Optional[bool] = None,
    limit:         int  = Query(default=100, le=1000),
    skip:          int  = 0,
    program_id:    str  = Depends(verify_program_ownership),
    tenant_id:     str  = Depends(get_current_tenant),
):
    col   = get_db()["endpoints"]
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if is_interesting is not None:
        query["is_interesting"] = is_interesting

    endpoints = []
    cursor = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        endpoints.append(doc)

    total = await col.count_documents(query)
    return {"endpoints": endpoints, "total": total}
