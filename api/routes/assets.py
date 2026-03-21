"""ZeroPoint :: api/routes/assets.py"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from api.auth import get_current_tenant
from api.deps import verify_program_ownership
from db.mongo import get_assets_col

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/", summary="List assets for a program")
async def list_assets(
    interest_level: Optional[str] = None,
    probe_status:   Optional[str] = None,
    limit:          int = Query(default=100, le=1000),
    skip:           int = 0,
    program_id:     str = Depends(verify_program_ownership),
    tenant_id:      str = Depends(get_current_tenant),
):
    col   = get_assets_col()
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if interest_level:
        query["interest_level"] = interest_level
    if probe_status:
        query["probe_status"] = probe_status

    assets = []
    cursor = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        assets.append(doc)

    total = await col.count_documents(query)
    return {"assets": assets, "total": total, "limit": limit, "skip": skip}


@router.get("/stats", summary="Asset statistics for a program")
async def asset_stats(
    program_id: str = Depends(verify_program_ownership),
    tenant_id:  str = Depends(get_current_tenant),
):
    from db.mongo import get_db
    db  = get_db()
    col = db["assets"]

    total    = await col.count_documents({"program_id": program_id, "tenant_id": tenant_id})
    alive    = await col.count_documents({"program_id": program_id, "tenant_id": tenant_id, "probe_status": "alive"})
    new      = await col.count_documents({"program_id": program_id, "tenant_id": tenant_id, "is_new": True})
    critical = await col.count_documents({"program_id": program_id, "tenant_id": tenant_id, "interest_level": "critical"})
    high     = await col.count_documents({"program_id": program_id, "tenant_id": tenant_id, "interest_level": "high"})

    return {
        "program_id": program_id,
        "total":      total,
        "alive":      alive,
        "new":        new,
        "critical":   critical,
        "high":       high,
    }