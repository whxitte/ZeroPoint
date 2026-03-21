"""ZeroPoint :: api/routes/leaks.py — GitHub OSINT results"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from api.auth import get_current_tenant
from api.deps import verify_program_ownership
from db.mongo import get_db

router = APIRouter(prefix="/leaks", tags=["github-leaks"])


@router.get("/", summary="List GitHub leaked credentials for a program")
async def list_leaks(
    severity:   Optional[str]  = None,
    match_type: Optional[str]  = None,
    is_new:     Optional[bool] = None,
    limit:      int  = Query(default=50, le=500),
    skip:       int  = 0,
    program_id: str  = Depends(verify_program_ownership),
    tenant_id:  str  = Depends(get_current_tenant),
):
    col   = get_db()["github_leaks"]
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if severity:
        query["severity"] = severity
    if match_type:
        query["match_type"] = match_type
    if is_new is not None:
        query["is_new"] = is_new

    leaks = []
    cursor = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        leaks.append(doc)

    total = await col.count_documents(query)
    return {"leaks": leaks, "total": total}


@router.get("/stats", summary="GitHub leak statistics for a program")
async def leak_stats(
    program_id: str = Depends(verify_program_ownership),
    tenant_id:  str = Depends(get_current_tenant),
):
    col      = get_db()["github_leaks"]
    pipeline = [
        {"$match": {"program_id": program_id, "tenant_id": tenant_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    by_sev = {}
    async for doc in col.aggregate(pipeline):
        by_sev[doc["_id"] or "unknown"] = doc["count"]

    return {"program_id": program_id, "total": sum(by_sev.values()), "by_severity": by_sev}