"""ZeroPoint :: api/routes/dork_results.py — Google Dork Engine results API"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.auth import get_current_tenant
from db.mongo import get_db

router = APIRouter(prefix="/dorks", tags=["google-dork"])


@router.get("/", summary="List Google dork findings for a program")
async def list_dork_results(
    program_id:    str,
    severity:      Optional[str]  = None,
    dork_category: Optional[str]  = None,
    is_new:        Optional[bool] = None,
    limit:         int = Query(default=100, le=1000),
    skip:          int = 0,
    tenant_id:     str = Depends(get_current_tenant),
):
    col   = get_db()["dork_results"]
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if severity:
        query["severity"] = severity
    if dork_category:
        query["dork_category"] = dork_category
    if is_new is not None:
        query["is_new"] = is_new

    results = []
    cursor  = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        results.append(doc)

    total = await col.count_documents(query)
    return {"results": results, "total": total, "limit": limit, "skip": skip}


@router.get("/stats", summary="Google dork statistics for a program")
async def dork_stats(
    program_id: str,
    tenant_id:  str = Depends(get_current_tenant),
):
    col      = get_db()["dork_results"]
    pipeline = [
        {"$match": {"program_id": program_id, "tenant_id": tenant_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    by_sev: dict = {}
    async for doc in col.aggregate(pipeline):
        by_sev[doc["_id"] or "unknown"] = doc["count"]

    # Results by category
    cat_pipeline = [
        {"$match": {"program_id": program_id, "tenant_id": tenant_id}},
        {"$group": {"_id": "$dork_category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    by_category: dict = {}
    async for doc in col.aggregate(cat_pipeline):
        if doc["_id"]:
            by_category[doc["_id"]] = doc["count"]

    return {
        "program_id":  program_id,
        "total":       sum(by_sev.values()),
        "by_severity": by_sev,
        "by_category": by_category,
    }


@router.get("/exposed-files", summary="Exposed files found via dorking (.env, .sql, backups)")
async def exposed_files(
    program_id: str,
    tenant_id:  str = Depends(get_current_tenant),
):
    """Returns all exposed_files and credentials category results — highest signal."""
    col   = get_db()["dork_results"]
    query = {
        "program_id":    program_id,
        "tenant_id":     tenant_id,
        "dork_category": {"$in": ["exposed_files", "credentials"]},
    }
    results = []
    async for doc in col.find(query).sort("severity", -1):
        doc.pop("_id", None)
        results.append(doc)
    return {"results": results, "total": len(results)}


@router.get("/{result_id}", summary="Get a specific dork result")
async def get_dork_result(
    result_id: str,
    tenant_id: str = Depends(get_current_tenant),
):
    from fastapi import HTTPException
    col = get_db()["dork_results"]
    doc = await col.find_one({"result_id": result_id, "tenant_id": tenant_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Dork result not found")
    doc.pop("_id", None)
    return doc