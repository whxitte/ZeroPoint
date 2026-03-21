"""ZeroPoint :: api/routes/findings.py"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends, Query
from api.auth import get_current_tenant
from api.deps import verify_program_ownership
from db.mongo import get_db

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/", summary="List Nuclei findings for a program")
async def list_findings(
    severity:   Optional[str]  = None,
    is_new:     Optional[bool] = None,
    limit:      int  = Query(default=50, le=500),
    skip:       int  = 0,
    program_id: str  = Depends(verify_program_ownership),
    tenant_id:  str  = Depends(get_current_tenant),
):
    col   = get_db()["findings"]
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if severity:
        query["severity"] = severity
    if is_new is not None:
        query["is_new"] = is_new

    findings = []
    cursor = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        # Don't return raw request/response in list view — too large
        doc.pop("request",  None)
        doc.pop("response", None)
        findings.append(doc)

    total = await col.count_documents(query)
    return {"findings": findings, "total": total}


@router.get("/stats/summary", summary="Findings summary by severity")
async def findings_summary(
    program_id: str = Depends(verify_program_ownership),
    tenant_id:  str = Depends(get_current_tenant),
):
    col      = get_db()["findings"]
    pipeline = [
        {"$match": {"program_id": program_id, "tenant_id": tenant_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    by_sev = {}
    async for doc in col.aggregate(pipeline):
        by_sev[doc["_id"] or "unknown"] = doc["count"]

    total = sum(by_sev.values())
    return {"program_id": program_id, "total": total, "by_severity": by_sev}


@router.get("/{finding_id}", summary="Get full finding details including PoC")
async def get_finding(
    finding_id: str,
    tenant_id:  str = Depends(get_current_tenant),
):
    from fastapi import HTTPException
    col = get_db()["findings"]
    doc = await col.find_one({"finding_id": finding_id, "tenant_id": tenant_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    doc.pop("_id", None)
    return doc