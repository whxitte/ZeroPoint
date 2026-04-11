"""ZeroPoint :: api/routes/port_findings.py — Port Scanner results API"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from api.auth import get_current_tenant
from api.deps import verify_program_ownership   # ← FIX: was missing
from db.mongo import get_db

router = APIRouter(prefix="/portfindings", tags=["port-scanner"])


@router.get("/", summary="List port scanner findings for a program")
async def list_port_findings(
    severity:   Optional[str]  = None,
    is_new:     Optional[bool] = None,
    port:       Optional[int]  = None,
    service:    Optional[str]  = None,
    limit:      int = Query(default=100, le=1000),
    skip:       int = 0,
    program_id: str = Depends(verify_program_ownership),   # ← FIX: was plain str param
    tenant_id:  str = Depends(get_current_tenant),
):
    col   = get_db()["port_findings"]
    query = {"program_id": program_id, "tenant_id": tenant_id}
    if severity:
        query["severity"] = severity
    if is_new is not None:
        query["is_new"] = is_new
    if port is not None:
        query["port"] = port
    if service:
        query["service"] = {"$regex": service, "$options": "i"}

    findings = []
    cursor   = col.find(query).skip(skip).limit(limit).sort("first_seen", -1)
    async for doc in cursor:
        doc.pop("_id", None)
        findings.append(doc)

    total = await col.count_documents(query)
    return {"findings": findings, "total": total, "limit": limit, "skip": skip}


@router.get("/stats", summary="Port scanner statistics for a program")
async def port_stats(
    program_id: str = Depends(verify_program_ownership),   # ← FIX
    tenant_id:  str = Depends(get_current_tenant),
):
    col      = get_db()["port_findings"]
    pipeline = [
        {"$match": {"program_id": program_id, "tenant_id": tenant_id}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    by_sev: dict = {}
    async for doc in col.aggregate(pipeline):
        by_sev[doc["_id"] or "unknown"] = doc["count"]

    svc_pipeline = [
        {"$match": {"program_id": program_id, "tenant_id": tenant_id}},
        {"$group": {"_id": "$service", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    top_services: dict = {}
    async for doc in col.aggregate(svc_pipeline):
        if doc["_id"]:
            top_services[doc["_id"]] = doc["count"]

    return {
        "program_id":   program_id,
        "total":        sum(by_sev.values()),
        "by_severity":  by_sev,
        "top_services": top_services,
    }


@router.get("/critical", summary="CRITICAL exposed services (unauthenticated databases, Docker)")
async def critical_findings(
    program_id: str = Depends(verify_program_ownership),   # ← FIX
    tenant_id:  str = Depends(get_current_tenant),
):
    col      = get_db()["port_findings"]
    query    = {"program_id": program_id, "tenant_id": tenant_id, "severity": "critical"}
    findings = []
    async for doc in col.find(query).sort("first_seen", -1):
        doc.pop("_id", None)
        findings.append(doc)
    return {"findings": findings, "total": len(findings)}


@router.get("/{finding_id}", summary="Get a specific port finding")
async def get_port_finding(
    finding_id: str,
    tenant_id:  str = Depends(get_current_tenant),
):
    from fastapi import HTTPException
    col = get_db()["port_findings"]
    doc = await col.find_one({"finding_id": finding_id, "tenant_id": tenant_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Port finding not found")
    doc.pop("_id", None)
    return doc
