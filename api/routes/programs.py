"""ZeroPoint :: api/routes/programs.py"""
from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from api.auth import get_current_tenant
from db.mongo import get_programs_col, upsert_program, get_program, list_active_programs
from models import Program, ProgramPlatform

router = APIRouter(prefix="/programs", tags=["programs"])


class ProgramCreate(BaseModel):
    program_id: str
    name:       str
    platform:   ProgramPlatform = ProgramPlatform.PRIVATE
    domains:    List[str]
    wildcards:  List[str] = []
    notes:      Optional[str] = None


@router.get("/", summary="List all programs for this tenant")
async def list_programs(tenant_id: str = Depends(get_current_tenant)):
    col = get_programs_col()
    programs = []
    async for doc in col.find({"tenant_id": tenant_id, "is_active": True}):
        doc.pop("_id", None)
        programs.append(doc)
    return {"programs": programs, "count": len(programs)}


@router.get("/{program_id}", summary="Get a specific program")
async def get_program_detail(
    program_id: str,
    tenant_id:  str = Depends(get_current_tenant),
):
    col = get_programs_col()
    doc = await col.find_one({"program_id": program_id, "tenant_id": tenant_id})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    doc.pop("_id", None)
    return doc


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Create a new program")
async def create_program(
    body:      ProgramCreate,
    tenant_id: str = Depends(get_current_tenant),
):
    program = Program(
        tenant_id  = tenant_id,
        program_id = body.program_id,
        name       = body.name,
        platform   = body.platform,
        domains    = body.domains,
        wildcards  = body.wildcards,
        notes      = body.notes,
    )
    await upsert_program(program)
    return {"status": "created", "program_id": program.program_id}


@router.delete("/{program_id}", summary="Deactivate a program")
async def deactivate_program(
    program_id: str,
    tenant_id:  str = Depends(get_current_tenant),
):
    col = get_programs_col()
    result = await col.update_one(
        {"program_id": program_id, "tenant_id": tenant_id},
        {"$set": {"is_active": False}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail=f"Program '{program_id}' not found")
    return {"status": "deactivated", "program_id": program_id}