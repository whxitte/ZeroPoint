"""
ZeroPoint :: api/deps.py
=========================
Shared FastAPI dependencies used across multiple route files.

Dependencies:
  verify_program_ownership()  — ensures a program_id belongs to the calling tenant
                                 raises 404 (not 403) to avoid leaking program IDs
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Query, status

from api.auth import get_current_tenant
from db.mongo import get_programs_col


async def verify_program_ownership(
    program_id: str,
    tenant_id:  str = Depends(get_current_tenant),
) -> str:
    """
    FastAPI dependency — verifies that program_id belongs to this tenant.

    Returns program_id on success so routes can use it directly.
    Raises 404 (not 403) so tenants cannot probe for program IDs that
    belong to other tenants — the program simply "doesn't exist" to them.

    Usage:
        @router.get("/")
        async def my_route(
            program_id: str = Depends(verify_program_ownership),
            tenant_id:  str = Depends(get_current_tenant),
        ):
            ...

    Note: This adds one DB lookup per request. With the compound
    (tenant_id, program_id) index on programs, it's a single index hit.
    """
    col = get_programs_col()
    doc = await col.find_one(
        {"program_id": program_id, "tenant_id": tenant_id, "is_active": True},
        projection={"_id": 1},   # only need existence check
    )
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Program '{program_id}' not found",
        )
    return program_id