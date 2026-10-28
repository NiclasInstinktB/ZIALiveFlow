"""Query chips: global (admin-managed) quick filters for the live flow.

  GET  /api/chips          → the global chips plus whether the current user may edit them.
  PUT  /api/chips/global   → replace the entire global list (admin only).

Personal chips live in the account prefs (see ``prefs_routes``). The client merges global
and personal chips and keeps order and visibility per account. Global chips are read-only
for viewers (no PUT without admin).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend import chips_store
from backend.auth.deps import get_current_user, require_permission
from backend.auth.models import PERM_SETTINGS, Principal

router = APIRouter(prefix="/api", tags=["chips"])


class ChipsBody(BaseModel):
    chips: list = Field(default_factory=list)


@router.get("/chips")
async def get_chips(principal: Principal = Depends(get_current_user)) -> dict:
    """Global chips for every signed-in user; ``can_edit_global`` only with the 'settings' permission."""
    return {"global": chips_store.list_global(), "can_edit_global": principal.has(PERM_SETTINGS)}


@router.put("/chips/global")
async def put_global_chips(body: ChipsBody, _: Principal = Depends(require_permission(PERM_SETTINGS))) -> dict:
    try:
        chips = chips_store.replace_global(body.chips)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return {"chips": chips}
