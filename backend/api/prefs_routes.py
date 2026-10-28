"""Personal UI settings: per signed-in account, persisted on the server.

Deliberately a free-form JSON object (column layout, visible filter fields and so on):
the frontend owns the catalogue, the server only persists each user's choices.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.auth.deps import get_current_user
from backend.auth.models import Principal
from backend.auth.store import get_admin_store

router = APIRouter(prefix="/api", tags=["prefs"])

_MAX_BYTES = 64 * 1024  # guard against bloated prefs (columns + verdicts + presets)


class PrefsBody(BaseModel):
    prefs: dict = Field(default_factory=dict)


@router.get("/prefs")
async def get_prefs(principal: Principal = Depends(get_current_user)) -> dict:
    return get_admin_store().get_prefs(principal.username)


@router.put("/prefs")
async def put_prefs(body: PrefsBody, principal: Principal = Depends(get_current_user)) -> dict:
    if len(json.dumps(body.prefs)) > _MAX_BYTES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Settings are too large.")
    return get_admin_store().set_prefs(principal.username, body.prefs)
