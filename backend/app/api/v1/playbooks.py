from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.playbook import Playbook

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


class PlaybookResponse(BaseModel):
    id: str
    name: str
    risk_tier: str
    allowed_params: dict
    description: Optional[str] = None

    class Config:
        from_attributes = True


@router.get("", response_model=List[PlaybookResponse])
async def list_playbooks(
    risk_tier: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    GET /api/v1/playbooks
    Returns all playbooks from the unified catalog stored in PostgreSQL.
    Consumable by both the React UI and agent allowlists.
    """
    query = select(Playbook)
    if risk_tier:
        query = query.where(Playbook.risk_tier == risk_tier.upper())

    result = await db.execute(query.order_by(Playbook.risk_tier.desc(), Playbook.id))
    playbooks = result.scalars().all()
    return playbooks


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    GET /api/v1/playbooks/{playbook_id}
    Returns details and allowed parameters for a single playbook.
    """
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalars().first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{playbook_id}' not found in unified catalog",
        )
    return playbook
