from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from api.database import get_session
from api.models import AttackRun
from redchain.engine.orchestrator import AttackOrchestrator
from redchain.models.attack_config import AttackConfig, TargetConfig

router = APIRouter(prefix="/attacks", tags=["attacks"])
SessionDep = Annotated[Session, Depends(get_session)]

# ── Request / Response schemas ──────────────────────────────────────────────
class RunAttackRequest(BaseModel):
    target_url: str
    strategies: list[str] = ["direct_hijack"]
    max_turns: int = 4
    forbidden_tools: list[str] = []
    secret_markers: list[str] = []
    target_description: str | None = None


class AttackRunSummary(BaseModel):
    session_id: str
    target_url: str
    strategies: list[str]
    status: str
    owasp_findings: list[str]
    turns_run: int
    duration_seconds: float
    created_at: str


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.post("/run", response_model = AttackRunSummary)
async def run_attack(request: RunAttackRequest, db: SessionDep):
    """
    Launch a full RedChain attack and persist the result.
    Returns a summary immediately after the attack completes.
    """

    config = AttackConfig(
        target = TargetConfig(url = request.target_url),
        strategies = request.strategies,
        max_turns = request.max_turns,
        forbidden_tools = request.forbidden_tools,
        secret_markers = request.secret_markers,
        target_description = request.target_description,
    )

    orchestrator = AttackOrchestrator(config)
    report = await orchestrator.run()

    # Persist summary row to SQLite
    run_row = AttackRun(
        session_id=report.session_id,
        target_url=request.target_url,
        strategies=",".join(request.strategies),
        status=report.status,
        owasp_findings=",".join(report.owasp_findings),
        turns_run=len(report.turns),
        duration_seconds=report.duration_seconds,
        created_at=report.created_at,
    )

    db.add(run_row)
    db.commit()
    db.refresh(run_row)

    return AttackRunSummary(
        session_id=report.session_id,
        target_url=request.target_url,
        strategies=request.strategies,
        status=report.status,
        owasp_findings=report.owasp_findings,
        turns_run=len(report.turns),
        duration_seconds=report.duration_seconds,
        created_at=report.created_at.isoformat(),
    )


@router.get("/", response_model = list[AttackRunSummary])
def list_attacks(db: SessionDep, limit: int = 50):
    """ Return a list of all past attack runs (newest first). """

    rows = db.exec(
        select(AttackRun).order_by(AttackRun.created_at.desc()).limit(limit)
    ).all()
    return [
        AttackRunSummary(
            session_id=r.session_id,
            target_url=r.target_url,
            strategies=r.strategies.split(","),
            status=r.status,
            owasp_findings=r.owasp_findings.split(",") if r.owasp_findings else [],
            turns_run=r.turns_run,
            duration_seconds=r.duration_seconds,
            created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]

@router.get("/{session_id}", response_model = AttackRunSummary)
def get_attack(session_id: str, db: SessionDep):
    """ Return summary of a specific attack run by session ID prefix. """
    row = db.exec(
        select(AttackRun).where(AttackRun.session_id.startswith(session_id))
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"Attack '{session_id}' not found")
    return AttackRunSummary(
        session_id=row.session_id,
        target_url=row.target_url,
        strategies=row.strategies.split(","),
        status=row.status,
        owasp_findings=row.owasp_findings.split(",") if row.owasp_findings else [],
        turns_run=row.turns_run,
        duration_seconds=row.duration_seconds,
        created_at=row.created_at.isoformat(),
    )