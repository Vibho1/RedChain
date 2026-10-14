from __future__ import annotations

from fastapi import APIRouter, HTTPException
from redchain.reporter.json_reporter import JSONReporter

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/{session_id}")
def get_full_report(session_id: str):
    """
    Return the full AuditReport JSON for a session.
    Includes turn-by-turn trace, evidence, and recommendations.
    """

    reporter = JSONReporter()

    try:
        report = reporter.load(session_id)
    
    except FileNotFoundError:

        raise HTTPException(
            status_code = 400,
            detail = f"No full report found for session '{session_id}'"
        )
    
    return report.model_dump(mode = "json")