from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel


class AttackRun(SQLModel, table=True):
    """
    One row in the SQLite DB per completed attack session.
    Stores summary data only - full trace lives in the JSON file.
    """

    id: Optional[int] = Field(default=None, primary_key=True)

    session_id: str = Field(index=True, unique=True)
    target_url: str
    strategies: str       # stored as comma-separated string
    status: str           # EXPLOITED / PARTIAL / RESILIENT
    owasp_findings: str   # stored as comma-separated string
    turns_run: int
    duration_seconds: float

    # sa_column=Column(DateTime) bypasses SQLModel's timezone enforcement
    # and stores a plain naive datetime — compatible with report.created_at
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        sa_column=Column(DateTime, nullable=False),
    )