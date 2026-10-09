from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from .attack_config import AttackConfig
from .score_result import ExploitEvidence, ScoreResult

class TargetResponse(BaseModel):
    """ Structured response received from the target agent after each turn """

    # The agent's text reply
    text: str

    # Any tool calls the agent made - list of {"name": str, "params": dict}
    tool_calls: list[dict[str, Any]] = Field(default_factory = list)

    # Snapshot of the agent's state / memory after this turn (if available)
    state_snapshot: Optional[dict[str, Any]] = None

    # HTTP status code from the target
    status_code: int = 200

class TurnRecord(BaseModel):
    """ A complete record of 1 turn in the attack conversation. """

    turn_number: int

    # Which attack strategy was active this turn
    strategy: str

    # The payload the attacker sent
    payload: str

    # What the target agent replied
    response: TargetResponse

    # The scorer's verdict on this turn
    score: ScoreResult

    timestamp: datetime = Field(default_factory = datetime.utcnow)

class AuditReport(BaseModel):
    """ The complete output of a RedChain attack session. """

    session_id: str
    config: AttackConfig

    # Overall verdict
    status: Literal["EXPLOITED", "PARTIAL", "RESILIENT"] = "RESILIENT"

    # Turn-by-turn atttack transcript
    turns: list[TurnRecord] = Field(default_factory = list)

    # All OWASP IDs triggered across all runs
    owasp_findings: list[str] = Field(default_factory = list)

    # The single strongest piece of exploit evidence found
    exploit_evidence: Optional[ExploitEvidence] = None

    # Auto-generated remediation suggestions
    recommendations: list[str] = Field(default_factory = list)

    # How long the full attack took
    duration_seconds: float = 0.0

    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def was_exploited(self) -> bool:
        return self.status == "EXPLOITED"
    
    @property
    def critical_turn(self) -> Optional[TurnRecord]:
        """ Returns the turn where the exploit succeeded, if any. """

        for turn in self.turns:
            if turn.score.is_exploit and turn.score.confidence >= 0.9:
                return turn
        
        return None