from __future__ import annotations

from abc import ABC, abstractmethod

from redchain.models.attack_config import AttackConfig
from redchain.models.attack_trace import TargetResponse, TurnRecord
from redchain.models.score_result import ScoreResult

class BaseScorer(ABC):
    """
    Abstract base class for all RedChain scorers.

    Every scorer takes the same inputs and returns a ScoreResult.
    The orchestrator calls them in a pipeline - first exploit found wins.
    """

    # The OWASP ID this scorer is responsible for detecting
    owasp_id: str = "ASI00"

    def __init__(self, config: AttackConfig) -> None:
        self.config = config

    @abstractmethod
    def score(
        self,
        payload: str,
        response: TargetResponse,
        history: list[TurnRecord],
    ) -> ScoreResult:
        """
        Evaluate the agent's response for exploit signals

        Args:
            payload:  The attacker's message that was sent this turn.
            response: The target agent's full response this turn.
            history:  All previous TurnRecords (for cross-turn checks).
        Returns:
            ScoreResult — is_exploit=True if a vulnerability was confirmed. 
        """

        ...

    
    def _clean(self, reasoning: str = "No signal detection") -> ScoreResult:
        """ Helper: return a clean (no exploit) result. """

        return ScoreResult(
            scorer = self.__class__.__name__,
            is_exploit = False,
            confidence = 0.0,
            owasp_id = self.owasp_id,
            reasoning = reasoning,
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(owasp={self.owasp_id})"