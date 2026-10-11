from __future__ import annotations

from abc import ABC, abstractmethod

from redchain.models.attack_config import AttackConfig
from redchain.models.attack_trace import TurnRecord

class BaseStrategy(ABC):
    """
    Abstract base class for all RedChain attack strategies.
    Every strategy must know how to generate a payload for any given turn.
    Think of this as the 'playbook template'.
    """

    # Set as class-level attributes in each subclass
    name: str = "base"
    owasp_id: str = "ASI00"
    description: str = "Base strategy"

    def __init__(self, config: AttackConfig) -> None:
        self.config = config

    @abstractmethod
    def get_turn_payload(self, turn_number: int, history: list[TurnRecord]) -> str:
        """
        Generate the attack payload for a given turn.

        Args:
            turn_number: Current turn (1 - indexed)
            history: All previous TurnRecords in this session.

        Returns:
            A string payload to send to the target agent.
        """
        ...
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(owasp={self.owasp_id})"