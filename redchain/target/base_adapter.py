from __future__ import annotations

from abc import ABC, abstractmethod

from redchain.models.attack_config import TargetConfig
from redchain.models.attack_trace import TargetResponse

class BaseTargetAdapter(ABC):
    """
    Abstract base class for all target adapters.
    Every adapter (HTTP, LangGraph, OpenAI) must implement these 2 methods.
    Think of this as the contract - the 'job description' every adapter must fulfill. 
    """

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @abstractmethod
    async def send_turn(self, payload: str, session_id: str) ->TargetResponse:
        """
        Send one turn of the attack conversation to the target agent.

        Args:
            payload: The attacker's message to send.
            session_id: Unique ID for this attack session (for stateful agents).
            
        Returns:
            TargetResponse with the agent's text reply, tool calls, and state.
        """
        ...

    @abstractmethod
    async def reset_session(self, session_id: str) -> None:
        """
        Clear the target agent's memory/state for a fresh attack session.
        Not all agents support this - adapters can make it a no-op if not applicable.

        Args:
            session_id: The session to reset.
        """

        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(url = {self.config.url!r})"