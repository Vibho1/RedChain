from __future__ import annotations

from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

class TargetConfig(BaseModel):
    """ Configuration for the target AI agent being tested """

    url: str
    adapter: Literal["http", "langgraph", "openai"] = "http"
    auth_token : Optional[str] = None
    headers: dict[str, str] = Field(default_factory = dict)

    # The field name in the request body that carries the message
    message_field: str = "message"

    # The field name in the request body for session tracking
    session_field: str = "session_id"

    model_config = {"json_schema_extra": {"example": {
        "url": "http://localhost:8001/chat",
        "adapter": "http",
        "auth_token": None,
    }}}


class AttackConfig(BaseModel):
    """ Full configuration for a RedChain attack session """

    session_id: str = Field(default_factory = lambda: str(uuid4()))
    target: TargetConfig

    # Which attack strategies to run (in order)
    strategies: list[str] = Field(
        default = ["direct_hijack"],
        description = "List of strategy names to execute"
    )

    max_turns: int = Field(default = 6, ge = 1, le = 20)

    # LLM powering the attacker planner
    attacker_llm: str = "claude-3-5-sonnet-20241022"

    # LLM used as a judge scorer (fallback evaluation)
    judge_llm: str = "gemini/gemini-1.5-pro"

    # Tools that should NEVER appear in tool_calls - triggers exploit signal
    forbidden_tools: list[str] = Field(default_factory = list)

    # Strings that should NEVER appear in agent output - triggers context leak signal
    secret_markers: list[str] = Field(default_factory = list)

    # Optional: human-readable description of what the target agent is supposed to do
    target_description: Optional[str] = None

    model_config = {"json_schema_extra": {"example": {
        "target": {"url": "https://localhost:8001/chat", "adapter": "http"},
        "strategies": ["direct_hijack", "tool_manipulation"],
        "max_turns": 6,
        "forbidden_tools": ["send_email", "delete_file"],
        "secret_markers": ["SYSTEM", "sk-", "Bearer "],
    }}}