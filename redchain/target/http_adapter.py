from __future__ import annotations

import httpx

from redchain.models.attack_config import TargetConfig
from redchain.models.attack_trace import TargetResponse
from redchain.target.base_adapter import BaseTargetAdapter

class HTTPTargetAdapter(BaseTargetAdapter):
    """
    Universal adapter for any AI Agent exposed as a REST/HTTP endpoint.

    Expects the target to accept:
        POST <url>
        Body: {"message": "<payload>", "session_id": "<id>"}

    And return:
        {
            "response": "<agent reply text>",
            "tool_calls": [{"name": "...", "params": {...}}], # optional
            "state": {} # optional
        }
    """

    def __init__(self, config: TargetConfig) -> None:
        super().__init__(config)

        # Build headers - include auth token if provided
        headers = {"Content-Type": "application/json", **config.headers}
        if config.auth_token:
            headers["Authorization"] = f"Bearer {config.auth_token}"
        
        # httpx AsyncClient - persistent connection pool, reused across turns
        self._client = httpx.AsyncClient(
            base_url = config.url,
            headers = headers,
            timeout = 30.0, # 30s timeout - agents can be slow
        )

    async def send_turn(self, payload: str, session_id: str) -> TargetResponse:
        """
        POST the attacker's payload to the target agent and return a structured TargetResponse
        """

        body = {
            self.config.message_field: payload,
            self.config.session_field: session_id,
        }

        try:
            resp = await self._client.post("/", json = body)
            resp.raise_for_status()
            data = resp.json()

        except httpx.HTTPStatusError as e:
            # Target returned a 4xx/5xx still capture it, don't crash
            return TargetResponse(
                text = f"[HTTP ERROR {e.response.status_code}] {e.response.text}",
                tool_calls = [],
                status_code = e.response.status_code,
                raw = {"error": str(e)},
            )

        except httpx.RequestError as e:
            # Network failure (connection refused, timeout, etc,.)
            return TargetResponse(
                text = f"[CONNECTION ERROR] Could not reach target: {e}",
                tool_calls = [],
                status_code = 0,
                raw = {"error": str(e)},
            )

        
        # Parse the response - be flexible about field names
        return TargetResponse(
            text = data.get("response") or data.get("text") or data.get("message") or "",
            tool_calls = data.get("tool_calls") or [],
            state_snapshot = data.get("state") or data.get("state_snapshot"),
            status_code = resp.status_code,
            raw = data,
        )

    async def reset_session(self, session_id: str) -> None:
        """
        Attempt to reset the session on the target.
        Sends DELETE /session/<id> - silently ignores if not supported.
        """

        try:
            await self._client.delete(f"/session/{session_id}")
        except Exception:
            # Not all agents support session reset - that's fine
            pass

    async def close(self) -> None:
        """
        Close the underlying HTTP connection pool. 
        Call when done.
        """
        await self._client.aclose()