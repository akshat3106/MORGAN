"""Anthropic API client wrapper and message formatting utilities.

Step 2.2:
Wraps AsyncAnthropic with API key validation, schema reshaping from MCP tool
definitions into Anthropic tool format, and response block filtering.
"""

from __future__ import annotations

import os
from typing import Any

from anthropic import AsyncAnthropic
from dotenv import load_dotenv

# Load environment variables at module import time
load_dotenv()

DEFAULT_MODEL = "claude-3-5-sonnet-20241022"


class LLM:
    """Wrapper around AsyncAnthropic for agent completions and tool use."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Please add it to your .env file or environment."
            )

        self.model = model or os.environ.get("MORGAN_MODEL", DEFAULT_MODEL)
        self.client = AsyncAnthropic(api_key=resolved_key)

    @staticmethod
    def to_anthropic_tools(
        mcp_tools: list[dict[str, Any]],
        only: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Filter and reshape MCP tool definitions into Anthropic tool format.

        Each output tool dictionary contains: ``name``, ``description``, and ``input_schema``.
        """
        anthropic_tools: list[dict[str, Any]] = []
        for tool in mcp_tools:
            name = tool.get("name", "")
            if only is not None and name not in only:
                continue

            schema = tool.get("input_schema") or tool.get("inputSchema") or {
                "type": "object",
                "properties": {},
            }
            anthropic_tools.append({
                "name": name,
                "description": tool.get("description", ""),
                "input_schema": schema,
            })
        return anthropic_tools

    async def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> Any:
        """Send a completion request to Anthropic and return the response."""
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools
        if tool_choice:
            kwargs["tool_choice"] = tool_choice

        return await self.client.messages.create(**kwargs)

    @staticmethod
    def text_of(response: Any) -> str:
        """Extract and concatenate all text blocks from a response."""
        content = getattr(response, "content", None)
        if content is None:
            if isinstance(response, str):
                return response
            if isinstance(response, dict):
                content = response.get("content", [])
            elif isinstance(response, list):
                content = response
            else:
                return ""

        texts: list[str] = []
        for block in content:
            if isinstance(block, str):
                texts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text":
                    texts.append(block.get("text", ""))
            else:
                if getattr(block, "type", None) == "text":
                    texts.append(getattr(block, "text", ""))
        return "".join(texts)

    @staticmethod
    def tool_calls_of(response: Any) -> list[Any]:
        """Extract all tool_use blocks from a response."""
        content = getattr(response, "content", None)
        if content is None:
            if isinstance(response, list):
                content = response
            elif isinstance(response, dict):
                content = response.get("content", [])
            else:
                return []

        calls: list[Any] = []
        for block in content:
            b_type = getattr(block, "type", None) if not isinstance(block, dict) else block.get("type")
            if b_type == "tool_use":
                calls.append(block)
        return calls
