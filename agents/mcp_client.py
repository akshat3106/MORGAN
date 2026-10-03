"""Async client wrapper for MORGAN's MCP server over stdio.

Step 1.8:
Provides ``OSToolClient`` as an async context manager managing the stdio
session, tool listing, and tool execution with JSON content decoding.
"""

from contextlib import AsyncExitStack
import json
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class OSToolClient:
    """Async context manager wrapping an MCP stdio client connection."""

    def __init__(
        self,
        command: str = sys.executable,
        args: list[str] | None = None,
    ) -> None:
        self.command = command
        self.args = args if args is not None else ["-m", "mcp_server.server"]
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "OSToolClient":
        self._stack = AsyncExitStack()
        try:
            params = StdioServerParameters(command=self.command, args=self.args)
            read_stream, write_stream = await self._stack.enter_async_context(
                stdio_client(params)
            )
            self._session = await self._stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            await self._session.initialize()
            return self
        except Exception:
            await self._stack.aclose()
            raise

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._stack:
            await self._stack.aclose()
            self._stack = None
            self._session = None

    @property
    def session(self) -> ClientSession:
        """The active ClientSession instance."""
        if self._session is None:
            raise RuntimeError("OSToolClient is not connected. Use 'async with OSToolClient(): ...'")
        return self._session

    async def list_tools(self) -> list[dict[str, Any]]:
        """List all available tools exposed by the MCP server.

        Returns a list of dicts with keys: ``name``, ``description``, and ``input_schema``.
        """
        response = await self.session.list_tools()
        tools_list: list[dict[str, Any]] = []

        for tool in response.tools:
            # mcp 2.x uses input_schema (snake_case)
            schema = getattr(tool, "input_schema", None)
            if schema is None:
                schema = getattr(tool, "inputSchema", {})

            tools_list.append({
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": schema or {},
            })

        return tools_list

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call an MCP tool by name with arguments and return the parsed result.

        Parses text content blocks as JSON with fallback to plain string.
        """
        args = arguments if arguments is not None else {}
        result = await self.session.call_tool(name, args)

        if not result.content:
            return {"ok": not result.isError}

        parsed_contents: list[Any] = []
        for block in result.content:
            text = getattr(block, "text", None)
            if text is not None:
                try:
                    parsed_contents.append(json.loads(text))
                except (json.JSONDecodeError, TypeError):
                    parsed_contents.append(text)
            else:
                parsed_contents.append(str(block))

        if len(parsed_contents) == 1:
            return parsed_contents[0]
        return parsed_contents
