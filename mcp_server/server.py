"""MORGAN MCP Server.

Step 1.7:
Registers all tool modules (system, processes, files, network, services)
and exposes ``get_tool_risk_levels`` for agents to query tool risk definitions.
"""

from typing import Any

from mcp.server.mcpserver import MCPServer

from .risk import RiskLevel, TOOL_RISK, register_risk
from .tools import files, network, processes, services, system

# Create the MCP server instance
mcp = MCPServer("morgan-os-tools")

# Register all tool domains
system.register(mcp)
processes.register(mcp)
files.register(mcp)
network.register(mcp)
services.register(mcp)


@mcp.tool()
async def get_tool_risk_levels() -> dict[str, Any]:
    """Return the complete dictionary of registered tools and their risk tiers.

    Used by the planner and diagnostic agents to inspect which tools can be safely run.
    """
    return {
        "ok": True,
        "risks": {name: level.value for name, level in TOOL_RISK.items()},
    }


register_risk("get_tool_risk_levels", RiskLevel.READ_ONLY)


def main() -> None:
    """Run the MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
