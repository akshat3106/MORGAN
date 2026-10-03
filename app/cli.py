"""MORGAN CLI for debugging and inspecting MCP tools.

Step 1.9:
Provides a command-line interface to list registered tools with color-coded
risk tiers and invoke tools directly with JSON arguments.
"""

import argparse
import asyncio
import json
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from agents.mcp_client import OSToolClient

console = Console()

RISK_COLORS = {
    "read_only": "[bold green]READ ONLY[/bold green]",
    "low": "[bold blue]LOW[/bold blue]",
    "medium": "[bold yellow]MEDIUM[/bold yellow]",
    "high": "[bold red]HIGH[/bold red]",
}


async def cmd_list() -> None:
    """Fetch and display all registered MCP tools in a formatted Rich table."""
    async with OSToolClient() as client:
        tools = await client.list_tools()
        risk_res = await client.call("get_tool_risk_levels")
        risks = risk_res.get("risks", {}) if isinstance(risk_res, dict) else {}

    table = Table(
        title="MORGAN MCP Tool Registry",
        title_style="bold cyan",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Tool Name", style="bold white", width=26)
    table.add_column("Risk Tier", justify="center", width=14)
    table.add_column("Description", style="white")

    for idx, tool in enumerate(tools, 1):
        name = tool["name"]
        raw_risk = risks.get(name, "high")
        risk_styled = RISK_COLORS.get(raw_risk.lower(), f"[red]{raw_risk.upper()}[/red]")

        # First line of description
        desc = (tool["description"] or "").strip().split("\n")[0]
        table.add_row(str(idx), name, risk_styled, desc)

    console.print()
    console.print(table)
    console.print(f"\n[dim]Total tools registered: [bold]{len(tools)}[/bold][/dim]\n")


async def cmd_call(tool_name: str, raw_args: str | None) -> None:
    """Invoke a tool with JSON arguments and pretty-print the result."""
    args_dict: dict[str, Any] = {}
    if raw_args:
        try:
            args_dict = json.loads(raw_args)
            if not isinstance(args_dict, dict):
                console.print("[red]Error: Arguments must be a valid JSON object/dictionary.[/red]")
                sys.exit(1)
        except json.JSONDecodeError as exc:
            console.print(f"[red]Error parsing JSON arguments: {exc}[/red]")
            sys.exit(1)

    with console.status(f"[cyan]Calling [bold]{tool_name}[/bold]...[/cyan]"):
        try:
            async with OSToolClient() as client:
                result = await client.call(tool_name, args_dict)
        except Exception as exc:
            console.print(f"[bold red]Tool execution error:[/bold red] {exc}")
            sys.exit(1)

    json_str = json.dumps(result, indent=2)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    panel = Panel(
        syntax,
        title=f"[bold green]Result: {tool_name}[/bold green]",
        border_style="green" if getattr(result, "get", lambda k, d=None: None)("ok", True) else "red",
    )
    console.print()
    console.print(panel)
    console.print()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="MORGAN OS Tools Debugger & Inspector",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: list
    subparsers.add_parser("list", help="List all registered tools with risk levels")

    # Subcommand: call
    call_parser = subparsers.add_parser("call", help="Invoke an MCP tool directly")
    call_parser.add_argument("tool", help="Name of the MCP tool to invoke")
    call_parser.add_argument(
        "arguments",
        nargs="?",
        default=None,
        help="Optional JSON string of arguments (e.g. '{\"host\": \"8.8.8.8\"}')",
    )

    args = parser.parse_args()

    if args.command == "list":
        asyncio.run(cmd_list())
    elif args.command == "call":
        asyncio.run(cmd_call(args.tool, args.arguments))


if __name__ == "__main__":
    main()
