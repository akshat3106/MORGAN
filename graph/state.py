"""In-memory state models for MORGAN incident workflows.

Defines the core data structures passed between diagnostic, planning, execution,
and verification agents, as well as the LangGraph state container.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    """The final resolution status of an incident."""

    SUCCESS = "success"
    FAILED = "failed"
    UNKNOWN = "unknown"
    ABORTED = "aborted"


@dataclass
class Evidence:
    """One tool call made while investigating a problem."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    result: Any = None


@dataclass
class FixAction:
    """A single remediation action proposed by the fix planner."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    risk: str = "high"  # Set from the risk registry, never trusted from the LLM
    preview: Any = None  # Dry-run execution result for user review
    result: Any = None  # Live execution result
    executed: bool = False


@dataclass
class FixPlan:
    """A proposed remediation plan comprising one or more fix actions."""

    root_cause: str
    explanation: str
    actions: list[FixAction] = field(default_factory=list)
    from_memory: bool = False
    memory_note: str = ""

    @property
    def max_risk(self) -> str:
        """The highest risk level among all actions in this plan."""
        order = ["read_only", "low", "medium", "high"]
        if not self.actions:
            return "read_only"
        return max(
            (a.risk for a in self.actions),
            key=lambda r: order.index(r) if r in order else len(order) - 1,
        )


@dataclass
class IncidentState:
    """Everything known about a single reported problem across the workflow."""

    symptom: str
    evidence: list[Evidence] = field(default_factory=list)
    diagnosis: str = ""
    plan: FixPlan | None = None
    approved: bool = False
    verification: str = ""
    outcome: Outcome = Outcome.UNKNOWN
    needs_user_input: str = ""

    def evidence_digest(self) -> str:
        """Format collected evidence into compact bullet lines for prompt injection."""
        if not self.evidence:
            return "No evidence collected."

        lines: list[str] = []
        for e in self.evidence:
            args_str = json.dumps(e.arguments, ensure_ascii=False) if e.arguments else "{}"
            if isinstance(e.result, (dict, list)):
                res_str = json.dumps(e.result, ensure_ascii=False)
            else:
                res_str = str(e.result)
            lines.append(f"- {e.tool}({args_str}) -> {res_str}")
        return "\n".join(lines)
