"""Tool risk registry.

Every mutating capability MORGAN has is labelled here, in code, at the moment the
tool is defined. The planner reads this registry; it has no way to write to it.
That separation is the whole point -- the model cannot talk itself into calling a
dangerous action "low risk", because it is not the thing doing the labelling.

The registry is also what the diagnostic agent is filtered through: it is handed
only the tools that report READ_ONLY, so it structurally cannot act on a guess.
"""

from enum import Enum


class RiskLevel(str, Enum):
    """How much damage a tool can do if MORGAN is wrong about calling it.

    Inherits from ``str`` so the value serialises straight into JSON and SQLite
    without a conversion step -- ``RiskLevel.LOW == "low"`` is True.
    """

    READ_ONLY = "read_only"  # observes only; cannot change the machine
    LOW = "low"              # reversible, or affects only disposable data
    MEDIUM = "medium"        # disrupts something running; recoverable
    HIGH = "high"            # may need a reboot or admin rights to undo

    @property
    def is_mutating(self) -> bool:
        """True for anything that can change machine state."""
        return self is not RiskLevel.READ_ONLY


# Tool name -> declared risk. Populated at import time by each tool module.
TOOL_RISK: dict[str, RiskLevel] = {}


def register_risk(tool_name: str, level: RiskLevel) -> None:
    """Declare a tool's risk level. Called once per tool, at definition time.

    Raises on a duplicate name: two tools sharing a name means one of them is
    silently unreachable, and a name registered twice at different levels means
    one of the two labels is a lie.
    """
    if not isinstance(level, RiskLevel):
        raise TypeError(f"{tool_name}: level must be a RiskLevel, got {type(level).__name__}")

    existing = TOOL_RISK.get(tool_name)
    if existing is not None and existing is not level:
        raise ValueError(
            f"{tool_name} already registered as {existing.value}, refusing to re-register as {level.value}"
        )

    TOOL_RISK[tool_name] = level


def get_risk(tool_name: str) -> RiskLevel:
    """Risk level for a tool. Unknown tools are HIGH -- fail closed.

    A tool nobody remembered to register is not a safe tool; it is an unreviewed
    one. Defaulting to HIGH means forgetting a ``register_risk`` call costs an
    extra approval prompt, never an unguarded action.
    """
    return TOOL_RISK.get(tool_name, RiskLevel.HIGH)


def read_only_tools() -> set[str]:
    """Names of every registered read-only tool -- the diagnostic agent's allowance."""
    return {name for name, level in TOOL_RISK.items() if level is RiskLevel.READ_ONLY}


def max_risk(tool_names: list[str]) -> RiskLevel:
    """Highest risk across a set of tools, for labelling a whole fix plan.

    An empty list is READ_ONLY: a plan that does nothing changes nothing.
    """
    order = [RiskLevel.READ_ONLY, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
    return max((get_risk(n) for n in tool_names), key=order.index, default=RiskLevel.READ_ONLY)
