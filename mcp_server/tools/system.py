"""Read-only machine observation: disks, health, and locked-down PowerShell.

Nothing in this module can change the machine. Every tool here is READ_ONLY, which
is what makes them the diagnostic agent's entire allowance -- it looks with these
and reports, and cannot act on a hunch.

``run_powershell_readonly`` is the exception that needs care: PowerShell *can* do
anything, so the safety here is not "the model was told to be careful" but two
mechanical gates it cannot argue with -- no shell metacharacters, and the first
word must be on a whitelist of observation-only cmdlets.
"""

import asyncio
import platform
import shutil
import time

import psutil

from ..risk import RiskLevel, register_risk

# Cmdlets that only observe. Anything absent is rejected -- fail closed, same rule
# as the risk registry. Note Get-* is NOT blanket-allowed: Get-Content can read any
# file on the disk, so it is deliberately off this list.
POWERSHELL_WHITELIST: frozenset[str] = frozenset({
    "get-process",
    "get-service",
    "get-computerinfo",
    "get-ciminstance",
    "get-wmiobject",
    "get-hotfix",
    "get-eventlog",
    "get-winevent",
    "get-netadapter",
    "get-netipaddress",
    "get-netipconfiguration",
    "get-nettcpconnection",
    "get-dnsclientcache",
    "get-pnpdevice",
    "get-volume",
    "get-physicaldisk",
    "get-disk",
    "get-partition",
    "get-scheduledtask",
    "get-localuser",
    "get-timezone",
    "get-uptime",
})

# Characters that chain one command into another, redirect output, or interpolate a
# subshell. Any of these means the string is no longer a single observed command.
_FORBIDDEN_CHARS: tuple[str, ...] = (";", "|", "&", ">", "<", "`", "$(", "\n", "\r")

_GB = 1024 ** 3

# psutil.cpu_percent() returns 0.0 the first time it is called in a process, because
# it has no previous sample to compare against. Prime it once at import so the first
# real reading is a measurement rather than a lie.
psutil.cpu_percent(interval=None)


def _gb(value: int | float) -> float:
    """Bytes -> gigabytes, rounded for display."""
    return round(value / _GB, 2)


async def get_disk_usage() -> dict:
    """Free and used space on every fixed drive.

    Returns a ``drives`` list and a top-level ``low_space`` flag. A drive is flagged
    when less than 10% of it is free -- the threshold lives here, in code, not in a
    prompt, so the question of whether a drive is full is not the model's opinion.
    """
    drives: list[dict] = []

    for part in psutil.disk_partitions(all=False):
        # Empty optical/card readers raise on access rather than reporting 0 bytes.
        if "cdrom" in part.opts.lower() or not part.fstype:
            continue
        try:
            total, used, free = shutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue

        percent_used = round(used / total * 100, 1) if total else 0.0
        drives.append({
            "drive": part.device,
            "mountpoint": part.mountpoint,
            "filesystem": part.fstype,
            "total_gb": _gb(total),
            "used_gb": _gb(used),
            "free_gb": _gb(free),
            "percent_used": percent_used,
            "low_space": percent_used >= 90.0,
        })

    return {
        "ok": True,
        "drives": drives,
        "low_space": any(d["low_space"] for d in drives),
    }


async def get_system_health() -> dict:
    """CPU load, memory pressure, swap, uptime, and OS identity.

    ``load_high`` and ``pressure_high`` fire above 85%. Like ``low_space``, these are
    code-side judgements handed to the model as facts.
    """
    # A real 0.5s sample, taken off the event loop so the server stays responsive.
    # cpu_percent(interval=None) would return the average since the last call, which
    # for a long-lived server is meaningless.
    cpu_percent = await asyncio.to_thread(psutil.cpu_percent, 0.5)

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    boot_time = psutil.boot_time()
    uptime_seconds = max(0.0, time.time() - boot_time)

    return {
        "ok": True,
        "cpu": {
            "percent": cpu_percent,
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "load_high": cpu_percent > 85.0,
        },
        "memory": {
            "total_gb": _gb(mem.total),
            "used_gb": _gb(mem.used),
            "available_gb": _gb(mem.available),
            "percent": mem.percent,
            "pressure_high": mem.percent > 85.0,
        },
        "swap": {
            "total_gb": _gb(swap.total),
            "used_gb": _gb(swap.used),
            "percent": swap.percent,
        },
        "uptime": {
            "boot_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot_time)),
            "uptime_hours": round(uptime_seconds / 3600, 1),
            "uptime_days": round(uptime_seconds / 86400, 2),
        },
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": platform.node(),
        },
    }


async def run_powershell_readonly(command: str, timeout_seconds: int = 30) -> dict:
    """Run one whitelisted, observation-only PowerShell command.

    Two gates, in this order:

    1. **Chaining check.** Any of ``; | & > <`` a backtick or ``$(`` and the command
       is refused outright. This runs *first* on purpose: ``Get-Process; Remove-Item x``
       starts with a whitelisted word, so a whitelist check alone would pass the
       dangerous half through. Order also keeps the error message honest -- rejecting
       that string as "not whitelisted" would be true-ish but misleading.
    2. **Whitelist check.** The first token must be a known read-only cmdlet.

    Only then does it execute, with a hard timeout so a wedged command cannot hang
    the agent. ``create_subprocess_exec`` takes a fixed argument list -- there is no
    shell parsing the string, so there is no shell injection surface.
    """
    command = (command or "").strip()
    if not command:
        return {"ok": False, "error": "empty_command", "message": "No command supplied."}

    # Gate 1: chaining / redirection / subshell -- before anything else.
    for token in _FORBIDDEN_CHARS:
        if token in command:
            return {
                "ok": False,
                "error": "forbidden_syntax",
                "message": (
                    f"Command rejected: contains {token!r}. Chaining, redirection and "
                    "subshells are not permitted -- run one cmdlet per call."
                ),
            }

    # Gate 2: whitelist, matched on the first token only.
    cmdlet = command.split()[0].lower()
    if cmdlet not in POWERSHELL_WHITELIST:
        return {
            "ok": False,
            "error": "not_whitelisted",
            "message": f"{cmdlet!r} is not a permitted read-only cmdlet.",
            "allowed": sorted(POWERSHELL_WHITELIST),
        }

    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "powershell_missing", "message": "powershell.exe not found."}

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        # communicate() was cancelled, but the process itself is still running --
        # kill it explicitly or it outlives the request.
        proc.kill()
        await proc.wait()
        return {
            "ok": False,
            "error": "timeout",
            "message": f"Command exceeded {timeout_seconds}s and was killed.",
            "command": command,
        }

    return {
        "ok": proc.returncode == 0,
        "command": command,
        "exit_code": proc.returncode,
        "stdout": stdout.decode("utf-8", errors="replace").strip(),
        "stderr": stderr.decode("utf-8", errors="replace").strip(),
    }


def register(mcp) -> None:
    """Expose this module's tools on the MCP server and declare their risk."""
    mcp.tool()(get_disk_usage)
    mcp.tool()(get_system_health)
    mcp.tool()(run_powershell_readonly)

    register_risk("get_disk_usage", RiskLevel.READ_ONLY)
    register_risk("get_system_health", RiskLevel.READ_ONLY)
    register_risk("run_powershell_readonly", RiskLevel.READ_ONLY)
