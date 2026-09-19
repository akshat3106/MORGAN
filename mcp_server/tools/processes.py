"""Process observation and termination.

Two tools with very different weight. ``list_top_processes`` only looks, and is part
of the diagnostic agent's allowance. ``terminate_process`` kills something a user is
probably relying on, so it is MEDIUM risk: it previews by default, and it refuses the
processes Windows cannot survive losing -- that refusal is not advice to the model, it
is a branch taken before any call to ``terminate()`` can be reached.

The protected list is matched on the executable name, lowercased, with ``.exe``
stripped, because psutil reports ``System`` on one machine and ``svchost.exe`` on the
next and the guard must not care which.
"""

import asyncio
import os

import psutil

from ..risk import RiskLevel, register_risk

# Kill any of these and the machine either bluescreens, loses its session, or drops
# every service hosted inside it. ``explorer`` is survivable -- it restarts itself --
# but killing it wipes the taskbar mid-incident, which is never the fix MORGAN wanted.
PROTECTED_PROCESSES: frozenset[str] = frozenset({
    "system",
    "registry",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "svchost",
    "dwm",
    "explorer",
    # Not a real process -- pid 0 is the idle counter. Named here so that a request
    # to kill it is refused with the protected message rather than an OS-level error.
    "system idle process",
    "idle",
})

# Windows accounts unused cycles to the idle process, so it reports whatever is left
# over -- 925% on a 12-core machine that is doing nothing. Reported as a process it
# reads as the top CPU consumer on the box, which is the exact opposite of the truth,
# so it is dropped from listings rather than explained in a prompt afterwards.
_IDLE_PIDS: frozenset[int] = frozenset({0})

_MB = 1024 ** 2

_SORT_KEYS: frozenset[str] = frozenset({"cpu", "memory"})


def _normalise(name: str | None) -> str:
    """Executable name -> the form the protected list is written in."""
    stem = (name or "").strip().lower()
    return stem[:-4] if stem.endswith(".exe") else stem


def is_protected(name: str | None) -> bool:
    """True if this process must never be terminated by MORGAN."""
    return _normalise(name) in PROTECTED_PROCESSES


async def list_top_processes(sort_by: str = "cpu", limit: int = 15) -> dict:
    """The heaviest processes on the machine, by cpu or memory.

    ``cpu_percent`` is a delta between two samples, so a single pass reports 0.0 for
    everything. This primes every process, waits out one real interval, then reads --
    the wait is the measurement, not a pause before it.

    Every row carries ``protected``, so whatever reads this list already knows which
    entries ``terminate_process`` will refuse, before it proposes one.
    """
    sort_by = (sort_by or "cpu").strip().lower()
    if sort_by not in _SORT_KEYS:
        return {
            "ok": False,
            "error": "bad_sort_key",
            "message": f"sort_by must be one of {sorted(_SORT_KEYS)}, got {sort_by!r}.",
        }
    limit = max(1, min(int(limit), 100))

    procs = list(psutil.process_iter(["pid", "name"]))

    # First pass: establish the baseline every later reading is measured against.
    for proc in procs:
        try:
            proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # One shared interval for all of them, taken off the event loop.
    await asyncio.to_thread(psutil.cpu_percent, 0.5)

    logical_cores = psutil.cpu_count(logical=True) or 1
    rows: list[dict] = []

    for proc in procs:
        if proc.info["pid"] in _IDLE_PIDS:
            continue
        try:
            name = proc.info.get("name")
            cpu = proc.cpu_percent(None)
            rss = proc.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Processes die mid-scan constantly; a vanished one is not an error.
            continue

        rows.append({
            "pid": proc.info["pid"],
            "name": name,
            # psutil reports cpu across all cores, so 400% is real on a quad-core.
            # Both readings are given: raw for comparing processes, normalised for
            # "how much of this machine is it eating".
            "cpu_percent": round(cpu, 1),
            "cpu_percent_of_machine": round(cpu / logical_cores, 1),
            "memory_mb": round(rss / _MB, 1),
            "protected": is_protected(name),
        })

    key = "cpu_percent" if sort_by == "cpu" else "memory_mb"
    rows.sort(key=lambda row: row[key], reverse=True)

    return {
        "ok": True,
        "sorted_by": sort_by,
        "total_processes": len(rows),
        "processes": rows[:limit],
    }


async def terminate_process(pid: int, dry_run: bool = True) -> dict:
    """Terminate a process by PID. Previews unless ``dry_run`` is explicitly False.

    Order matters here. The process is resolved to a name *first*, then checked
    against ``PROTECTED_PROCESSES``, and that check returns before the ``dry_run``
    branch is ever reached -- so a protected process is refused identically whether
    this was a preview or a live call. Nothing gets past it by claiming intent.

    Failure modes are reported distinctly because they mean different things to the
    planner: ``access_denied`` says retry elevated, ``timeout`` says the process
    ignored a polite request, ``no_such_process`` says the plan was built against a
    machine state that has since moved on.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad_pid", "message": f"pid must be an integer, got {pid!r}."}

    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.NoSuchProcess:
        return {
            "ok": False,
            "error": "no_such_process",
            "message": f"No process with pid {pid}.",
            "pid": pid,
        }
    except psutil.AccessDenied:
        return {
            "ok": False,
            "error": "access_denied",
            "message": f"Cannot inspect pid {pid}; MORGAN is not running elevated.",
            "pid": pid,
        }

    # Guard first, and independently of dry_run.
    if is_protected(name):
        return {
            "ok": False,
            "error": "protected_process",
            "message": (
                f"{name} (pid {pid}) is a protected system process and will not be "
                "terminated. Killing it would take the session or the machine down."
            ),
            "pid": pid,
            "name": name,
        }

    # Killing the server mid-request strands the agent waiting on a reply that can no
    # longer be sent.
    if pid == os.getpid():
        return {
            "ok": False,
            "error": "self_terminate",
            "message": f"pid {pid} is MORGAN's own process.",
            "pid": pid,
            "name": name,
        }

    if dry_run:
        try:
            memory_mb = round(proc.memory_info().rss / _MB, 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            memory_mb = None
        return {
            "ok": True,
            "dry_run": True,
            "pid": pid,
            "name": name,
            "memory_mb": memory_mb,
            "message": f"Would terminate {name} (pid {pid}), reclaiming ~{memory_mb} MB.",
        }

    try:
        proc.terminate()
        # terminate() only asks; wait() is what confirms the process actually went.
        await asyncio.to_thread(proc.wait, 5)
    except psutil.NoSuchProcess:
        # It exited between the guard and the call -- the requested end state holds.
        return {
            "ok": True,
            "dry_run": False,
            "pid": pid,
            "name": name,
            "message": f"{name} (pid {pid}) had already exited.",
        }
    except psutil.AccessDenied:
        return {
            "ok": False,
            "error": "access_denied",
            "message": f"Denied terminating {name} (pid {pid}); requires elevation.",
            "pid": pid,
            "name": name,
        }
    except psutil.TimeoutExpired:
        return {
            "ok": False,
            "error": "timeout",
            "message": (
                f"{name} (pid {pid}) did not exit within 5s of a terminate request. "
                "It is still running; a forced kill was not attempted."
            ),
            "pid": pid,
            "name": name,
        }

    return {
        "ok": True,
        "dry_run": False,
        "pid": pid,
        "name": name,
        "message": f"Terminated {name} (pid {pid}).",
    }


def register(mcp) -> None:
    """Expose this module's tools on the MCP server and declare their risk."""
    mcp.tool()(list_top_processes)
    mcp.tool()(terminate_process)

    register_risk("list_top_processes", RiskLevel.READ_ONLY)
    register_risk("terminate_process", RiskLevel.MEDIUM)
