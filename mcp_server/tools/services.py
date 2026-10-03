"""Windows service observation and remediation.

Step 1.6 tools:
- ``list_services``: Inspect installed Windows services, link status, and startup configuration (read_only).
- ``restart_service``: Stop and restart a non-protected Windows service via ``sc.exe`` (medium risk).
"""

import asyncio
from typing import Any

import psutil

from ..risk import RiskLevel, register_risk

# Critical core Windows services that MORGAN must never stop or restart.
# Any attempt to restart these will result in an immediate refusal regardless of dry_run.
PROTECTED_SERVICES: frozenset[str] = frozenset({
    "rpcss",         # Remote Procedure Call (RPC)
    "dcomlaunch",    # DCOM Server Process Launcher
    "lsm",           # Local Session Manager
    "winlogon",      # Windows Logon Process
    "profsvc",       # User Profile Service
    "themes",        # Themes
    "plugplay",      # Plug and Play
})


def _normalise(name: str | None) -> str:
    """Normalise service name for case-insensitive matching."""
    return (name or "").strip().lower()


def is_protected(name: str | None) -> bool:
    """True if this service is protected and must never be restarted."""
    return _normalise(name) in PROTECTED_SERVICES


async def _sc(
    *args: str, timeout_seconds: int = 30
) -> tuple[int, str, str]:
    """Execute ``sc.exe`` with fixed argument list.

    Returns (returncode, stdout, stderr).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "sc.exe",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return -1, "", f"sc.exe not found: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", f"Timed out after {timeout_seconds}s waiting for sc.exe"

    out_text = stdout.decode("utf-8", errors="replace").strip()
    err_text = stderr.decode("utf-8", errors="replace").strip()
    return proc.returncode or 0, out_text, err_text


async def list_services(
    status_filter: str = "all",
    name_contains: str = "",
) -> dict[str, Any]:
    """List installed Windows services with their display name, status, and start type.

    Args:
        status_filter: Filter by service status: 'all', 'running', or 'stopped'.
        name_contains: Optional substring match on service name or display name (case-insensitive).

    Returns:
        Dictionary with list of matching services and summary counts.
    """
    status_norm = (status_filter or "all").strip().lower()
    match_norm = (name_contains or "").strip().lower()

    services: list[dict[str, Any]] = []
    running_count = 0
    stopped_count = 0

    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue

        name = info.get("name") or ""
        display_name = info.get("display_name") or ""
        status = info.get("status") or "unknown"
        start_type = info.get("start_type") or "unknown"
        pid = info.get("pid")
        binpath = info.get("binpath") or ""
        description = info.get("description") or ""

        if status == "running":
            running_count += 1
        elif status == "stopped":
            stopped_count += 1

        # Apply status filter
        if status_norm != "all" and status.lower() != status_norm:
            continue

        # Apply substring filter
        if match_norm and (match_norm not in name.lower() and match_norm not in display_name.lower()):
            continue

        services.append({
            "name": name,
            "display_name": display_name,
            "status": status,
            "start_type": start_type,
            "pid": pid,
            "protected": is_protected(name),
            "binpath": binpath,
            "description": description,
        })

    # Sort alphabetically by service name
    services.sort(key=lambda s: s["name"].lower())

    return {
        "ok": True,
        "services": services,
        "count": len(services),
        "summary": {
            "total_matching": len(services),
            "system_running": running_count,
            "system_stopped": stopped_count,
        },
    }


async def restart_service(
    name: str,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Restart a Windows service by stopping and then starting it.

    MEDIUM-risk mutating action.
    - Protected system services (e.g., rpcss, dcomlaunch, winlogon) are refused at preview and execution.
    - If dry_run is True (default), previews the action and verifies service existence without restarting.
    - When executing, error 1062 ('service has not been started') on stop is tolerated as benign.

    Args:
        name: Short name of the Windows service (e.g., 'wuauserv', 'Spooler').
        dry_run: If True, preview only; if False, execute restart.

    Returns:
        Result dictionary with status and message.
    """
    clean_name = (name or "").strip()
    if not clean_name:
        return {
            "ok": False,
            "dry_run": dry_run,
            "error": "invalid_name",
            "message": "Service name cannot be empty.",
        }

    # Protected check: Refuse unconditionally before touching the service
    if is_protected(clean_name):
        return {
            "ok": False,
            "dry_run": dry_run,
            "refused": True,
            "protected": True,
            "service": clean_name,
            "error": "protected_service",
            "message": f"Service '{clean_name}' is critical to Windows operation and cannot be restarted.",
        }

    # Verify service existence
    try:
        svc = psutil.win_service_get(clean_name)
        info = svc.as_dict()
        display_name = info.get("display_name") or clean_name
        current_status = info.get("status") or "unknown"
    except (psutil.NoSuchProcess, ValueError, OSError):
        return {
            "ok": False,
            "dry_run": dry_run,
            "service": clean_name,
            "error": "service_not_found",
            "message": f"Service '{clean_name}' does not exist on this machine.",
        }

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "service": clean_name,
            "display_name": display_name,
            "current_status": current_status,
            "message": (
                f"Would stop and restart service '{clean_name}' ({display_name}). "
                f"Current status: {current_status}."
            ),
        }

    # Live execution: Stop service
    code_stop, out_stop, err_stop = await _sc("stop", clean_name, timeout_seconds=20)
    if code_stop != 0:
        combined = f"{out_stop} {err_stop}".lower()
        # Windows error 1062: "The service has not been started" is benign for restart
        if "1062" in combined or "not been started" in combined:
            pass
        else:
            err_msg = err_stop or out_stop or f"Exit code {code_stop}"
            return {
                "ok": False,
                "dry_run": False,
                "service": clean_name,
                "display_name": display_name,
                "error": "stop_failed",
                "message": f"Failed to stop service '{clean_name}' (elevation may be required): {err_msg}",
            }

    # Brief delay for cleanup before starting
    await asyncio.sleep(2.0)

    # Start service
    code_start, out_start, err_start = await _sc("start", clean_name, timeout_seconds=20)
    if code_start != 0:
        err_msg = err_start or out_start or f"Exit code {code_start}"
        return {
            "ok": False,
            "dry_run": False,
            "service": clean_name,
            "display_name": display_name,
            "error": "start_failed",
            "message": f"Failed to start service '{clean_name}' (elevation may be required): {err_msg}",
        }

    # Query updated status
    try:
        svc_after = psutil.win_service_get(clean_name)
        new_status = svc_after.status()
    except Exception:
        new_status = "unknown"

    return {
        "ok": True,
        "dry_run": False,
        "service": clean_name,
        "display_name": display_name,
        "status": new_status,
        "message": f"Service '{clean_name}' ({display_name}) was successfully restarted. New status: {new_status}.",
    }


def register(mcp) -> None:
    """Expose this module's tools on the MCP server and declare their risk."""
    mcp.tool()(list_services)
    mcp.tool()(restart_service)

    register_risk("list_services", RiskLevel.READ_ONLY)
    register_risk("restart_service", RiskLevel.MEDIUM)
