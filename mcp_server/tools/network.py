"""Network observation and remediation.

Step 1.5 tools:
- ``get_network_status``: Inspect interfaces, link state, addresses, and error counters (read_only).
- ``test_connectivity``: Check reachability, packet loss, and latency via ping (read_only).
- ``test_dns``: Query DNS resolution time and resolved IP addresses (read_only).
- ``flush_dns_cache``: Purge the Windows DNS resolver cache (low risk).
- ``reset_network_stack``: Reset Winsock catalog and TCP/IP stack (high risk).
"""

import asyncio
import re
import socket
import time

import psutil

from ..risk import RiskLevel, register_risk

_MB = 1024 ** 2

# 169.254.0.0/16. Windows assigns one of these when DHCP does not answer, so an
# adapter holding one is up and cabled but never got a lease -- visibly "connected"
# with no route anywhere. It is a specific, common, fixable fault, so it is named.
_APIPA_PREFIX = "169.254."

_LOOPBACK_PREFIX = "127."

_PACKETS_RE = re.compile(
    r"Packets:\s+Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\(([\d.]+)%\s*loss\)",
    re.IGNORECASE,
)
_RTT_RE = re.compile(
    r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
    re.IGNORECASE,
)


async def _run(
    *args: str, timeout_seconds: int = 30
) -> tuple[int, str, str]:
    """Execute a subprocess safely with fixed argument list.

    Returns (returncode, stdout, stderr).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return -1, "", f"Executable not found: {exc}"

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"Command timed out after {timeout_seconds}s"

    return (
        proc.returncode if proc.returncode is not None else 0,
        stdout.decode("utf-8", errors="replace").strip(),
        stderr.decode("utf-8", errors="replace").strip(),
    )


def _classify(name: str, addresses: list[dict]) -> tuple[bool, bool]:
    """``(is_loopback, has_routable_ipv4)`` for one interface."""
    is_loopback = "loopback" in name.lower()
    routable = False

    for addr in addresses:
        if addr["family"] != "ipv4":
            continue
        ip = addr["address"]
        if ip.startswith(_LOOPBACK_PREFIX):
            is_loopback = True
        elif not ip.startswith(_APIPA_PREFIX):
            routable = True

    return is_loopback, routable


def _collect() -> list[dict]:
    """One row per interface: addresses, link state, and traffic counters."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)

    rows: list[dict] = []

    for name, entries in addrs.items():
        addresses: list[dict] = []
        mac = None

        for entry in entries:
            if entry.family == socket.AF_INET:
                addresses.append({
                    "family": "ipv4",
                    "address": entry.address,
                    "netmask": entry.netmask,
                })
            elif entry.family == socket.AF_INET6:
                # Strip the zone index (``%12``); it is a local scope id, not part
                # of the address, and it differs per boot.
                addresses.append({
                    "family": "ipv6",
                    "address": entry.address.split("%", 1)[0],
                    "netmask": entry.netmask,
                })
            elif mac is None:
                mac = entry.address

        stat = stats.get(name)
        io = counters.get(name)
        is_loopback, routable = _classify(name, addresses)

        row = {
            "name": name,
            "is_up": bool(stat.isup) if stat else False,
            "is_loopback": is_loopback,
            "mac": mac,
            "addresses": addresses,
            "has_routable_ipv4": routable,
            # Up, addressed, and still unroutable: DHCP never answered.
            "self_assigned_ip": any(
                a["family"] == "ipv4" and a["address"].startswith(_APIPA_PREFIX)
                for a in addresses
            ),
            # psutil reports 0 for adapters that do not advertise a link rate
            # (most virtual ones); None says "unknown", which 0 would misstate.
            "speed_mbps": (stat.speed or None) if stat else None,
            "mtu": stat.mtu if stat else None,
        }

        if io:
            packets = io.packets_sent + io.packets_recv
            errors = io.errin + io.errout
            drops = io.dropin + io.dropout
            row.update({
                "mb_sent": round(io.bytes_sent / _MB, 1),
                "mb_received": round(io.bytes_recv / _MB, 1),
                "packets": packets,
                "errors": errors,
                "drops": drops,
                # Counters are cumulative since boot, so this is a lifetime rate --
                # it says an adapter has been unhealthy at some point, not that it
                # is dropping packets right now. Naming it so the planner cannot
                # read it as a live measurement.
                "error_rate_percent_since_boot": (
                    round((errors + drops) / packets * 100, 3) if packets else 0.0
                ),
            })

        rows.append(row)

    # Up and routable first, then up, then the rest; busiest within each group.
    rows.sort(
        key=lambda r: (r["is_up"] and r["has_routable_ipv4"], r["is_up"], r.get("packets", 0)),
        reverse=True,
    )
    return rows


async def get_network_status() -> dict:
    """Every network interface on the machine, with link state and traffic counters.

    Read-only: it reads adapter tables and reports them. The two fields worth acting
    on are ``no_active_connection`` (nothing is up with a routable address, so no
    connectivity test below this is meaningful) and any interface flagged
    ``self_assigned_ip`` (up, but DHCP never issued a lease).

    Loopback is reported but never counts toward being connected; a machine with
    only ``127.0.0.1`` is offline, however many interfaces it lists.
    """
    try:
        interfaces = await asyncio.to_thread(_collect)
    except OSError as exc:
        return {
            "ok": False,
            "error": "enumeration_failed",
            "message": f"Could not read network interfaces: {exc}",
        }

    usable = [i for i in interfaces if i["is_up"] and not i["is_loopback"]]
    active = [i for i in usable if i["has_routable_ipv4"]]
    stranded = [i["name"] for i in usable if i["self_assigned_ip"]]

    if active:
        message = (
            f"{len(active)} active connection(s): "
            + ", ".join(f"{i['name']} ({i['addresses'][0]['address']})" for i in active[:3] if i["addresses"])
        )
    elif stranded:
        message = (
            f"No routable address. {', '.join(stranded)} is up but holds a self-assigned "
            "169.254.x address, meaning DHCP did not issue a lease."
        )
    elif usable:
        message = f"{len(usable)} interface(s) up but none hold an IP address."
    else:
        message = "No network interface is up. The machine is offline at the adapter level."

    return {
        "ok": True,
        "no_active_connection": not active,
        "active_count": len(active),
        "interface_count": len(interfaces),
        "self_assigned_interfaces": stranded,
        "interfaces": interfaces,
        "message": message,
    }


async def test_connectivity(host: str = "8.8.8.8", count: int = 4) -> dict:
    """Check network reachability and packet loss to a host or IP via ping.

    Read-only tool: measures packet loss and round-trip latency.
    """
    host = (host or "").strip()
    if not host or any(c in host for c in " \t\n\r;|&`$><\"'"):
        return {
            "ok": False,
            "error": "bad_host",
            "message": f"Invalid host name or IP address: {host!r}.",
        }

    try:
        count = max(1, min(int(count), 20))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": "bad_count",
            "message": f"count must be an integer, got {count!r}.",
        }

    timeout_seconds = max(5, count * 3 + 2)
    code, stdout, stderr = await _run(
        "ping.exe", "-n", str(count), "-w", "2000", host,
        timeout_seconds=timeout_seconds,
    )

    if code != 0 and not stdout:
        return {
            "ok": False,
            "error": "ping_failed",
            "host": host,
            "message": f"Ping execution failed: {stderr or 'Unknown error'}",
        }

    pkt_match = _PACKETS_RE.search(stdout)
    rtt_match = _RTT_RE.search(stdout)

    if not pkt_match:
        return {
            "ok": True,
            "host": host,
            "reachable": False,
            "packet_loss_percent": 100.0,
            "packets_sent": count,
            "packets_received": 0,
            "avg_latency_ms": None,
            "message": f"Host {host} is unreachable or could not be resolved.",
        }

    sent = int(pkt_match.group(1))
    received = int(pkt_match.group(2))
    lost = int(pkt_match.group(3))
    loss_pct = float(pkt_match.group(4))

    min_ms = int(rtt_match.group(1)) if rtt_match else None
    max_ms = int(rtt_match.group(2)) if rtt_match else None
    avg_ms = int(rtt_match.group(3)) if rtt_match else None

    reachable = received > 0

    if reachable:
        if loss_pct > 0:
            msg = f"{host} is reachable with {loss_pct:.0f}% packet loss (avg {avg_ms} ms)."
        else:
            msg = f"{host} is reachable with 0% packet loss (avg {avg_ms} ms)."
    else:
        msg = f"{host} is completely unreachable (100% packet loss)."

    return {
        "ok": True,
        "host": host,
        "reachable": reachable,
        "packet_loss_percent": loss_pct,
        "packets_sent": sent,
        "packets_received": received,
        "packets_lost": lost,
        "min_latency_ms": min_ms,
        "max_latency_ms": max_ms,
        "avg_latency_ms": avg_ms,
        "message": msg,
    }


def _resolve_dns(hostname: str) -> list[str]:
    """Synchronous getaddrinfo resolution helper returning unique IPs."""
    info = socket.getaddrinfo(hostname, None)
    addresses: list[str] = []
    seen: set[str] = set()
    for item in info:
        ip = item[4][0]
        if ip not in seen:
            seen.add(ip)
            addresses.append(ip)
    return addresses


async def test_dns(hostname: str = "google.com") -> dict:
    """Test DNS resolution success and latency for a given hostname.

    Read-only tool: measures name resolution time in milliseconds. Flags
    resolution as slow if it takes more than 500 ms.
    """
    host = (hostname or "").strip()
    if not host or any(c in host for c in " \t\n\r;|&`$><\"'"):
        return {
            "ok": False,
            "error": "bad_hostname",
            "message": f"Invalid host name: {hostname!r}.",
        }

    t0 = time.perf_counter()
    try:
        addresses = await asyncio.to_thread(_resolve_dns, host)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
    except socket.gaierror as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "ok": True,
            "hostname": host,
            "resolved": False,
            "addresses": [],
            "latency_ms": round(elapsed_ms, 1),
            "slow": False,
            "message": f"Could not resolve hostname {host!r}: {exc}",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": "dns_lookup_failed",
            "hostname": host,
            "message": f"DNS resolution failed for {host!r}: {exc}",
        }

    slow = elapsed_ms > 500.0
    msg = f"Resolved {host} to {', '.join(addresses[:4])} in {elapsed_ms:.1f} ms."
    if slow:
        msg += " (Slow DNS resolution: >500 ms)."

    return {
        "ok": True,
        "hostname": host,
        "resolved": True,
        "addresses": addresses,
        "latency_ms": round(elapsed_ms, 1),
        "slow": slow,
        "message": msg,
    }


async def flush_dns_cache(dry_run: bool = True) -> dict:
    """Flush the Windows DNS resolver cache.

    Low-risk mutating action. Purges stale or poisoned DNS records by executing
    ``ipconfig /flushdns``. When dry_run is True, returns a preview without modifying
    the system.
    """
    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "message": "Would flush the Windows DNS resolver cache (ipconfig /flushdns).",
        }

    code, stdout, stderr = await _run("ipconfig.exe", "/flushdns", timeout_seconds=15)
    if code != 0:
        return {
            "ok": False,
            "dry_run": False,
            "error": "flush_failed",
            "message": f"Failed to flush DNS cache: {stderr or stdout or 'Unknown error'}",
        }

    return {
        "ok": True,
        "dry_run": False,
        "message": "Successfully flushed the Windows DNS resolver cache.",
    }


async def reset_network_stack(dry_run: bool = True) -> dict:
    """Reset the Winsock catalog and TCP/IP stack to default state.

    HIGH-risk mutating action: executes ``netsh winsock reset`` and ``netsh int ip reset``.
    Requires administrator privileges and a system reboot to take full effect.
    When dry_run is True, returns a preview warning.
    """
    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "needs_admin": True,
            "needs_reboot": True,
            "message": (
                "Would reset Winsock catalog ('netsh winsock reset') and TCP/IP stack "
                "('netsh int ip reset'). Requires administrator privileges and a reboot."
            ),
        }

    code_ws, out_ws, err_ws = await _run("netsh.exe", "winsock", "reset", timeout_seconds=15)
    code_ip, out_ip, err_ip = await _run("netsh.exe", "int", "ip", "reset", timeout_seconds=15)

    if code_ws != 0 or code_ip != 0:
        err = err_ws or err_ip or out_ws or out_ip
        return {
            "ok": False,
            "dry_run": False,
            "error": "reset_failed",
            "message": f"Network stack reset failed (elevation may be required): {err}",
        }

    return {
        "ok": True,
        "dry_run": False,
        "needs_reboot": True,
        "message": "Successfully reset Winsock and TCP/IP stack. A system reboot is required.",
    }


def register(mcp) -> None:
    """Expose this module's tools on the MCP server and declare their risk."""
    mcp.tool()(get_network_status)
    mcp.tool()(test_connectivity)
    mcp.tool()(test_dns)
    mcp.tool()(flush_dns_cache)
    mcp.tool()(reset_network_stack)

    register_risk("get_network_status", RiskLevel.READ_ONLY)
    register_risk("test_connectivity", RiskLevel.READ_ONLY)
    register_risk("test_dns", RiskLevel.READ_ONLY)
    register_risk("flush_dns_cache", RiskLevel.LOW)
    register_risk("reset_network_stack", RiskLevel.HIGH)


