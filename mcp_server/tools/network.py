"""Network observation.

Step 1.5 tools:
- ``get_network_status``: Inspect interfaces, link state, addresses, and error counters.
- ``test_connectivity``: Check reachability, packet loss, and latency via ping.

The remaining Step 1.5 tools (``test_dns``, ``flush_dns_cache``, ``reset_network_stack``)
will use the shared ``_run`` helper built on ``create_subprocess_exec`` with fixed
argument lists.
"""

import asyncio
import re
import socket

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


def register(mcp) -> None:
    """Expose this module's tools on the MCP server and declare their risk."""
    mcp.tool()(get_network_status)
    mcp.tool()(test_connectivity)

    register_risk("get_network_status", RiskLevel.READ_ONLY)
    register_risk("test_connectivity", RiskLevel.READ_ONLY)

