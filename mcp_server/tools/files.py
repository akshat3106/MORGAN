"""Temp-file analysis, temp cleanup, and large-file discovery.

The disk-full incident is the one MORGAN is most often going to be handed, and temp
cleanup is the fix that resolves it. That makes this module the place where "low
risk" has to actually mean something, so three rules are enforced in code rather
than described in a prompt:

*Age is measured from the newest thing in the tree.* A top-level temp entry is only
stale if nothing inside it has been touched since the cutoff -- a week-old folder
that an installer wrote to an hour ago is in use, whatever its own timestamp says.
Windows updates directory mtimes inconsistently, so a directory's own stamp is never
trusted on its own.

*A locked file is skipped, never forced.* Something holding a handle is something
running. Every removal failure lands in ``skipped`` with its reason and the tool
still reports ``ok`` -- a partial clean is the expected outcome on a live machine,
not an error, and the planner needs the reclaimed figure either way.

*Nothing above a temp root is reachable.* Entries are re-resolved and checked to be
inside the root that produced them immediately before removal, so a symlink or
junction planted in ``%TEMP%`` cannot walk the delete out into the rest of the disk.
"""

import asyncio
import os
import shutil
import time
from pathlib import Path

from ..risk import RiskLevel, register_risk

_MB = 1024 ** 2

# A directory tree can be pathological (node_modules, a build cache with a million
# files). The walk stops here and says so rather than hanging the agent mid-incident.
_MAX_ENTRIES = 200_000

# FILE_ATTRIBUTE_REPARSE_POINT
_REPARSE_POINT = 0x400


def _temp_dirs() -> list[Path]:
    """The temp roots worth scanning, de-duplicated, existing ones only.

    ``TEMP`` and ``%LOCALAPPDATA%\\Temp`` are usually the same directory reached by
    two different names, and on some machines ``TMP`` is a third. Dedup is by
    resolved path, so the same bytes are never counted twice into a reclaim figure.
    """
    candidates = [
        os.environ.get("TEMP"),
        os.environ.get("TMP"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
    ]

    seen: set[str] = set()
    roots: list[Path] = []
    for raw in candidates:
        if not raw:
            continue
        try:
            path = Path(os.path.expandvars(raw)).resolve()
        except OSError:
            continue
        if not path.is_dir():
            continue
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        roots.append(path)
    return roots


def _is_link(entry: os.DirEntry) -> bool:
    """True for symlinks and Windows junctions/reparse points.

    Junctions report ``is_dir()`` true and ``is_symlink()`` false, which is how a
    recursive walk ends up following ``Application Data`` in a circle. The
    reparse-point attribute catches both.
    """
    try:
        if entry.is_symlink():
            return True
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & _REPARSE_POINT)
    except OSError:
        return True  # Unreadable: treat as something not to descend into.


def _tree_stats(path: Path) -> tuple[int, float, int]:
    """``(total_bytes, newest_mtime, unreadable_count)`` for a directory tree.

    Unreadable children are counted, not raised on: a temp directory always holds
    something the current user cannot stat, and that must not abort the scan. Their
    bytes are simply not claimed as reclaimable.
    """
    total = 0
    newest = 0.0
    unreadable = 0
    stack = [str(path)]

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False) and not _is_link(entry):
                            stack.append(entry.path)
                            continue
                        stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        unreadable += 1
                        continue
                    total += stat.st_size
                    newest = max(newest, stat.st_mtime)
        except OSError:
            unreadable += 1

    return total, newest, unreadable


def _scan_temp(days: int) -> tuple[list[dict], int, list[dict]]:
    """Stale top-level temp entries, their total size, and what could not be read.

    Returns ``(entries, total_bytes, skipped)``. ``entries`` are candidates for
    removal -- nothing inside them has changed since the cutoff; ``total_bytes`` is
    their combined size, which is the reclaim estimate; ``skipped`` holds entries
    that exist but could not be measured, so the caller can say what it failed to
    account for instead of silently under-reporting.
    """
    now = time.time()
    cutoff = now - (days * 86400)
    entries: list[dict] = []
    skipped: list[dict] = []
    total = 0

    for root in _temp_dirs():
        try:
            children = list(os.scandir(root))
        except OSError as exc:
            skipped.append({"path": str(root), "reason": "unreadable_root", "detail": str(exc)})
            continue

        for child in children:
            try:
                stat = child.stat(follow_symlinks=False)
                # Links are never candidates. A junction is not the bytes it points
                # at, and unlinking one deletes a pointer while reporting its target's
                # size as reclaimed -- a reclaim figure that was never true.
                if child.is_symlink() or stat.st_file_attributes & _REPARSE_POINT:
                    skipped.append({"path": child.path, "reason": "symlink_or_junction"})
                    continue
                is_dir = child.is_dir(follow_symlinks=False)
                if is_dir:
                    size, newest, unreadable = _tree_stats(Path(child.path))
                    # An empty directory has no newest child; fall back to its own stamp.
                    mtime = newest or stat.st_mtime
                else:
                    size, mtime, unreadable = stat.st_size, stat.st_mtime, 0
            except OSError as exc:
                skipped.append({"path": child.path, "reason": "unreadable", "detail": str(exc)})
                continue

            if mtime >= cutoff:
                continue  # Touched inside the window -- something is still using it.

            entries.append({
                "path": child.path,
                "root": str(root),
                "is_dir": is_dir,
                "size_mb": round(size / _MB, 2),
                "size_bytes": size,
                "age_days": round((now - mtime) / 86400, 1),
                # Non-zero means the size below is a floor, not the whole truth.
                "unreadable_children": unreadable,
            })
            total += size

    entries.sort(key=lambda row: row["size_bytes"], reverse=True)
    return entries, total, skipped


async def analyze_temp_files(older_than_days: int = 7) -> dict:
    """How much stale temp data is on this machine, and where it sits.

    Read-only by construction: it stats and it reports. This is what the diagnostic
    agent calls to turn "the disk is full" into a number that a proposed fix can be
    measured against afterwards.
    """
    try:
        days = max(0, int(older_than_days))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": "bad_older_than_days",
            "message": f"older_than_days must be an integer, got {older_than_days!r}.",
        }

    roots = _temp_dirs()
    if not roots:
        return {
            "ok": False,
            "error": "no_temp_dirs",
            "message": "No readable temp directory found via TEMP, TMP, SystemRoot or LOCALAPPDATA.",
        }

    entries, total, skipped = await asyncio.to_thread(_scan_temp, days)

    return {
        "ok": True,
        "older_than_days": days,
        "temp_dirs": [str(r) for r in roots],
        "file_count": len(entries),
        "total_mb": round(total / _MB, 1),
        "largest": entries[:20],
        "skipped_count": len(skipped),
        "skipped": skipped[:10],
        "message": (
            f"{len(entries)} temp entries older than {days} days, "
            f"{round(total / _MB, 1)} MB across {len(roots)} temp directories."
        ),
    }


def _remove(entry: dict) -> tuple[bool, str | None]:
    """Remove one scanned entry. Returns ``(removed, reason_if_not)``.

    The path is re-checked against its own temp root immediately before deletion.
    The scan and the delete are separate passes, and in between them a junction can
    appear in a world-writable directory; this is the check that means a redirected
    path is refused rather than followed out of ``%TEMP%``.
    """
    path = Path(entry["path"])
    root = Path(entry["root"])

    try:
        if not path.resolve().is_relative_to(root.resolve()):
            return False, "outside_temp_root"
    except OSError as exc:
        return False, f"unresolvable: {exc}"

    try:
        if entry["is_dir"]:
            # ignore_errors stays False: a locked child must surface as a skip with a
            # reason, not vanish into a half-deleted tree reported as success.
            shutil.rmtree(path)
        else:
            path.unlink()
    except FileNotFoundError:
        return True, None  # Already gone; the requested end state holds.
    except PermissionError:
        return False, "locked_or_in_use"
    except OSError as exc:
        return False, str(exc)

    return True, None


async def clean_temp_files(older_than_days: int = 7, dry_run: bool = True) -> dict:
    """Delete stale temp entries. Previews unless ``dry_run`` is explicitly False.

    LOW risk, not READ_ONLY: it destroys data, but only data Windows already treats
    as disposable, and only entries untouched for the whole window. Locked files are
    left alone -- a handle is a running program, and prising files out from under one
    turns a disk-space fix into an application crash.

    A run that skips entries still reports ``ok``. On a live machine that is the
    normal result, and the planner needs ``reclaimed_mb`` to verify the fix either way.
    """
    try:
        days = max(0, int(older_than_days))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": "bad_older_than_days",
            "message": f"older_than_days must be an integer, got {older_than_days!r}.",
        }

    entries, total, unreadable = await asyncio.to_thread(_scan_temp, days)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "older_than_days": days,
            "would_delete_count": len(entries),
            "would_reclaim_mb": round(total / _MB, 1),
            "largest": entries[:20],
            "unreadable_count": len(unreadable),
            "message": (
                f"Would delete {len(entries)} temp entries older than {days} days, "
                f"reclaiming ~{round(total / _MB, 1)} MB. Locked files will be skipped."
            ),
        }

    removed = 0
    reclaimed = 0
    skipped: list[dict] = []

    def _sweep() -> None:
        nonlocal removed, reclaimed
        for entry in entries:
            ok, reason = _remove(entry)
            if ok:
                removed += 1
                reclaimed += entry["size_bytes"]
            else:
                skipped.append({
                    "path": entry["path"],
                    "size_mb": entry["size_mb"],
                    "reason": reason,
                })

    await asyncio.to_thread(_sweep)

    return {
        "ok": True,
        "dry_run": False,
        "older_than_days": days,
        "deleted_count": removed,
        "reclaimed_mb": round(reclaimed / _MB, 1),
        "skipped_count": len(skipped),
        "skipped": skipped[:20],
        "message": (
            f"Deleted {removed} of {len(entries)} temp entries, reclaiming "
            f"{round(reclaimed / _MB, 1)} MB. {len(skipped)} skipped (locked or in use)."
        ),
    }


def _walk_large(root: Path, min_bytes: int, limit: int) -> tuple[list[dict], int, int, bool]:
    """``(rows, scanned, unreadable, truncated)`` -- files at or above ``min_bytes``."""
    now = time.time()
    rows: list[dict] = []
    scanned = 0
    unreadable = 0
    truncated = False
    stack = [str(root)]

    while stack and not truncated:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    scanned += 1
                    if scanned > _MAX_ENTRIES:
                        truncated = True
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not _is_link(entry):
                                stack.append(entry.path)
                            continue
                        if _is_link(entry):
                            continue  # Report the target where its bytes actually live.
                        stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        unreadable += 1
                        continue
                    if stat.st_size >= min_bytes:
                        rows.append({
                            "path": entry.path,
                            "size_mb": round(stat.st_size / _MB, 1),
                            "size_bytes": stat.st_size,
                            "modified_days_ago": round((now - stat.st_mtime) / 86400, 1),
                        })
        except OSError:
            unreadable += 1

    rows.sort(key=lambda row: row["size_bytes"], reverse=True)
    return rows[:limit], scanned, unreadable, truncated


async def find_large_files(directory: str, min_size_mb: int = 500, limit: int = 20) -> dict:
    """The biggest files under a directory. Read-only; finds, never removes.

    This is the second half of the disk-full diagnosis: temp cleanup explains part of
    a full drive, and this explains the rest -- an ISO in Downloads, a runaway log, an
    old VM image. What to do about those is the user's decision, which is why nothing
    here deletes.

    Symlinks and junctions are not followed, so a file is reported once, at the path
    that really holds its bytes.
    """
    if not directory or not str(directory).strip():
        return {
            "ok": False,
            "error": "no_directory",
            "message": "directory is required; pass a path such as C:\\Users\\you\\Downloads.",
        }

    try:
        min_size_mb = max(0, int(min_size_mb))
        limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": "bad_arguments",
            "message": "min_size_mb and limit must be integers.",
        }

    try:
        root = Path(os.path.expandvars(str(directory))).expanduser().resolve()
    except OSError as exc:
        return {
            "ok": False,
            "error": "bad_directory",
            "message": f"Could not resolve {directory!r}: {exc}",
        }

    if not root.is_dir():
        return {
            "ok": False,
            "error": "not_a_directory",
            "message": f"{root} is not an existing directory.",
        }

    rows, scanned, unreadable, truncated = await asyncio.to_thread(
        _walk_large, root, min_size_mb * _MB, limit
    )

    message = f"{len(rows)} files at or above {min_size_mb} MB under {root}."
    if truncated:
        message += f" Scan stopped at {_MAX_ENTRIES} entries; results are partial."
    if unreadable:
        message += f" {unreadable} locations were unreadable."

    return {
        "ok": True,
        "directory": str(root),
        "min_size_mb": min_size_mb,
        "scanned_entries": scanned,
        "unreadable_count": unreadable,
        "truncated": truncated,
        "match_count": len(rows),
        "files": rows,
        "message": message,
    }


def register(mcp) -> None:
    """Expose this module's tools on the MCP server and declare their risk."""
    mcp.tool()(analyze_temp_files)
    mcp.tool()(clean_temp_files)
    mcp.tool()(find_large_files)

    register_risk("analyze_temp_files", RiskLevel.READ_ONLY)
    register_risk("clean_temp_files", RiskLevel.LOW)
    register_risk("find_large_files", RiskLevel.READ_ONLY)
