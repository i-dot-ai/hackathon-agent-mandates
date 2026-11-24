"""Safe counts for pupil-data.aggregate (OpenSpec add-safe-counts, question 8).

    check(arguments, claims)   before forwarding: no identifier columns, level 4 only at clearance 4,
                               at most 2 group_by columns, where only on level 1-2 columns
    breakdown_arguments(...)   the one call the gateway makes upstream: the same query, also grouped by pupil
    release(rows, ...)         pupils per group, small groups dropped, small counts and complements hidden,
                               everything rounded to 5

The tool itself counts census rows and suppresses nothing; each pupil has up to 5 rows (one per term), so a row
threshold can be passed by one child. The gateway therefore counts distinct pupils from a per-pupil breakdown that
never leaves the gateway, and releases only rounded pupil counts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .audit import DEFAULT_MANIFEST, column_level

SERVER, TOOL = "pupil-data", "aggregate"
PUPIL_COLUMN = "Psuedo ID"
IDENTIFIER_COLUMNS = frozenset({PUPIL_COLUMN, "DisplayName"})
MAX_GROUP_COLUMNS = 2
MAX_WHERE_LEVEL = 2
DEFAULT_K = 10
SMALL_CELL = 4  # counts (and complements) from 1 to this are hidden
ROUND_TO = 5


def applies(server: str, tool: str) -> bool:
    return (server, tool) == (SERVER, TOOL)


def _columns(value: Any) -> list[str] | None:
    if isinstance(value, list) and all(isinstance(c, str) for c in value):
        return value
    return None


def check(arguments: dict, claims: dict | None) -> tuple[str, str] | None:
    """(reason_code, detail) refusing the call, or None. `claims` are the verified mandate's claims."""
    group_by = _columns(arguments.get("group_by"))
    measure = arguments.get("measure")
    where = arguments.get("where") or {}
    if group_by is None or not isinstance(measure, str) or not isinstance(where, dict):
        return "COUNT_COLUMN_REFUSED", "group_by must be a list of column names, measure a column name"
    named = [*group_by, measure, *map(str, where)]
    for column in named:
        if column in IDENTIFIER_COLUMNS:
            return "COUNT_COLUMN_REFUSED", column
    clearance = (claims or {}).get("clearance")
    cleared_4 = type(clearance) is int and clearance == 4  # noqa: PLR2004  (bool is an int: True is not 4)
    for column in named:
        if column_level(column) >= 4 and not cleared_4:  # noqa: PLR2004
            return "COUNT_COLUMN_REFUSED", column
    if type(clearance) is int and 1 <= clearance < 4:  # noqa: PLR2004  (graded pupil-data: counts stay within it)
        for column in named:
            if column_level(column) > clearance:
                return "COUNT_COLUMN_REFUSED", f"{column} is above clearance {clearance}"
    if len(group_by) > MAX_GROUP_COLUMNS:
        return "COUNT_TOO_FINE", f"at most {MAX_GROUP_COLUMNS} group_by columns"
    for column in where:
        if column_level(str(column)) > MAX_WHERE_LEVEL:
            return "COUNT_TOO_FINE", f"where on {column}"
    return None


def k_for(claims: dict | None) -> int:
    """The minimum group size: the default, or a higher `counts.k` from the mandate. Never lower."""
    counts = (claims or {}).get("counts")
    k = counts.get("k") if isinstance(counts, dict) else None
    return max(DEFAULT_K, k) if type(k) is int else DEFAULT_K


def has_pupils(table: str) -> bool:
    """Whether the table has a pupil column, from the manifest. An unreadable manifest assumes it does."""
    path = Path(os.environ.get("GATEWAY_MANIFEST_PATH", DEFAULT_MANIFEST))
    try:
        columns = json.loads(path.read_text())["classification"]["columns"].get(table, {})
    except (OSError, KeyError, ValueError):
        return True
    return PUPIL_COLUMN in columns


def breakdown_arguments(arguments: dict) -> dict:
    """The upstream call: the agent's query, also grouped by pupil, so pupils per group can be counted."""
    return {**arguments, "group_by": [*arguments["group_by"], PUPIL_COLUMN]}


def round5(n: int) -> int:
    """Nearest multiple of 5 (integers have no ties), zero stays zero."""
    return ((n + 2) // ROUND_TO) * ROUND_TO


def _hidden(m: int, n: int) -> bool:
    return 1 <= m <= SMALL_CELL or 1 <= n - m <= SMALL_CELL


def release(rows: list[dict], group_by: list[str], k: int, *, per_pupil: bool) -> list[dict]:
    """Fold the upstream rows into released ones.

    per_pupil: rows are the breakdown (one per group and pupil). Otherwise (a table without pupils) rows are the
    tool's own groups, released as rounded row counts.
    """
    if not per_pupil:
        return [{**{c: r[c] for c in group_by}, "total": round5(r["total"]), "count": round5(r["count"])}
                for r in rows]  # fmt: skip
    groups: dict[tuple, dict[str, int]] = {}
    for r in rows:
        key = tuple(r[c] for c in group_by)
        g = groups.setdefault(key, {"n": 0, "m": 0})
        g["n"] += 1  # one breakdown row per pupil in the group
        g["m"] += r["count"] > 0  # the pupil has the flag in at least one matching row
    released, suppressed = [], 0
    for key in sorted(groups):
        n, m = groups[key]["n"], groups[key]["m"]
        if n < k:
            suppressed += 1
            continue
        row = dict(zip(group_by, key, strict=True))
        row["total"] = round5(n)
        row["count"] = None if _hidden(m, n) else round5(m)
        released.append(row)
    if suppressed:
        released.append({"suppressed_groups": suppressed})
    return released


def max_level(arguments: dict) -> int:
    """The highest level among the grouped and measured columns: what a released count is about."""
    columns = [*arguments.get("group_by", []), arguments.get("measure", "")]
    return max((column_level(c) for c in columns if c), default=1)

