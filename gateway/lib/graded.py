"""Graded pupil-data (OpenSpec add-graded-pupil-data): a mandate's clearance decides which columns it receives.

    special_category_read(server, tool, arguments, claims)   a clearance-4 pupil-data call that returns level-4
                                                             columns: held for a person's approval
    strip(data, level)                                       a result without columns above `level`

The MCP server strips the same columns through the tool grant's level; the gateway strips again before release,
so a result never leaves with more than the mandate's clearance even if the server didn't.
"""

from __future__ import annotations

import os
import posixpath
from typing import Any

from .audit import _is_row, column_level

GRADED_SERVER = "pupil-data"
CENSUS_FILE = "synthetic/synthetic_personal_data_school_census.csv"
# pupil-data tools whose results include level-4 census columns
SPECIAL_CATEGORY_TOOLS = frozenset({"search", "pupil"})
# what a mandate without a clearance claim receives from pupil-data: basic PII (names, gender, age, deprivation)
DEFAULT_CLAIMLESS_LEVEL = 2


def claimless_level() -> int:
    """GATEWAY_CLAIMLESS_LEVEL (1-4), else the default. A bad value falls back to the default, never to 4."""
    raw = os.environ.get("GATEWAY_CLAIMLESS_LEVEL", "")
    return int(raw) if raw.isdigit() and 1 <= int(raw) <= 4 else DEFAULT_CLAIMLESS_LEVEL  # noqa: PLR2004


def _clearance(claims: dict | None) -> int | None:
    clearance = (claims or {}).get("clearance")
    return clearance if type(clearance) is int and 1 <= clearance <= 4 else None  # noqa: PLR2004


def special_category_read(server: str, tool: str, arguments: dict, claims: dict | None) -> bool:
    if server != GRADED_SERVER or _clearance(claims) != 4:  # noqa: PLR2004
        return False
    if tool in SPECIAL_CATEGORY_TOOLS:
        return True
    path = arguments.get("path")
    # any spelling that could open the file: case-insensitive (macOS), any directory prefix
    return tool == "get" and isinstance(path, str) and (
        posixpath.basename(posixpath.normpath(path.replace("\\", "/"))).lower() == posixpath.basename(CENSUS_FILE)
    )


def level_for(server: str, claims: dict | None) -> int | None:
    """The level a graded server's result is stripped to, or None (nothing to strip).

    The clearance; without a clearance claim, the claim-less level (add-graded-pupil-data: claim-less mandates
    keep working, with basic data only).
    """
    if server != GRADED_SERVER:
        return None
    if "clearance" not in (claims or {}):
        level = claimless_level()
    else:
        level = _clearance(claims)
    return level if level is not None and level < 4 else None  # noqa: PLR2004


def _strip_row(row: dict, level: int) -> dict:
    return {k: v for k, v in row.items() if column_level(k) <= level}


def strip(data: Any, level: int, query: str | None = None) -> Any:
    """Rows (flat dicts) lose every column above `level`; documents (nested JSON) are left as they are.

    With a search `query`, a row is kept only if the query matches a column left after stripping. The server
    matches the whole row, so otherwise the choice of rows would reveal what was stripped: a search for "ASIA"
    with no clearance returned exactly the pupils of that ethnicity.
    """
    if isinstance(data, list):
        rows = [_strip_row(r, level) if _is_row(r) else r for r in data]
        if isinstance(query, str):
            rows = [r for r in rows if not _is_row(r) or _matches_visible(r, query)]
        return rows
    if _is_row(data):
        return _strip_row(data, level)
    return data


def _matches_visible(row: dict, query: str) -> bool:
    return query.lower() in ",".join(str(v) for v in row.values()).lower()
