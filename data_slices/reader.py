"""The only way an interface server reads data: by table, capped at a data level from the manifest.

Every column has a level in the manifest's classification (1 public to 4 special category). `rows` drops each
column above `max_level` unless it is named in `keep`, so a server limits itself even when called without the
gateway. A column the manifest does not list counts as level 4.
"""

import csv
import json
import os
from functools import lru_cache
from pathlib import Path

DATA_ROOT = Path(os.environ.get("SLICES_DATA_ROOT", Path(__file__).resolve().parents[1] / "mcp_server/data/synthetic"))
TERM_ORDER = {"AUT": 0, "SPR": 1, "SUM": 2}
UNLISTED_LEVEL = 4


@lru_cache
def classification() -> dict:
    """The manifest's classification: level names, table levels and column levels."""
    return json.loads((DATA_ROOT / "synthetic_manifest.json").read_text())["classification"]


def column_level(table: str, column: str) -> int:
    return classification()["columns"].get(table, {}).get(column, UNLISTED_LEVEL)


def rows(table: str, max_level: int, keep: tuple[str, ...] = ()) -> list[dict]:
    """Rows of `table`, without any column above `max_level` that is not named in `keep`."""
    if table not in classification()["tables"]:
        msg = f"unknown table {table!r}"
        raise ValueError(msg)
    with (DATA_ROOT / f"synthetic_{table}.csv").open(newline="") as f:
        reader = csv.DictReader(f)
        allowed = [c for c in reader.fieldnames or [] if c in keep or column_level(table, c) <= max_level]
        return [{c: row[c] for c in allowed} for row in reader]


def latest_at(census_rows: list[dict], pupil_id: str, urn: str) -> dict | None:
    """The pupil's most recent census row, or None if they are not currently at `urn`."""
    mine = [r for r in census_rows if r["Psuedo ID"] == pupil_id]
    if not mine:
        return None
    latest = max(mine, key=lambda r: (r["AcademicYear"], TERM_ORDER[r["CensusTerm"]]))
    return latest if latest["URN"] == urn else None


def project(row: dict, keys: tuple[str, ...]) -> dict:
    """Exactly `keys` from `row`, so a column added to the data later can't leak through by default."""
    return {k: row[k] for k in keys}
