import csv
import itertools
import json
import time
from collections import Counter
from pathlib import Path

from fastmcp import FastMCP

from tool_grants import granted, level_function

DATA_ROOT = Path(__file__).resolve().parents[1] / "data"
SYNTH_ROOT = DATA_ROOT / "synthetic"
WRITES_PATH = DATA_ROOT / "writes" / "corrections.jsonl"
TERM_ORDER = {"AUT": 0, "SPR": 1, "SUM": 2}
YEAR_GROUP_AGE = {10: "14", 11: "15"}  # AgeAtStartOfAcademicYear for each year group

mcp = FastMCP("MCP Access", version="0.1.0")
# every tool checks its arguments against, and filters its output by, the call's tool grant
GRANTED = granted(level_function(SYNTH_ROOT / "synthetic_manifest.json"))


@mcp.tool
@GRANTED
def search(query: str, urn: str | None = None, limit: int = 100) -> list[dict]:
    """
    Case-insensitive text search across the rows of the synthetic school census.

    Args:
        query: substring to look for anywhere in a row, e.g. a pupil's "Psuedo ID" or "2023/24".
        urn: optional school URN (e.g. "SCH01") to restrict the search to that school's pupils.
        limit: maximum number of rows to return.

    Returns:
        The matching census rows, at most `limit`.
    """
    with (SYNTH_ROOT / "synthetic_personal_data_school_census.csv").open(newline="") as f:
        hits = (
            row
            for row in csv.DictReader(f)
            if urn in (None, row["URN"]) and query.lower() in ",".join(row.values()).lower()
        )
        return list(itertools.islice(hits, limit))


@mcp.tool
@GRANTED
def get(path: str, limit: int = 100) -> dict | list:
    """
    Return the contents of one data file, by path relative to the data directory.

    A JSON file (e.g. "synthetic/synthetic_manifest.json") is returned parsed. A CSV file
    (e.g. "synthetic/synthetic_schools.csv") is returned as a list of row dicts, at most `limit` rows.
    """
    target = (DATA_ROOT / path).resolve()
    if not target.is_relative_to(DATA_ROOT):
        msg = f"{path} is outside the data directory"
        raise ValueError(msg)
    if target.suffix == ".csv":
        with target.open(newline="") as f:
            return list(itertools.islice(csv.DictReader(f), limit))
    return json.loads(target.read_text())


@mcp.tool
@GRANTED
def aggregate(table: str, group_by: list[str], measure: str, where: dict[str, str] | None = None) -> list[dict]:
    """
    Group a synthetic CSV table and count rows: one result row per group with "total" (rows in the group) and
    "count" (rows where `measure` is "1"). No small-cell suppression is applied; that is the gateway's decision.

    Args:
        table: file stem under mcp_server/data/synthetic, e.g. "personal_data_school_census".
        group_by: columns to group on, e.g. ["URN"] or ["URN", "Ethnicity"].
        measure: a 0/1 flag column to count, e.g. "FSMeligible" or "InCareAtCurrentSchool".
        where: optional exact-match filters, e.g. {"CensusTerm": "SPR", "AcademicYear": "2023/24"}.
    """
    path = SYNTH_ROOT / f"synthetic_{table}.csv"
    if not table.isidentifier() or not path.is_file():
        msg = f"unknown table {table!r}"
        raise ValueError(msg)
    where = where or {}
    total: Counter[tuple[str, ...]] = Counter()
    count: Counter[tuple[str, ...]] = Counter()
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        missing = {*group_by, measure, *where} - set(reader.fieldnames or [])
        if missing:
            msg = f"unknown columns {sorted(missing)} in {table}"
            raise ValueError(msg)
        for row in reader:
            if any(row[k] != v for k, v in where.items()):
                continue
            key = tuple(row[c] for c in group_by)
            total[key] += 1
            count[key] += row[measure] == "1"
    return [dict(zip(group_by, key, strict=True), total=total[key], count=count[key]) for key in sorted(total)]


@mcp.tool
@GRANTED
def classification() -> dict:
    """
    The PII level of every table and column, from the manifest: "levels" names each level (1 public to
    4 special category), "tables" gives each table's level and "columns" each column's, keyed by table.
    """
    return json.loads((SYNTH_ROOT / "synthetic_manifest.json").read_text())["classification"]


def _rows(name: str) -> list[dict]:
    with (SYNTH_ROOT / f"synthetic_{name}.csv").open(newline="") as f:
        return list(csv.DictReader(f))


def _by_id(name: str) -> dict[str, dict]:
    return {r["Psuedo ID"]: r for r in _rows(name)}


def _latest(pupil_id: str, urn: str) -> dict | None:
    """The pupil's most recent census row, or None if they are not currently at `urn`."""
    rows = [r for r in _rows("personal_data_school_census") if r["Psuedo ID"] == pupil_id]
    if not rows:
        return None
    latest = max(rows, key=lambda r: (r["AcademicYear"], TERM_ORDER[r["CensusTerm"]]))
    return latest if latest["URN"] == urn else None


@mcp.tool
@GRANTED
def roster(urn: str, year_group: int, academic_year: str = "2023/24", term: str = "SPR") -> list[dict]:
    """
    The pupils in one year group at one school, by pseudo ID and display name.

    Args:
        urn: school URN, e.g. "SCH04".
        year_group: 10 or 11.
        academic_year: census year, e.g. "2023/24".
        term: census term, "AUT", "SPR" or "SUM".
    """
    if year_group not in YEAR_GROUP_AGE:
        msg = f"year_group must be one of {sorted(YEAR_GROUP_AGE)}"
        raise ValueError(msg)
    names = _by_id("display_names")
    return [
        {"Psuedo ID": r["Psuedo ID"], "DisplayName": names[r["Psuedo ID"]]["DisplayName"]}
        for r in _rows("personal_data_school_census")
        if (r["URN"], r["AcademicYear"], r["CensusTerm"], r["AgeAtStartOfAcademicYear"])
        == (urn, academic_year, term, YEAR_GROUP_AGE[year_group])
    ]


@mcp.tool
@GRANTED
def pupil(pupil_id: str, urn: str) -> dict:
    """
    One pupil's full record: their latest census row (ethnicity and care status included), display name and
    deprivation. Empty if the pupil is not currently at `urn`. Every column is returned; filtering by PII level
    is the gateway's decision.
    """
    row = _latest(pupil_id, urn)
    if row is None:
        return {}
    name = _by_id("display_names")[pupil_id]
    deprivation = _by_id("personal_data_deprivation").get(pupil_id, {})
    return {**row, "DisplayName": name["DisplayName"], **deprivation}


@mcp.tool
@GRANTED
def draft(urn: str, pupil_ids: list[str], kind: str = "absence") -> list[dict]:
    """
    Draft a letter home for each pupil currently at `urn`; pupils at other schools are skipped.

    Put every pupil in one call: a draft is held for a person's approval, and one call with all the pupils is one
    approval, where one call per pupil is one approval each.

    Args:
        urn: school URN the letters are from.
        pupil_ids: pseudo IDs to write to.
        kind: "absence" or "attendance_meeting".
    """
    templates = {
        "absence": "Dear parent or carer of {name},\n\nOur records show {name} has missed school recently. "
        "Please contact {school} to discuss.",
        "attendance_meeting": "Dear parent or carer of {name},\n\nWe would like to invite you to a meeting at "
        "{school} about {name}'s attendance.",
    }
    if kind not in templates:
        msg = f"kind must be one of {sorted(templates)}"
        raise ValueError(msg)
    school = next((r["SchoolName"] for r in _rows("schools") if r["URN"] == urn), urn)
    names = _by_id("display_names")
    return [
        {"Psuedo ID": p, "letter": templates[kind].format(name=names[p]["DisplayName"], school=school)}
        for p in pupil_ids
        if _latest(p, urn)
    ]


@mcp.tool
@GRANTED
def write(pupil_id: str, urn: str, column: str, value: str, reason: str) -> dict:
    """
    Correct one field of a pupil's latest census row. The synthetic data is not changed: the correction is
    appended to data/writes/corrections.jsonl and returned as {before, after}.

    Args:
        pupil_id: pseudo ID of a pupil currently at `urn`.
        urn: school URN.
        column: census column to correct; "Psuedo ID" and "URN" cannot be changed.
        value: the new value.
        reason: why the record is being corrected.
    """
    row = _latest(pupil_id, urn)
    if row is None:
        msg = f"{pupil_id} is not a current pupil at {urn}"
        raise ValueError(msg)
    if column not in row or column in {"Psuedo ID", "URN"}:
        msg = f"column {column!r} cannot be corrected"
        raise ValueError(msg)
    entry = {
        "ts": time.time(),
        "pupil_id": pupil_id,
        "urn": urn,
        "column": column,
        "before": row[column],
        "after": value,
        "reason": reason,
    }
    WRITES_PATH.parent.mkdir(exist_ok=True)
    with WRITES_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry
