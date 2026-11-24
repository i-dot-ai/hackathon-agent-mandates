"""directory: level 2. Pseudo IDs and display names, for one cohort or one pupil.

Cohort membership comes from census columns at level 2 or below (URN, year, term, age, pupil ID); the reader
drops every census column above level 2 before this module sees a row.
"""

from fastmcp import FastMCP

from data_slices import reader
from tool_grants import granted, level_function

LEVEL = 2
KEYS = ("Psuedo ID", "DisplayName")
YEAR_GROUP_AGE = {10: "14", 11: "15"}  # AgeAtStartOfAcademicYear for each year group

mcp = FastMCP("directory")
# every tool checks its arguments against, and filters its output by, the call's tool grant
GRANTED = granted(level_function(reader.DATA_ROOT / "synthetic_manifest.json"))


def _names() -> dict[str, str]:
    return {r["Psuedo ID"]: r["DisplayName"] for r in reader.rows("display_names", LEVEL)}


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
    names = _names()
    cohort = (urn, academic_year, term, YEAR_GROUP_AGE[year_group])
    return [
        reader.project({"Psuedo ID": r["Psuedo ID"], "DisplayName": names[r["Psuedo ID"]]}, KEYS)
        for r in reader.rows("personal_data_school_census", LEVEL)
        if (r["URN"], r["AcademicYear"], r["CensusTerm"], r["AgeAtStartOfAcademicYear"]) == cohort
    ]


@mcp.tool
@GRANTED
def name(pupil_id: str, urn: str) -> dict:
    """One pupil's pseudo ID and display name. Empty if the pupil is not currently at `urn`."""
    if reader.latest_at(reader.rows("personal_data_school_census", LEVEL), pupil_id, urn) is None:
        return {}
    return reader.project({"Psuedo ID": pupil_id, "DisplayName": _names()[pupil_id]}, KEYS)
