"""special: level 4. Ethnicity and care status for one pupil per call, never with a name.

The gateway holds every call to this server for approval (STEP_UP). This module never opens the names or
deprivation files, so it can't return a name even if asked.
"""

from fastmcp import FastMCP

from data_slices import reader
from tool_grants import granted, level_function

LEVEL = 4
KEYS = ("Psuedo ID", "URN", "AcademicYear", "CensusTerm", "Ethnicity", "InCareAtCurrentSchool")

mcp = FastMCP("special")
# every tool checks its arguments against, and filters its output by, the call's tool grant
GRANTED = granted(level_function(reader.DATA_ROOT / "synthetic_manifest.json"))


@mcp.tool
@GRANTED
def record(pupil_id: str, urn: str) -> dict:
    """One pupil's latest ethnicity and care status. Empty if the pupil is not currently at `urn`."""
    row = reader.latest_at(reader.rows("personal_data_school_census", LEVEL, keep=KEYS), pupil_id, urn)
    return {} if row is None else reader.project(row, KEYS)
