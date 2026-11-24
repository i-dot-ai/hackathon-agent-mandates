"""schools: level 1. The schools list and the classification table, nothing personal."""

from fastmcp import FastMCP

from data_slices import reader
from tool_grants import granted, level_function

LEVEL = 1
KEYS = ("URN", "SchoolName", "SchoolLA")

mcp = FastMCP("schools")
# every tool checks its arguments against, and filters its output by, the call's tool grant
GRANTED = granted(level_function(reader.DATA_ROOT / "synthetic_manifest.json"))


@mcp.tool
@GRANTED
def list() -> list[dict]:  # noqa: A001  (the tool name agents see is "list")
    """Every school: URN, name and local authority."""
    return [reader.project(r, KEYS) for r in reader.rows("schools", LEVEL)]


@mcp.tool
@GRANTED
def classification() -> dict:
    """The data level of every table and column: 1 public, 2 basic PII, 3 sensitive PII, 4 special category."""
    return reader.classification()
