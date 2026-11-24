import asyncio

import pytest
from fastapi.testclient import TestClient
from fastmcp import Client

from data_slices import directory, reader, schools, special
from data_slices.main import app

ABOVE_LEVEL_2 = {"Ethnicity", "InCareAtCurrentSchool", "FSMeligible", "Language"}
DEPRIVATION = {"HomeArea", "SchoolArea", "DeprivationScore", "DeprivationDecile"}


def call(server, tool, **args):
    async def run():
        async with Client(server) as client:
            return (await client.call_tool(tool, args)).data

    return asyncio.run(run())


def tools(server):
    async def run():
        async with Client(server) as client:
            return sorted(t.name for t in await client.list_tools())

    return asyncio.run(run())


# ---------------------------------------------------------------- reader


def test_reader_drops_columns_above_level():
    census = reader.rows("personal_data_school_census", 2)
    assert census
    assert not ABOVE_LEVEL_2 & set(census[0])
    assert {"Psuedo ID", "URN", "AcademicYear", "CensusTerm", "AgeAtStartOfAcademicYear"} <= set(census[0])


def test_reader_keep_allows_named_columns_only():
    row = reader.rows("personal_data_school_census", 1, keep=("Ethnicity",))[0]
    assert "Ethnicity" in row
    assert "InCareAtCurrentSchool" not in row
    assert "Psuedo ID" not in row  # level 2, not kept


def test_reader_unlisted_column_counts_as_level_4():
    assert reader.column_level("personal_data_school_census", "NotInManifest") == 4


def test_reader_refuses_unknown_table():
    with pytest.raises(ValueError, match="unknown table"):
        reader.rows("../../etc/passwd", 4)


# ---------------------------------------------------------------- schools


def test_schools_tools():
    assert tools(schools.mcp) == ["classification", "list"]


def test_schools_list_is_public_only():
    result = call(schools.mcp, "list")
    assert len(result) == 12
    assert all(set(r) == {"URN", "SchoolName", "SchoolLA"} for r in result)


def test_schools_classification():
    result = call(schools.mcp, "classification")
    assert set(result) == {"levels", "tables", "columns"}


# ---------------------------------------------------------------- directory


def test_directory_tools():
    assert tools(directory.mcp) == ["name", "roster"]


def test_directory_roster_is_ids_and_names_only():
    result = call(directory.mcp, "roster", urn="SCH04", year_group=11, academic_year="2023/24", term="SPR")
    assert len(result) == 41
    assert all(set(r) == {"Psuedo ID", "DisplayName"} for r in result)


def test_directory_name_at_school_and_elsewhere():
    assert call(directory.mcp, "name", pupil_id="P0011", urn="SCH04") == {
        "Psuedo ID": "P0011",
        "DisplayName": "Zara Okafor",
    }
    assert call(directory.mcp, "name", pupil_id="P0586", urn="SCH04") == {}


def test_directory_never_returns_sensitive_columns():
    rows = call(directory.mcp, "roster", urn="SCH07", year_group=10, academic_year="2022/23", term="AUT")
    assert rows
    assert all(not (ABOVE_LEVEL_2 | DEPRIVATION) & set(r) for r in rows)


# ---------------------------------------------------------------- special


def test_special_tools():
    assert tools(special.mcp) == ["record"]


def test_special_record_has_no_name():
    result = call(special.mcp, "record", pupil_id="P0011", urn="SCH04")
    assert set(result) == set(special.KEYS)
    assert (result["Ethnicity"], result["URN"]) == ("ASIA", "SCH04")
    assert "DisplayName" not in result


def test_special_record_elsewhere_is_empty():
    assert call(special.mcp, "record", pupil_id="P0586", urn="SCH04") == {}


# ---------------------------------------------------------------- the mounted app


def test_app_mounts_three_interfaces():
    with TestClient(app) as client:
        assert client.get("/healthcheck").json() == {"status": "ok"}
    assert {r.path for r in app.routes} >= {"/schools/mcp", "/directory/mcp", "/special/mcp"}
