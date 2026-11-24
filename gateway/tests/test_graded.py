"""Graded pupil-data (OpenSpec add-graded-pupil-data): basic data by default, level 4 asked for each time."""

import pytest

from gateway.lib import graded
from gateway.lib.interfaces import check_clearance

SCH02 = [{"server": "pupil-data", "tools": ["pupil", "search", "get", "roster", "aggregate"],
          "constraints": {"urn": ["SCH02"]}}]  # fmt: skip
LEVEL_3 = {"FSMeligible", "Language"}
LEVEL_4 = {"Ethnicity", "InCareAtCurrentSchool"}


def _pupil(stack, **claims):
    client, mandate, call, _ = stack
    return call(client, mandate(SCH02, **claims), "pupil-data", "pupil", pupil_id="P0050", urn="SCH02")


def test_clearance_2_gets_basic_data_only(stack):
    status, resp = _pupil(stack, clearance=2)
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")
    record = resp["result"]
    assert record["Psuedo ID"] == "P0050"
    assert record["DisplayName"] == "Owen Patel"
    assert not set(record) & (LEVEL_3 | LEVEL_4)


def test_clearance_3_adds_level_3(stack):
    status, resp = _pupil(stack, clearance=3)
    assert status == 200
    assert set(resp["result"]) >= LEVEL_3
    assert not set(resp["result"]) & LEVEL_4


def test_search_rows_are_stripped_too(stack):
    client, mandate, call, _ = stack
    status, resp = call(client, mandate(SCH02, clearance=1), "pupil-data", "search", query="SPR", urn="SCH02")
    assert status == 200
    assert resp["result"]
    assert not any(set(row) & (LEVEL_3 | LEVEL_4) for row in resp["result"])
    # the pupil ID is level 2: at clearance 1 a search can't confirm it through the rows it picks
    status, resp = call(client, mandate(SCH02, clearance=1), "pupil-data", "search", query="P0050", urn="SCH02")
    assert (status, resp["result"]) == (200, [])


def test_claimless_person_tool_is_refused(stack):
    status, resp = _pupil(stack)
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_MISSING")
    assert "result" not in resp


def test_claimless_search_gets_basic_data_only(stack):
    client, mandate, call, _ = stack
    status, resp = call(client, mandate(SCH02), "pupil-data", "search", query="P0050", urn="SCH02")
    assert status == 200
    assert resp["result"]
    assert not any(set(row) & (LEVEL_3 | LEVEL_4) for row in resp["result"])


def test_claimless_get_of_census_is_stripped(stack):
    client, mandate, call, _ = stack
    files = [{"server": "pupil-data", "tools": ["get"]}]
    status, resp = call(client, mandate(files), "pupil-data", "get", path=graded.CENSUS_FILE, limit=5)
    assert status == 200
    assert resp["result"]
    assert not any(set(row) & (LEVEL_3 | LEVEL_4) for row in resp["result"])


def test_claimless_counts_still_work(stack):
    client, mandate, call, _ = stack
    scope = [{"server": "pupil-data", "tools": ["aggregate"]}]
    args = {"table": "personal_data_school_census", "group_by": ["URN"], "measure": "FSMeligible"}
    status, resp = call(client, mandate(scope), "pupil-data", "aggregate", **args)
    assert status == 200
    assert any(row.get("count") for row in resp["result"])  # counts are aggregates: not stripped


@pytest.mark.parametrize(("raw", "level"), [("", 2), ("3", 3), ("4", 4), ("9", 2), ("x", 2), ("0", 2)])
def test_claimless_level_setting(monkeypatch, raw, level):
    monkeypatch.setenv("GATEWAY_CLAIMLESS_LEVEL", raw)
    assert graded.claimless_level() == level
    assert graded.level_for("pupil-data", {}) == (None if level == 4 else level)


@pytest.mark.parametrize("tool", ["pupil", "search"])
def test_level_4_read_is_held(stack, tool):
    client, mandate, call, _ = stack
    args = {"pupil_id": "P0050"} if tool == "pupil" else {"query": "P0050"}
    status, resp = call(client, mandate(SCH02, clearance=4), "pupil-data", tool, urn="SCH02", **args)
    assert (status, resp["decision"]["reason_code"]) == (202, "SPECIAL_CATEGORY")
    assert "result" not in resp


def test_census_get_is_held_at_clearance_4(stack):
    client, mandate, call, _ = stack
    path = {"path": graded.CENSUS_FILE}
    files = [{"server": "pupil-data", "tools": ["get"]}]
    status, resp = call(client, mandate(files, clearance=4), "pupil-data", "get", **path)
    assert (status, resp["decision"]["reason_code"]) == (202, "SPECIAL_CATEGORY")
    assert graded.special_category_read("pupil-data", "get", {"path": "./" + graded.CENSUS_FILE}, {"clearance": 4})
    for spelling in (
        "Synthetic/Synthetic_Personal_Data_School_Census.csv",
        "/x/../synthetic_personal_data_school_census.CSV",
    ):
        assert graded.special_category_read("pupil-data", "get", {"path": spelling}, {"clearance": 4})
    assert not graded.special_category_read("pupil-data", "get", {"path": "synthetic/synthetic_schools.csv"},
                                            {"clearance": 4})  # fmt: skip


def test_counts_stay_within_the_clearance(stack):
    client, mandate, call, _ = stack
    token = mandate(SCH02, clearance=2)
    args = {"table": "synthetic_personal_data_school_census", "group_by": ["Gender"], "urn": "SCH02"}
    status, resp = call(client, token, "pupil-data", "aggregate", measure="FSMeligible", **args)
    assert (status, resp["decision"]["reason_code"]) == (403, "COUNT_COLUMN_REFUSED")
    assert resp["decision"]["detail"] == "FSMeligible is above clearance 2"


def test_check_clearance_rules():
    assert check_clearance("pupil-data", {"clearance": 1}, "pupil") is None
    assert check_clearance("pupil-data", {}, "roster")[1] == "CLEARANCE_MISSING"
    assert check_clearance("pupil-data", {}, "search") is None
    assert check_clearance("directory", {"clearance": 1})[1] == "CLEARANCE_TOO_LOW"  # other servers unchanged


def test_strip_leaves_documents_alone():
    manifest = {"classification": {"columns": {"t": {"Ethnicity": 4}}}}
    assert graded.strip(manifest, 2) == manifest
    assert graded.strip([{"Psuedo ID": "P1", "Ethnicity": "WHIT"}], 2) == [{"Psuedo ID": "P1"}]


@pytest.mark.parametrize("query", ["ASIA", "2_OTH", "WHIT"])  # ethnicity, language, ethnicity
@pytest.mark.parametrize("clearance", [None, 2])
def test_search_cant_select_pupils_by_a_stripped_value(stack, query, clearance):
    """Searching for a hidden value used to return exactly the pupils who have it (11 of 11 for ASIA)."""
    client, mandate, call, _ = stack
    m = mandate(SCH02) if clearance is None else mandate(SCH02, clearance=clearance)
    status, resp = call(client, m, "pupil-data", "search", query=query, urn="SCH02", limit=100)
    assert status == 200
    assert resp["result"] == []  # the only match was in a column this mandate may not see


def test_search_on_visible_columns_still_works(stack):
    client, mandate, call, _ = stack
    status, resp = call(client, mandate(SCH02, clearance=3), "pupil-data", "search", query="2_OTH", urn="SCH02",
                        limit=5)  # fmt: skip
    assert status == 200
    assert resp["result"]  # Language is level 3, visible at clearance 3
    assert all(row["Language"] == "2_OTH" for row in resp["result"])
