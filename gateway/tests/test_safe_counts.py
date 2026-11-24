"""Safe counts (OpenSpec add-safe-counts): counts can't name a child, through grouping, filtering or small groups."""

import asyncio
import json

import pytest

from gateway import cli
from gateway.lib import audit, safe_counts
from gateway.lib.common import priv_from_pem
from gateway.tests.test_gateway import gw  # noqa: F401  (fixture)

CENSUS = "personal_data_school_census"
LEAK_FILTER = {"table": CENSUS, "group_by": ["Ethnicity", "URN"], "measure": "FSMeligible",
               "where": {"Psuedo ID": "P0011"}}  # fmt: skip
LEAK_GROUP = {"table": CENSUS, "group_by": ["Psuedo ID", "Ethnicity", "URN"], "measure": "FSMeligible"}


def counts_caller(state, *, claims=None, constraints=None, name="counts.jwt"):
    scope = [{"server": "pupil-data", "tools": ["aggregate"], "constraints": constraints or {"table": [CENSUS]}}]
    args = ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / name),
            "--scope", json.dumps(scope)]  # fmt: skip
    if claims:
        args += ["--claims", json.dumps(claims)]
    cli.main(args)
    mandate = (state / name).read_text()
    priv = priv_from_pem((state / "agent.pem").read_bytes())

    def call(client, **arguments):
        body = cli.sign_request(priv, server="pupil-data", tool="aggregate", arguments=arguments, mandate=mandate)
        return client.post("/tools/call", json=body)

    return call


def events():
    return asyncio.run(audit.get_store().all_events())


# ---------------------------------------------------------------- column rules (unit)


@pytest.mark.parametrize(
    ("arguments", "claims", "expected"),
    [
        (LEAK_FILTER, {"clearance": 4}, ("COUNT_COLUMN_REFUSED", "Psuedo ID")),
        (LEAK_GROUP, {"clearance": 4}, ("COUNT_COLUMN_REFUSED", "Psuedo ID")),
        ({"group_by": ["URN", "Ethnicity"], "measure": "FSMeligible"}, {}, ("COUNT_COLUMN_REFUSED", "Ethnicity")),
        (
            {"group_by": ["URN"], "measure": "InCareAtCurrentSchool"},
            {"clearance": True},
            ("COUNT_COLUMN_REFUSED", "InCareAtCurrentSchool"),
        ),
        ({"group_by": ["URN", "Ethnicity"], "measure": "FSMeligible"}, {"clearance": 4}, None),
        (
            {"group_by": ["URN", "Gender", "Ethnicity"], "measure": "FSMeligible"},
            {"clearance": 4},
            ("COUNT_TOO_FINE", "at most 2 group_by columns"),
        ),
        (
            {"group_by": ["URN"], "measure": "FSMeligible", "where": {"Language": "1_ENG"}},
            {},
            ("COUNT_TOO_FINE", "where on Language"),
        ),
        ({"group_by": ["URN"], "measure": "FSMeligible", "where": {"CensusTerm": "SPR"}}, {}, None),
        (
            {"group_by": "URN", "measure": "FSMeligible"},
            {},
            ("COUNT_COLUMN_REFUSED", "group_by must be a list of column names, measure a column name"),
        ),
    ],
)
def test_column_rules(arguments, claims, expected):
    assert safe_counts.check(arguments, claims) == expected


def test_k_can_be_raised_not_lowered():
    assert safe_counts.k_for({"counts": {"k": 3}}) == 10
    assert safe_counts.k_for({"counts": {"k": 20}}) == 20
    assert safe_counts.k_for({"counts": {"k": True}}) == 10
    assert safe_counts.k_for(None) == 10


def test_rounding():
    assert [safe_counts.round5(n) for n in (0, 1, 2, 3, 7, 8, 112, 113)] == [0, 0, 0, 5, 5, 10, 110, 115]


def test_release_suppresses_small_groups_and_cells():
    rows = [{"URN": "A", "Psuedo ID": f"P{i:04d}", "total": 3, "count": int(i == 0)} for i in range(12)]  # 1 flagged
    rows += [{"URN": "B", "Psuedo ID": f"P{i:04d}", "total": 1, "count": 0} for i in range(100, 105)]  # 5 pupils
    rows += [{"URN": "C", "Psuedo ID": f"P{i:04d}", "total": 2, "count": int(i < 210)} for i in range(200, 211)]
    out = safe_counts.release(rows, ["URN"], 10, per_pupil=True)
    assert out == [
        {"URN": "A", "total": 10, "count": None},  # 12 pupils, 1 flagged: the count is hidden
        {"URN": "C", "total": 10, "count": None},  # 11 pupils, 10 flagged: the 1 without is hidden
        {"suppressed_groups": 1},  # B (5 pupils) dropped, with no key
    ]
    assert safe_counts.release(rows, ["URN"], 20, per_pupil=True) == [{"suppressed_groups": 3}]


# ---------------------------------------------------------------- through the gateway


def test_eval_counts_case_is_released_in_pupils(gw):  # noqa: F811
    client, _, state = gw
    call = counts_caller(state, constraints={"table": [CENSUS], "measure": ["FSMeligible"]})
    r = call(client, table=CENSUS, group_by=["URN"], measure="FSMeligible")
    assert r.status_code == 200, r.text
    rows = r.json()["result"]
    assert len(rows) == 12
    assert all(row["total"] % 5 == 0 and row["count"] is not None and row["count"] % 5 == 0 for row in rows)
    assert not any("suppressed_groups" in row for row in rows)
    assert {row["URN"] for row in rows} == {f"SCH{i:02d}" for i in range(1, 13)}
    (event,) = events()
    assert event["max_pii_level"] == 3
    assert event["pupil_ids_returned"] == []


def test_both_leaks_are_refused_before_forwarding(gw, monkeypatch):  # noqa: F811
    client, _, state = gw
    call = counts_caller(state)

    async def never(*_args, **_kwargs):
        msg = "forwarded"
        raise AssertionError(msg)

    monkeypatch.setattr("gateway.main._forward", never)
    for leak in (LEAK_FILTER, LEAK_GROUP):
        r = call(client, **leak)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "COUNT_COLUMN_REFUSED")
        assert "result" not in r.json()
    assert [e["reason_code"] for e in events()] == ["COUNT_COLUMN_REFUSED", "COUNT_COLUMN_REFUSED"]


def test_one_in_care_pupil_is_not_counted(gw):  # noqa: F811
    client, _, state = gw
    call = counts_caller(state, claims={"clearance": 4})
    r = call(client, table=CENSUS, group_by=["URN"], measure="InCareAtCurrentSchool")
    assert r.status_code == 200, r.text
    by_school = {row["URN"]: row for row in r.json()["result"]}
    assert by_school["SCH07"] == {"URN": "SCH07", "total": 110, "count": None}  # 112 pupils, exactly 1 in care
    assert by_school["SCH02"]["count"] == 0  # none in care: zero is safe to say


def test_differencing_gives_multiples_of_five(gw):  # noqa: F811
    client, _, state = gw
    call = counts_caller(state, claims={"clearance": 4})
    whole = call(client, table=CENSUS, group_by=["URN"], measure="FSMeligible").json()["result"]
    spring = call(client, table=CENSUS, group_by=["URN"], measure="FSMeligible",
                  where={"CensusTerm": "SPR"}).json()["result"]  # fmt: skip
    for row in whole + spring:
        assert row["total"] % 5 == 0
        assert row["count"] is None or row["count"] % 5 == 0


def test_tables_without_pupils_are_rounded_rows(gw):  # noqa: F811
    client, _, state = gw
    call = counts_caller(state, constraints={"table": ["schools"]})
    r = call(client, table="schools", group_by=["SchoolLA"], measure="URN")
    assert r.status_code == 200, r.text
    assert r.json()["result"] == [{"SchoolLA": "SYN", "total": 10, "count": 0}]  # 12 schools, rounded
