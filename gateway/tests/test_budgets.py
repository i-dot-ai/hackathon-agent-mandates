"""Run budgets (OpenSpec add-run-budgets): the whole run is limited, not just each call."""

import asyncio
import csv
import json
import sqlite3

import pytest

from gateway import cli, main
from gateway.lib import audit, budgets
from gateway.lib.common import pub_from_pem
from gateway.tests.test_audit import _bare_event, all_events, caller, claims_of, issue, reader
from gateway.tests.test_gateway import gw  # noqa: F401  (fixture)

CENSUS_CSV = "mcp_server/data/synthetic/synthetic_personal_data_school_census.csv"
TERM = {"AUT": 0, "SPR": 1, "SUM": 2}


def pupils_currently_at(urn: str, n: int) -> list[str]:
    latest: dict[str, tuple] = {}
    with open(CENSUS_CSV, newline="") as f:  # noqa: PTH123
        for r in csv.DictReader(f):
            key = (r["AcademicYear"], TERM[r["CensusTerm"]])
            if r["Psuedo ID"] not in latest or key > latest[r["Psuedo ID"]][0]:
                latest[r["Psuedo ID"]] = (key, r["URN"])
    return sorted(p for p, (_, u) in latest.items() if u == urn)[:n]


def pupil_mandate(state, out, *, urn="SCH05", claims=None, rate=None):
    entry = {"server": "pupil-data", "tools": ["pupil", "search"], "constraints": {"urn": [urn]}}
    if rate:
        entry["rate"] = rate
    return issue(state, out, scope=[entry], claims={"clearance": 3, **(claims or {})})  # person tools need one


def set_limits(**overrides):
    main.state["limits"] = budgets.State(budgets.Limits(**overrides))


def reasons(responses):
    return [(r.status_code, r.json()["decision"]["reason_code"]) for r in responses]


# ---------------------------------------------------------------- configuration


def test_repo_limits_file_loads_with_the_documented_defaults():
    limits = budgets.load_limits(env={})
    assert limits == budgets.Limits()
    assert limits.per_key_per_minute == 300
    assert limits.default_distinct_pupils is None


def test_env_overrides_and_validation(tmp_path):
    env = {"GATEWAY_LIMIT_CEILINGS_PER_KEY_PER_MINUTE": "600", "GATEWAY_LIMIT_BUDGETS_DEFAULT_CALLS": "50",
           "GATEWAY_LIMIT_BUDGETS_DEFAULT_DISTINCT_PUPILS": "null"}  # fmt: skip
    limits = budgets.load_limits(env=env)
    assert (limits.per_key_per_minute, limits.default_calls, limits.default_distinct_pupils) == (600, 50, None)

    bad = tmp_path / "limits.yaml"
    for text, match in (
        ("ceilings:\n  per_key_per_minut: 5\n", "unknown key"),
        ("throttle:\n  x: 1\n", "unknown section"),
        ("ceilings:\n  per_key_per_minute: -1\n", "non-negative integer"),
        ("alerts:\n  many_pupils: null\n", "non-negative integer"),
    ):
        bad.write_text(text)
        with pytest.raises(budgets.LimitsConfigError, match=match):
            budgets.load_limits(bad, env={})
    with pytest.raises(budgets.LimitsConfigError, match="override must be an integer"):
        budgets.load_limits(env={"GATEWAY_LIMIT_ALERTS_MANY_PUPILS": "lots"})
    with pytest.raises(budgets.LimitsConfigError, match="doesn't exist"):
        budgets.load_limits(env={"GATEWAY_LIMITS_CONFIG": str(tmp_path / "missing.yaml")})


def test_describe_shows_the_limits(gw):  # noqa: F811
    client, _, _ = gw
    assert client.get("/describe").json()["limits"]["per_key_per_minute"] == 300


# ---------------------------------------------------------------- claims


def test_malformed_budget_is_refused_and_argument_budget_ignored(gw):  # noqa: F811
    client, _, state = gw
    bad = caller(state, pupil_mandate(state, "bad.jwt", claims={"budget": {"distinct_pupils": "lots"}}))
    r = bad(client, "pupil-data", "search", query="SPR", urn="SCH05")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "BUDGET_INVALID")

    p1, p2 = pupils_currently_at("SCH05", 2)
    small = caller(state, pupil_mandate(state, "small.jwt", claims={"budget": {"distinct_pupils": 1}}))
    assert small(client, "pupil-data", "pupil", pupil_id=p1, urn="SCH05").status_code == 200
    r = small(client, "pupil-data", "pupil", pupil_id=p2, urn="SCH05")
    assert r.json()["decision"]["reason_code"] == "BUDGET_EXHAUSTED"
    # limits are read from claims only: nothing in a call's arguments reaches parse_claims
    plan = budgets.plan_for(main.state["limits"], {"jti": "j", "scope": []}, "pupil-data", "pupil",
                            {"budget": {"distinct_pupils": 1000}})  # fmt: skip
    assert plan.claimed.budget == {}


# ---------------------------------------------------------------- distinct pupils


def test_one_at_a_time_then_stopped(gw):  # noqa: F811
    client, _, state = gw
    mandate = pupil_mandate(state, "walk.jwt", claims={"budget": {"distinct_pupils": 3}})
    call = caller(state, mandate)
    pupils = pupils_currently_at("SCH05", 4)
    responses = [call(client, "pupil-data", "pupil", pupil_id=p, urn="SCH05") for p in pupils]
    assert reasons(responses) == [(200, "IN_SCOPE")] * 3 + [(429, "BUDGET_EXHAUSTED")]
    assert "result" not in responses[3].json()
    assert responses[3].json()["decision"]["detail"] == "distinct_pupils 3"
    assert asyncio.run(audit.family_pupils(claims_of(mandate)["jti"])) == set(pupils[:3])
    withheld = all_events()[-1]
    assert (withheld["decision"], withheld["pupil_ids_returned"]) == ("DENY", [])

    again = call(client, "pupil-data", "pupil", pupil_id=pupils[0], urn="SCH05")  # seen before: free
    assert again.status_code == 200


def test_a_result_crossing_the_budget_is_withheld_whole(gw):  # noqa: F811
    client, _, state = gw
    call = caller(state, pupil_mandate(state, "cross.jwt", claims={"budget": {"distinct_pupils": 3}}))
    (p1,) = pupils_currently_at("SCH05", 1)
    assert call(client, "pupil-data", "pupil", pupil_id=p1, urn="SCH05").status_code == 200
    r = call(client, "pupil-data", "search", query="SPR", urn="SCH05", limit=20)  # many new pupils at once
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (429, "BUDGET_EXHAUSTED")
    assert "result" not in r.json()


def test_a_supplementary_mandate_shares_its_parents_budget(gw):  # noqa: F811
    client, _, state = gw
    budget = {"budget": {"distinct_pupils": 3}}
    parent = pupil_mandate(state, "parent.jwt", claims=budget)
    pupils = pupils_currently_at("SCH05", 4)
    for p in pupils[:3]:
        assert caller(state, parent)(client, "pupil-data", "pupil", pupil_id=p, urn="SCH05").status_code == 200
    # the issuer copies the parent's budget into the supplementary mandate, which points at its parent
    # a real parent claim names its status list too: the gateway refuses a child whose parent it can't check
    pclaims = claims_of(parent)
    parent_ref = {"jti": pclaims["jti"], "status": pclaims["status"]["status_list"]}
    child = pupil_mandate(state, "child.jwt", claims={**budget, "parent": parent_ref})
    r = caller(state, child)(client, "pupil-data", "pupil", pupil_id=pupils[3], urn="SCH05")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (429, "BUDGET_EXHAUSTED")


def test_gateway_default_budget_applies_to_claimless_mandates_only_when_configured(gw):  # noqa: F811
    client, _, state = gw
    p1, p2 = pupils_currently_at("SCH05", 2)
    plain = caller(state, pupil_mandate(state, "plain.jwt"))
    assert plain(client, "pupil-data", "pupil", pupil_id=p1, urn="SCH05").status_code == 200
    assert plain(client, "pupil-data", "pupil", pupil_id=p2, urn="SCH05").status_code == 200  # default: none
    set_limits(default_distinct_pupils=1)
    fresh = caller(state, pupil_mandate(state, "fresh.jwt"))
    assert fresh(client, "pupil-data", "pupil", pupil_id=p1, urn="SCH05").status_code == 200
    r = fresh(client, "pupil-data", "pupil", pupil_id=p2, urn="SCH05")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (429, "BUDGET_EXHAUSTED")


# ---------------------------------------------------------------- calls and rates


def test_per_minute_rate(gw, monkeypatch):  # noqa: F811
    client, _, state = gw
    clock = [1000.0]
    monkeypatch.setattr(budgets.time, "monotonic", lambda: clock[0])
    call = caller(state, pupil_mandate(state, "rate.jwt", rate={"per_minute": 2}))
    responses = [call(client, "pupil-data", "search", query=q, urn="SCH05") for q in ("SPR", "AUT", "SUM")]
    assert reasons(responses) == [(200, "IN_SCOPE"), (200, "IN_SCOPE"), (429, "RATE_LIMITED")]
    assert responses[2].headers["retry-after"] == "60"
    clock[0] += 61
    assert call(client, "pupil-data", "search", query="SPR", urn="SCH05").status_code == 200


def test_max_calls_and_call_budget_count_only_allowed_calls(gw):  # noqa: F811
    client, _, state = gw
    call = caller(state, pupil_mandate(state, "max.jwt", rate={"max_calls": 2}))
    responses = [
        call(client, "pupil-data", "search", query="SPR", urn="SCH05"),
        call(client, "pupil-data", "search", query="SPR", urn="SCH09"),  # refused: doesn't count
        call(client, "pupil-data", "search", query="AUT", urn="SCH05"),
        call(client, "pupil-data", "search", query="SUM", urn="SCH05"),
    ]
    assert reasons(responses) == [
        (200, "IN_SCOPE"),
        (403, "CONSTRAINT_VIOLATED"),
        (200, "IN_SCOPE"),
        (429, "BUDGET_EXHAUSTED"),
    ]
    calls = caller(state, pupil_mandate(state, "calls.jwt", claims={"budget": {"calls": 1}}))
    assert calls(client, "pupil-data", "search", query="SPR", urn="SCH05").status_code == 200
    r = calls(client, "pupil-data", "search", query="AUT", urn="SCH05")
    assert (r.status_code, r.json()["decision"]["detail"]) == (429, "calls 1")


# ---------------------------------------------------------------- ceilings


def test_agent_key_ceiling(gw):  # noqa: F811
    client, call, _ = gw
    set_limits(per_key_per_minute=3)
    responses = [call(client, "search", query="P0004", urn="SCH01")[0] for _ in range(5)]
    assert reasons(responses) == [(200, "IN_SCOPE")] * 3 + [(429, "RATE_LIMITED")] * 2
    assert responses[3].json()["decision"]["detail"] == "agent key ceiling"


def test_forged_flood_is_cut_off_and_barely_recorded(gw):  # noqa: F811
    client, _, _ = gw
    set_limits(unverified_per_source_per_minute=5)
    responses = [
        client.post(
            "/tools/call",
            json={
                "server": "pupil-data",
                "tool": "search",
                "arguments": {},
                "mandate": "garbage",
                "nonce": f"n{i}",
                "ts": 0,
                "sig": "x",
            },
        )
        for i in range(30)
    ]
    assert reasons(responses)[:5] == [(403, "MANDATE_MALFORMED")] * 5
    assert set(reasons(responses)[5:]) == {(429, "RATE_LIMITED")}
    assert len(all_events()) <= 5 + 2  # five refusals, then about one event per second while the ceiling holds


def test_the_eval_is_far_below_the_ceilings(gw):  # noqa: F811
    client, call, _ = gw
    responses = [call(client, "search", query="P0004", urn="SCH01")[0] for _ in range(64)]  # two eval runs' worth
    assert {r.status_code for r in responses} == {200}


# ---------------------------------------------------------------- alerts


def test_refusals_raise_an_alert_not_a_refusal(gw):  # noqa: F811
    client, call, state = gw
    jti = claims_of((state / "mandate.jwt").read_text())["jti"]
    denied = [call(client, "search", query="SPR", urn="SCH02")[0] for _ in range(6)]
    allowed = call(client, "search", query="P0004", urn="SCH01")[0]
    assert {r.json()["decision"]["reason_code"] for r in denied} == {"CONSTRAINT_VIOLATED"}
    assert allowed.status_code == 200
    alerts = [e for e in all_events() if e["event_type"] == "alert"]
    assert [(a["reason_code"], a["jti"]) for a in alerts] == [("ALERT_REFUSALS", jti)]


def test_a_targeted_pupil_is_flagged_once_and_still_served(gw):  # noqa: F811
    client, _, state = gw
    for i in range(4):
        r = caller(state, issue(state, f"m{i}.jwt"))(client, "pupil-data", "search", query="P0004", urn="SCH01")
        assert r.status_code == 200
    alerts = [e for e in all_events() if e["event_type"] == "alert"]
    assert [(a["reason_code"], a["scope_pupil_id"]) for a in alerts] == [("ALERT_PUPIL_TARGETED", "P0004")]
    out = reader(state, principal="officer:jsmith")(client, "audit", "events", principal="officer:jsmith").json()
    shown = [e for e in out["result"]["verified"] if e["event_type"] == "alert"]
    assert shown == [{**shown[0], "reason_code": "ALERT_PUPIL_TARGETED", "pupil_id": "P0004"}]


def test_mandates_with_budget_claims_get_no_alerts(gw):  # noqa: F811
    client, _, state = gw
    call = caller(state, pupil_mandate(state, "quiet.jwt", claims={"budget": {"calls": 100}}))
    for _ in range(6):
        call(client, "pupil-data", "search", query="SPR", urn="SCH09")
    assert [e for e in all_events() if e["event_type"] == "alert"] == []


# ---------------------------------------------------------------- an older audit file


def test_an_audit_file_from_before_alerts_is_migrated_and_still_verifies(tmp_path):
    cli.main(["--state", str(tmp_path), "init"])
    path = tmp_path / "audit.sqlite"
    old = audit.SQLITE_SCHEMA.replace(", 'alert'", "").replace(" family_jti TEXT, scope_entry TEXT,", "")
    old = "\n".join(line for line in old.splitlines() if "audit_events_family" not in line)
    # an old file holding one event, written the way the earlier version wrote it
    signed = asyncio.run(audit.MemoryStore(audit.Signer(tmp_path)).append(_bare_event()))
    raw = sqlite3.connect(path)
    raw.executescript(old)
    cols = [*audit.FIELDS, "event_hash", "sig"]
    row = {**signed, "identity_verified": 0, **{k: json.dumps(signed[k]) for k in audit.ARRAY_FIELDS}}
    raw.execute(f"INSERT INTO audit_events ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",  # noqa: S608
                [row[k] for k in cols])  # fmt: skip
    raw.commit()
    assert "'alert'" not in raw.execute("SELECT sql FROM sqlite_master WHERE name='audit_events'").fetchone()[0]
    raw.close()

    reopened = audit.SqliteStore(audit.Signer(tmp_path), path)
    audit._store = reopened  # noqa: SLF001
    asyncio.run(audit.record_alert(jti="urn:uuid:j", principal="p", reason_code="ALERT_REFUSALS",
                                   event_id=budgets.alert_id("j", "refusals")))  # fmt: skip
    chain = asyncio.run(reopened.all_events())
    assert [e["event_type"] for e in chain] == ["decision", "alert"]
    pub = pub_from_pem((tmp_path / "gateway.pub").read_bytes())
    assert audit.verify_chain(chain, pub) == []
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        sqlite3.connect(path).execute("DELETE FROM audit_events")
    audit._store = None  # noqa: SLF001
    json.dumps(chain)  # events stay plain data
