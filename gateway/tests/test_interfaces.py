"""Clearance against server data levels (OpenSpec add-interface-slices, spec mandate-clearance)."""

import json

import pytest
from fastapi.testclient import TestClient

from data_slices import directory, schools, special
from gateway import cli, main
from gateway.lib.common import priv_from_pem
from gateway.lib.interfaces import SERVER_LEVELS, check_clearance
from mcp_server.api.routes_mcp import mcp as pupil_data

SCH04_Y11 = {"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}

# ---------------------------------------------------------------- check_clearance, design decision 6


@pytest.mark.parametrize(
    ("server", "claims", "expected"),
    [
        ("pupil-data", {}, None),  # legacy: no claim, no check
        ("schools", {}, "CLEARANCE_MISSING"),
        ("directory", {"clearance": True}, "CLEARANCE_INVALID"),
        ("directory", {"clearance": "high"}, "CLEARANCE_INVALID"),
        ("directory", {"clearance": 0}, "CLEARANCE_INVALID"),
        ("directory", {"clearance": 5}, "CLEARANCE_INVALID"),
        ("directory", {"clearance": 2.0}, "CLEARANCE_INVALID"),
        ("census", {"clearance": 4}, "UNKNOWN_SERVER"),
        ("census", {}, "UNKNOWN_SERVER"),
        ("directory", {"clearance": 1}, "CLEARANCE_TOO_LOW"),
        ("pupil-data", {"clearance": 3}, None),  # graded, not refused (add-graded-pupil-data)
        ("pupil-data", {"clearance": 1}, None),
        ("directory", {"clearance": 2}, None),
        ("special", {"clearance": 4}, None),
    ],
)
def test_check_clearance(server, claims, expected):
    result = check_clearance(server, claims)
    assert (result and result[1]) == expected


def test_too_low_detail_names_both_levels():
    assert check_clearance("directory", {"clearance": 1}) == (
        "DENY",
        "CLEARANCE_TOO_LOW",
        "directory is level 2, clearance is 1",
    )


# ---------------------------------------------------------------- through the gateway


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "mandate.jwt")]
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    # in-process upstreams, no network
    for name, server in {"pupil-data": pupil_data, "schools": schools.mcp, "directory": directory.mcp}.items():
        monkeypatch.setitem(main.MCP_SERVERS, name, server)
    monkeypatch.setitem(main.MCP_SERVERS, "special", special.mcp)
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())

    def mandate(scope, **claims):
        token, _ = cli.issue_mandate(
            state,
            agent_priv.public_key(),
            scope=scope,
            deny=["*.write", "pii.*"],
            ttl=600,
            purpose="interface slices test",
            principal="officer:test",
            org="school:SCH04",
            extra=claims,
        )
        return token

    def call(client, token, server, tool, **arguments):
        body = cli.sign_request(agent_priv, server=server, tool=tool, arguments=arguments, mandate=token)
        r = client.post("/tools/call", json=body)
        return r.status_code, r.json()

    with TestClient(main.app) as client:
        yield client, mandate, call


def directory_scope():
    return [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}]


def test_directory_allowed_at_clearance_2(gw):
    client, mandate, call = gw
    status, resp = call(client, mandate(directory_scope(), clearance=2), "directory", "roster", **SCH04_Y11)
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")
    assert resp["result"]
    assert all(set(r) == {"Psuedo ID", "DisplayName"} for r in resp["result"])


def test_directory_refused_at_clearance_1(gw):
    client, mandate, call = gw
    status, resp = call(client, mandate(directory_scope(), clearance=1), "directory", "roster", **SCH04_Y11)
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")
    assert resp["decision"]["detail"] == "directory is level 2, clearance is 1"


def test_clearance_in_arguments_is_ignored(gw):
    client, mandate, call = gw
    token = mandate(directory_scope(), clearance=1)
    status, resp = call(client, token, "directory", "roster", **SCH04_Y11, clearance=4)
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")


def test_malformed_clearance(gw):
    client, mandate, call = gw
    token = mandate([{"server": "schools", "tools": ["list"]}], clearance="high")
    status, resp = call(client, token, "schools", "list")
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_INVALID")


def test_pupil_data_refused_below_clearance_4(gw):
    """Kept by name: since add-graded-pupil-data, clearance 3 is served, stripped to level 3."""
    client, mandate, call = gw
    scope = [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH04"]}}]
    status, resp = call(client, mandate(scope, clearance=3), "pupil-data", "search", query="P0011", urn="SCH04")
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")


def test_clearance_never_widens_scope(gw):
    client, mandate, call = gw
    token = mandate([{"server": "schools", "tools": ["list"]}], clearance=4)
    status, resp = call(client, token, "directory", "roster", **SCH04_Y11)
    assert (status, resp["decision"]["reason_code"]) == (403, "OUT_OF_SCOPE")


def test_default_mandate_unchanged_on_pupil_data(gw):
    client, mandate, call = gw
    scope = [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}]
    status, resp = call(client, mandate(scope), "pupil-data", "search", query="P0004", urn="SCH01", limit=1)
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")


def test_no_clearance_refused_on_interface_server(gw):
    client, mandate, call = gw
    status, resp = call(client, mandate([{"server": "schools", "tools": ["list"]}]), "schools", "list")
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_MISSING")


def test_schools_at_clearance_1(gw):
    client, mandate, call = gw
    token = mandate([{"server": "schools", "tools": ["list"]}], clearance=1)
    status, resp = call(client, token, "schools", "list")
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")
    assert len(resp["result"]) == 12


def test_unknown_server(gw):
    client, mandate, call = gw
    token = mandate([{"server": "census", "tools": ["record"]}], clearance=4)
    status, resp = call(client, token, "census", "record", pupil_id="P0011")
    assert (status, resp["decision"]["reason_code"], resp["decision"]["detail"]) == (403, "UNKNOWN_SERVER", "census")


def special_scope():
    return [{"server": "special", "tools": ["record"], "constraints": {"urn": ["SCH04"]}}]


def test_special_held_for_approval_and_not_forwarded(gw, monkeypatch):
    client, mandate, call = gw
    forwarded = []
    monkeypatch.setitem(main.MCP_SERVERS, "special", forwarded)  # anything forwarded would fail loudly
    status, resp = call(
        client, mandate(special_scope(), clearance=4), "special", "record", pupil_id="P0011", urn="SCH04"
    )
    assert (status, resp["decision"]["decision"], resp["decision"]["reason_code"]) == (202, "STEP_UP", "SENSITIVE_TOOL")
    assert "result" not in resp


def test_special_refused_below_clearance_4(gw):
    client, mandate, call = gw
    status, resp = call(
        client, mandate(special_scope(), clearance=3), "special", "record", pupil_id="P0011", urn="SCH04"
    )
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")


def test_describe_shows_levels(gw):
    client, _, _ = gw
    desc = client.get("/describe").json()
    assert desc["server_levels"] == {
        "pupil-data": 4, "schools": 1, "directory": 2, "special": 4, "audit": 2, "grants": 1,
    }  # fmt: skip
    assert set(desc["servers"]) == set(SERVER_LEVELS)
    assert "special.*" in desc["step_up_patterns"]


def test_schema_documents_clearance():
    schema = json.loads(open("gateway/lib/mandate.schema.json").read())  # noqa: PTH123, SIM115
    assert schema["properties"]["clearance"]["maximum"] == 4
