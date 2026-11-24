"""Zero-trust tool grants (OpenSpec add-scope-requests, spec tool-grants)."""

import asyncio
import socket
import threading
import time
import uuid

import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

import tool_grants as tg
from data_slices import directory
from gateway.lib.grant_issue import grant_fields, grant_for
from mcp_server.api.routes_mcp import mcp as pupil_data

ARGS = {"query": "P0004", "urn": "SCH01", "limit": 1}


def _mint(priv, *, server="pupil-data", tool="search", arguments=ARGS, now=None, decision_id=None, **over):
    fields = {"level": 4, "urns": ["SCH01"], "pupils": None, "constraints": {"urn": ["SCH01"]}, "max_rows": 100}
    fields.update(over)
    return tg.mint(
        priv,
        server=server,
        tool=tool,
        arguments=arguments,
        decision_id=decision_id or f"d-{uuid.uuid4()}",
        mandate_jti="urn:uuid:m",
        agent_id="a",
        principal="officer:test",
        now=now,
        **fields,
    )


@pytest.fixture
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


# ---------------------------------------------------------------- mint and verify


def test_valid_grant(keys):
    priv, pub = keys
    grant = tg.verify(_mint(priv), pub, server="pupil-data", tool="search", arguments=ARGS)
    grant = tg.verify(_mint(priv, decision_id="d-1"), pub, server="pupil-data", tool="search", arguments=ARGS)
    assert (grant.jti, grant.urns, grant.level, grant.max_rows) == ("d-1", ("SCH01",), 4, 100)


@pytest.mark.parametrize(
    ("token_kw", "server", "tool", "arguments", "code"),
    [
        ({}, "pupil-data", "search", {**ARGS, "query": ""}, "GRANT_MISMATCH"),  # other arguments
        ({}, "pupil-data", "pupil", ARGS, "GRANT_MISMATCH"),  # other tool
        ({}, "directory", "search", ARGS, "GRANT_MISMATCH"),  # other server
        ({"now": time.time() - 120}, "pupil-data", "search", ARGS, "GRANT_EXPIRED"),
    ],
)
def test_refusals(keys, *, token_kw, server, tool, arguments, code):
    priv, pub = keys
    with pytest.raises(tg.GrantError) as e:
        tg.verify(_mint(priv, **token_kw), pub, server=server, tool=tool, arguments=arguments)
    assert e.value.code == code


def test_missing_and_forged(keys):
    _, pub = keys
    with pytest.raises(tg.GrantError) as e:
        tg.verify(None, pub, server="pupil-data", tool="search", arguments=ARGS)
    assert e.value.code == "GRANT_MISSING"
    other = Ed25519PrivateKey.generate()
    with pytest.raises(tg.GrantError) as e:
        tg.verify(_mint(other), pub, server="pupil-data", tool="search", arguments=ARGS)
    assert e.value.code == "GRANT_INVALID"


def test_replay_is_refused():
    seen = tg.SeenGrants()
    seen.check_and_add("d-1")
    with pytest.raises(tg.GrantError) as e:
        seen.check_and_add("d-1")
    assert e.value.code == "GRANT_REPLAYED"


# ---------------------------------------------------------------- derived only from the mandate


def test_grant_ignores_arguments():
    claims = {"jti": "urn:uuid:m", "agent_id": "a", "delegator": {"principal": "officer:test"}, "clearance": 2}
    entry = {"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}
    fields = grant_fields(claims, entry, "directory")
    assert fields == {"level": 2, "urns": ["SCH04"], "pupils": None, "constraints": entry["constraints"],
                      "max_rows": 100}  # fmt: skip
    # an extra urn or clearance in the arguments changes nothing: only args_hash depends on them
    token = grant_for(
        Ed25519PrivateKey.generate(), claims, entry, server="directory", tool="roster",
        arguments={"urn": "SCH02", "clearance": 4}, decision_id="d-2",
    )  # fmt: skip
    import jwt  # noqa: PLC0415

    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["subjects"]["urns"] == ["SCH04"]
    assert payload["level"] == 2


def test_claimless_mandate_gets_the_claimless_level(monkeypatch):
    # a mandate with no clearance keeps reaching pupil-data (question 0, the Day 2 default mandate), but its
    # grant carries the claim-less level (add-graded-pupil-data), so the server strips what the gateway would
    entry = {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}
    assert grant_fields({"jti": "j"}, entry, "pupil-data")["level"] == 2
    monkeypatch.setenv("GATEWAY_CLAIMLESS_LEVEL", "3")
    assert grant_fields({"jti": "j"}, entry, "pupil-data")["level"] == 3
    monkeypatch.setenv("GATEWAY_CLAIMLESS_LEVEL", "9")  # a bad value never falls back to 4
    assert grant_fields({"jti": "j"}, entry, "pupil-data")["level"] == 2
    assert grant_fields({"jti": "j", "clearance": 4}, entry, "pupil-data")["level"] == 4


def test_claimless_counts_are_not_stripped():
    # safe counts release rounded aggregates and are never stripped (add-graded-pupil-data): stripping the per-pupil
    # breakdown's group columns at the server would merge groups and corrupt the counts
    entry = {"server": "pupil-data", "tools": ["aggregate"], "constraints": {"table": ["personal_data_school_census"]}}
    assert grant_fields({"jti": "j"}, entry, "pupil-data", tool="aggregate")["level"] == 4
    assert grant_fields({"jti": "j"}, entry, "pupil-data", tool="search")["level"] == 2


def test_claimless_search_drops_special_category_columns(served):
    base, priv = served
    args = {"query": "P0004", "urn": "SCH01"}
    entry = {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}
    fields = grant_fields({"jti": "j"}, entry, "pupil-data")
    rows = _call(f"{base}/mcp/", "search", args, _mint(priv, tool="search", arguments=args, **fields))
    assert rows
    assert all(r["Psuedo ID"] == "P0004" for r in rows)
    returned = {k for r in rows for k in r}
    assert not {"Ethnicity", "InCareAtCurrentSchool", "FSMeligible", "Language"} & returned
    assert "Gender" in returned  # basic data still comes through


# ---------------------------------------------------------------- over real HTTP


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def served(tmp_path, keys):
    """pupil-data and directory over HTTP behind the grant middleware, as in Compose."""
    priv, pub = keys
    pub_path = tmp_path / "tool_grant.pub"
    tg.ensure_keypair(tmp_path / "k.pem", tmp_path / "unused.pub")  # exercise creation
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    pub_path.write_bytes(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    pd_app = pupil_data.http_app(path="/", stateless_http=True)
    dir_app = directory.mcp.http_app(path="/", stateless_http=True)
    from fastmcp.utilities.lifespan import combine_lifespans  # noqa: PLC0415

    app = FastAPI(lifespan=combine_lifespans(pd_app.lifespan, dir_app.lifespan))
    app.mount("/mcp", tg.GrantMiddleware(pd_app, "pupil-data", pub_path))
    app.mount("/directory/mcp", tg.GrantMiddleware(dir_app, "directory", pub_path))
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", priv
    server.should_exit = True
    thread.join(timeout=5)


def _call(url, tool, arguments, grant=None):
    async def go():
        headers = {tg.HEADER: grant} if grant else {}
        async with Client(StreamableHttpTransport(url, headers=headers)) as client:
            return (await client.call_tool(tool, arguments)).data

    return asyncio.run(go())


def test_direct_call_has_no_grant(served):
    base, _ = served
    with pytest.raises(ToolError, match="GRANT_MISSING"):
        _call(f"{base}/mcp/", "search", ARGS)


def test_listing_tools_still_works(served):
    base, _ = served

    async def go():
        async with Client(f"{base}/mcp/") as client:
            return [t.name for t in await client.list_tools()]

    assert "search" in asyncio.run(go())


def test_granted_call_and_replay(served):
    base, priv = served
    grant = _mint(priv)
    rows = _call(f"{base}/mcp/", "search", ARGS, grant)
    assert [r["Psuedo ID"] for r in rows] == ["P0004"]
    with pytest.raises(ToolError, match="GRANT_REPLAYED"):
        _call(f"{base}/mcp/", "search", ARGS, grant)


def test_grant_reused_for_another_call(served):
    base, priv = served
    with pytest.raises(ToolError, match="GRANT_MISMATCH"):
        _call(f"{base}/mcp/", "search", {**ARGS, "query": ""}, _mint(priv))


def test_gateway_bug_does_not_leak_another_school(served):
    """The grant says SCH01; the arguments (which a buggy gateway let through) ask for SCH02."""
    base, priv = served
    args = {"query": "SPR", "urn": "SCH02", "limit": 5}
    with pytest.raises(ToolError, match="GRANT_SCOPE"):
        _call(f"{base}/mcp/", "search", args, _mint(priv, arguments=args))


def test_rows_outside_the_grant_are_dropped(served):
    """No urn argument at all: the server still returns only the granted school's rows."""
    base, priv = served
    args = {"query": "P0004", "limit": 50}
    rows = _call(f"{base}/mcp/", "search", args, _mint(priv, arguments=args, constraints={}, urns=["SCH02"]))
    assert rows == [] or all(r["URN"] == "SCH02" for r in rows)


def test_audience_enforced_at_the_tool(served):
    base, priv = served
    args = {"urn": "SCH04", "year_group": 11}

    def grant(pupils):
        return _mint(
            priv, server="directory", tool="roster", arguments=args, level=2, urns=["SCH04"],
            pupils=pupils, constraints={"urn": ["SCH04"]},
        )  # fmt: skip

    everyone = [r["Psuedo ID"] for r in _call(f"{base}/directory/mcp/", "roster", args, grant(None))]
    two = sorted(everyone)[:2]
    assert len(everyone) > 2
    rows = _call(f"{base}/directory/mcp/", "roster", args, grant(two))
    assert sorted(r["Psuedo ID"] for r in rows) == two


def test_roster_for_another_school(served):
    base, priv = served
    args = {"urn": "SCH02", "year_group": 11}
    grant = _mint(priv, server="directory", tool="roster", arguments=args, level=2, urns=["SCH04"], constraints={})
    with pytest.raises(ToolError, match="GRANT_SCOPE"):
        _call(f"{base}/directory/mcp/", "roster", args, grant)


def test_level_enforced_at_the_tool(served):
    base, priv = served
    args = {"pupil_id": "P0011", "urn": "SCH04"}
    record = _call(
        f"{base}/mcp/", "pupil", args,
        _mint(priv, tool="pupil", arguments=args, level=2, urns=["SCH04"], constraints={}),
    )  # fmt: skip
    assert record["Psuedo ID"] == "P0011"
    assert "Ethnicity" not in record
    assert "InCareAtCurrentSchool" not in record
    assert "FSMeligible" not in record


def test_max_rows_cap(served):
    base, priv = served
    args = {"query": "SCH01", "urn": "SCH01", "limit": 50}
    rows = _call(f"{base}/mcp/", "search", args, _mint(priv, arguments=args, max_rows=3))
    assert len(rows) == 3


# ---------------------------------------------------------------- every pupil-data tool, task 3.5


def _sch01_grant(**over):
    fields = {
        "jti": "g", "server": "pupil-data", "tool": "t", "args_hash": "h", "mandate_jti": "m", "agent_id": None,
        "principal": None, "level": 4, "urns": ("SCH01",), "pupils": None, "constraints": {}, "max_rows": 100,
    }  # fmt: skip
    fields.update(over)
    return tg.Grant(**fields)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("search", {"query": "SPR", "urn": "SCH02"}),
        ("roster", {"urn": "SCH02", "year_group": 11}),
        ("pupil", {"pupil_id": "P0004", "urn": "SCH02"}),
        ("draft", {"urn": "SCH02", "pupil_ids": ["P0004"]}),
        ("write", {"pupil_id": "P0004", "urn": "SCH02", "column": "FSMeligible", "value": "1", "reason": "t"}),
    ],
)
def test_tools_naming_a_school_refuse_another(tool, arguments):
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    token = tg.current_grant.set(_sch01_grant())
    try:
        with pytest.raises(ToolError, match="GRANT_SCOPE"):
            getattr(routes_mcp, tool)(**arguments)
    finally:
        tg.current_grant.reset(token)


def test_tools_without_a_school_argument_return_no_other_school():
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    token = tg.current_grant.set(_sch01_grant())
    try:
        rows = routes_mcp.search(query="SPR", limit=100)  # no urn: every school would match
        assert rows
        assert {r["URN"] for r in rows} == {"SCH01"}
        groups = routes_mcp.aggregate(table="personal_data_school_census", group_by=["URN"], measure="FSMeligible")
        assert {g["URN"] for g in groups} == {"SCH01"}
        assert routes_mcp.get(path="synthetic/synthetic_schools.csv") == [
            r for r in routes_mcp.get.__wrapped__(path="synthetic/synthetic_schools.csv") if r["URN"] == "SCH01"
        ]
        assert routes_mcp.classification()["levels"]  # a document with no rows passes through
    finally:
        tg.current_grant.reset(token)


def test_no_grant_in_process_is_unchanged():
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    assert len(routes_mcp.search(query="SPR", limit=100)) == 100


def test_batch_request_without_a_grant_gets_nothing(served):
    """A JSON-RPC batch slips past a check that only looks at single tools/call bodies; it must still fail closed."""
    import json as _json  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    base, _ = served
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "search", "arguments": {"query": "P0011", "urn": "SCH04"}}}]  # fmt: skip
    req = urllib.request.Request(  # noqa: S310
        f"{base}/mcp/",
        data=_json.dumps(batch).encode(),
        headers={"content-type": "application/json", "accept": "application/json, text/event-stream"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            body = resp.read().decode()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
    assert "P0011" not in body


def test_http_call_that_reaches_a_tool_without_a_grant_is_refused():
    """Fail closed at the tool too: whatever route got an HTTP call past the middleware, no grant means no data."""
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    marker = tg.over_http.set(True)
    try:
        with pytest.raises(ToolError, match="GRANT_MISSING"):
            routes_mcp.search(query="P0011", urn="SCH04")
    finally:
        tg.over_http.reset(marker)


@pytest.mark.parametrize(("level", "expected_rows"), [(2, False), (4, True)])
def test_server_search_cant_select_by_a_column_above_the_grant(served, level, expected_rows):
    """At the data server too: a search hit must match a column the grant lets through, or the rows it picks
    reveal the stripped value (searching "ASIA" at level 2 returned exactly the pupils of that ethnicity)."""
    base, priv = served
    args = {"query": "ASIA", "urn": "SCH01", "limit": 100}
    grant = _mint(priv, arguments=args, level=level)
    rows = _call(f"{base}/mcp/", "search", args, grant)
    assert bool(rows) is expected_rows
    if rows:
        assert all(r["Ethnicity"] == "ASIA" for r in rows)
