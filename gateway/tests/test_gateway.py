import json

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway import eval as ev
from gateway.lib.common import priv_from_pem
from gateway.lib.gateway_verify import Request, check_request
from mcp_server.api.routes_mcp import mcp


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "mandate.jwt")]
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)  # in-process upstream, no network
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = (state / "mandate.jwt").read_text()

    def call(client, tool, body=None, **arguments):
        body = body or cli.sign_request(
            agent_priv, server="pupil-data", tool=tool, arguments=arguments, mandate=mandate
        )
        return client.post("/tools/call", json=body), body

    with TestClient(main.app) as client:
        yield client, call, state


def test_allow_deny_replay_revoke(gw):
    client, call, state = gw

    r, body = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert r.status_code == 200, r.text
    assert r.json()["decision"]["decision"] == "ALLOW"
    assert {row["URN"] for row in r.json()["result"]} == {"SCH01"}

    # get is limited to the two files with no pupil data, so the names file is refused
    r, _ = call(client, "get", path="synthetic/synthetic_display_names.csv")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")

    r, _ = call(client, "search", body=body)  # replay of the first signed request
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")

    cli.main(["--state", str(state), "revoke", "--idx", "0"])
    r, _ = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "REVOKED")


def test_bulk_export_is_denied(gw):
    client, call, _ = gw
    for arguments in (
        {"query": ""},
        {"query": "  "},
        {"query": "SPR", "limit": 101},
        {"query": "SPR", "limit": "5"},
        {"query": "SPR", "limit": -1},
        {"query": "SPR", "limit": True},
    ):
        r, _ = call(client, "search", urn="SCH01", **arguments)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "TOO_MUCH"), arguments
    r, _ = call(client, "search", urn="SCH01", query="SPR", limit=100)
    assert r.status_code == 200, r.text


def test_path_spellings(gw):
    client, call, _ = gw
    for path in ("./" + ev.SCHOOLS, ev.SCHOOLS.replace("/", "//"), "synthetic/x/../synthetic_schools.csv/"):
        r, _ = call(client, "get", path=path)
        assert r.status_code == 200, path
        assert r.json()["result"][0]["URN"] == "SCH01"
    for path in (
        "synthetic/../synthetic/synthetic_display_names.csv",
        "/" + ev.SCHOOLS,
        "../data/" + ev.SCHOOLS,
        ev.SCHOOLS + "/../synthetic_display_names.csv",
        ev.SCHOOLS.upper(),
        ev.SCHOOLS + "\x00",
        "",
        123,
        [ev.SCHOOLS],
    ):
        r, _ = call(client, "get", path=path)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED"), path


def test_any_scope_entry_may_allow_but_entries_do_not_mix():
    def check(tool="t", **arguments):
        # pupil-data: a server with a data level that mandates without clearance may still call
        req = Request("pupil-data", tool, arguments, mandate="", nonce="", ts=0, sig="")
        scope = [
            {"server": "pupil-data", "tools": ["t"], "constraints": {"urn": ["SCH01"], "path": ["a"]}},
            {"server": "pupil-data", "tools": ["t"], "constraints": {"urn": ["SCH02"], "path": ["b"]}},
        ]
        return check_request(req, scope, deny=[], step_up_patterns=[], claims={})[:2]

    assert check(urn="SCH01", path="a") == ("ALLOW", "IN_SCOPE")
    assert check(urn="SCH02", path="b") == ("ALLOW", "IN_SCOPE")  # the second entry is tried
    assert check(urn="SCH01", path="b") == ("DENY", "CONSTRAINT_VIOLATED")  # urn from one, path from the other
    assert check(urn="SCH03", path="a") == ("DENY", "CONSTRAINT_VIOLATED")
    assert check(path="a") == ("DENY", "CONSTRAINT_MISSING")
    assert check(urn="SCH02", path="b", limit=101) == ("DENY", "TOO_MUCH")
    assert check(tool="other", urn="SCH01", path="a") == ("DENY", "OUT_OF_SCOPE")


def test_issue_warns_when_entries_for_one_tool_constrain_different_arguments():
    def entry(**constraints):
        return {"server": "pupil-data", "tools": ["pupil"], "constraints": constraints}

    assert cli.scope_warnings(cli.DEFAULT_SCOPE) == []
    assert cli.scope_warnings(ev.TWO_SCHOOLS_SCOPE) == []  # same argument in both entries: a plain second grant
    (warning,) = cli.scope_warnings([entry(urn=["SCH01"]), entry(pupil_id=["P0011"])])
    assert "pupil-data.pupil" in warning
    assert len(cli.scope_warnings([entry(urn=["SCH01"]), entry()])) == 1  # an unconstrained entry beside a narrow one


def test_tampered_mandate_is_denied(gw):
    client, call, state = gw
    mandate = (state / "mandate.jwt").read_text()
    header, payload, sig = mandate.split(".")
    claims = json.loads(cli.b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = ["SCH01", "SCH02"]
    forged = ".".join([header, cli.b64u(json.dumps(claims).encode()), sig])
    body = cli.sign_request(
        priv_from_pem((state / "agent.pem").read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH02"},
        mandate=forged,
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "SIG_INVALID")


def test_demo_is_off_by_default(gw):
    client, _, _ = gw
    assert client.post("/demo/mandate", json={}).status_code == 404
    assert client.post("/demo/revoke", json={"idx": 0}).status_code == 404
    assert client.get("/demo/issuer").status_code == 404


def test_demo_walkthrough(gw, monkeypatch):
    monkeypatch.setenv("GATEWAY_ENABLE_DEMO", "1")
    client, _, _ = gw
    m = client.post("/demo/mandate", json={"urn": "SCH01"}).json()
    assert m["header"]["typ"] == "mandate+jwt"
    assert m["claims"]["scope"][0]["constraints"] == {"urn": ["SCH01"]}

    issuer = client.get("/demo/issuer").json()["issuer"]
    assert (issuer["iss"], issuer["kid"]) == (m["claims"]["iss"], m["header"]["kid"])
    assert "d" not in issuer["public_jwk"]  # the private half never leaves the state dir

    r = client.post("/demo/call", json={"tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}).json()
    assert (r["status"], r["response"]["decision"]["decision"]) == (200, "ALLOW")

    t = client.post("/demo/revoke", json={"idx": m["status_idx"]}).json()
    assert t["status_list"]["revoked"] == [m["status_idx"]]
    r = client.post("/demo/call", json={"tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}).json()
    assert (r["status"], r["response"]["decision"]["reason_code"]) == (403, "REVOKED")


def test_describe_and_issue_to_public_jwk(gw, tmp_path, capsys):
    client, call, state = gw

    desc = client.get("/describe").json()
    assert [t["name"] for t in desc["servers"]["pupil-data"]] == [
        "search",
        "get",
        "aggregate",
        "classification",
        "roster",
        "pupil",
        "draft",
        "write",
    ]
    ex = desc["signing"]["example"]
    assert Request(**ex["request"]).signing_input().decode() == ex["signing_input"]

    # team runs keygen and sends only the public JWK; issuer never sees the private key
    team_key = tmp_path / "team.pem"
    cli.main(["keygen", "-o", str(team_key)])
    (tmp_path / "team.jwk").write_text(capsys.readouterr().out)
    cli.main(["--state", str(state), "issue", "--agent-key", str(tmp_path / "team.jwk"), "-o", str(tmp_path / "m.jwt")])
    body = cli.sign_request(
        priv_from_pem(team_key.read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH01"},
        mandate=(tmp_path / "m.jwt").read_text(),
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW")


def test_issue_with_claims_of_your_own(gw, tmp_path, capsys):
    client, call, state = gw
    out = tmp_path / "m.jwt"
    issue = ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(out)]

    def search_with(mandate):
        body = cli.sign_request(
            priv_from_pem((state / "agent.pem").read_bytes()),
            server="pupil-data",
            tool="search",
            arguments={"query": "SPR", "urn": "SCH01"},
            mandate=mandate,
        )
        r, _ = call(client, "search", body=body)
        return r.status_code, r.json()["decision"]["reason_code"]

    cli.main([*issue, "--claims", '{"team_note": "letters run"}'])
    capsys.readouterr()
    cli.main(["decode", str(out)])
    assert json.loads(capsys.readouterr().out)["team_note"] == "letters run"
    # the gateway ignores a claim it does not read, so the mandate still works
    assert search_with(out.read_text()) == (200, "IN_SCOPE")

    # clearance is read (add-interface-slices); pupil-data is graded (add-graded-pupil-data): clearance 2 is
    # served, stripped to level 2
    cli.main([*issue, "--claims", '{"clearance": 2}'])
    assert search_with(out.read_text()) == (200, "IN_SCOPE")

    with pytest.raises(ValueError, match="scope"):
        cli.main([*issue, "--claims", '{"scope": []}'])


def test_eval_set_passes_against_template_gateway(gw, tmp_path):
    client, _, state = gw
    ev.main(["build", "--state", str(state), "-o", str(tmp_path / "pack")])

    def post(body):
        r = client.post("/tools/call", json=body)
        return r.status_code, r.json()

    results = ev.run_cases(tmp_path / "pack", post)
    # questions 3 to 5 are the teams' build work, so only the starter's questions 0 to 2 must pass
    assert [line for ok, line in results if not ok and line[:2] in {"Q0", "Q1", "Q2"}] == []
    assert len(results) == len(ev.VALID) + len(ev.INVALID) + len(ev.BUILD)


def test_expired_means_expired(gw, monkeypatch):
    """No grace on exp: one second past expiry is EXPIRED, however small the clock skew allowance."""
    client, call, state = gw
    mandate_claims = json.loads(cli.b64u_decode((state / "mandate.jwt").read_text().split(".")[1]))
    monkeypatch.setattr("gateway.lib.gateway_verify.time.time", lambda: mandate_claims["exp"] + 1)
    r, _ = call(client, "search", query="P0004", urn="SCH01")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "EXPIRED")
