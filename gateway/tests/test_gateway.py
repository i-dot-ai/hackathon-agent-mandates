import json

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway import eval as ev
from gateway.lib.common import priv_from_pem
from gateway.lib.gateway_verify import Request, check_request
from mcp_server.api.routes_mcp import SYNTH_ROOT, mcp

ROLE = "safeguarding-lead"  # the role the gateway lists for level 4 by default


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        [
            "--state",
            str(state),
            "issue",
            "--agent-key",
            str(state / "agent.pem"),
            "--clearance",
            "4",
            "--role",
            ROLE,
            "-o",
            str(state / "mandate.jwt"),
        ]
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
        req = Request("s", tool, arguments, mandate="", nonce="", ts=0, sig="")
        scope = [
            {"server": "s", "tools": ["t"], "constraints": {"urn": ["SCH01"], "path": ["a"]}},
            {"server": "s", "tools": ["t"], "constraints": {"urn": ["SCH02"], "path": ["b"]}},
        ]
        return check_request(req, scope, deny=[], step_up_patterns=[])[:2]

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


def test_demo_routes_are_off_unless_switched_on(gw):
    client, _, _ = gw
    # minting, signing and revoking with no authentication: never on a gateway that is not switched to demo
    assert not main.DEMO_ENABLED
    for path in ("/demo/mandate", "/demo/call", "/demo/revoke"):
        assert client.post(path, json={}).status_code == 404, path
    assert client.get("/demo/issuer").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.usefixtures("gw")
def test_demo_walkthrough():
    # the walkthrough mounts the demo router itself, as GATEWAY_DEMO=1 does for the local frontend
    from fastapi import FastAPI  # noqa: PLC0415

    from gateway.demo import router  # noqa: PLC0415

    demo_app = FastAPI()
    demo_app.include_router(router)
    client = TestClient(demo_app)
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
    cli.main(
        [
            "--state",
            str(state),
            "issue",
            "--agent-key",
            str(tmp_path / "team.jwk"),
            "--clearance",
            "4",
            "--role",
            ROLE,
            "-o",
            str(tmp_path / "m.jwt"),
        ]
    )
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
    issue = [
        "--state",
        str(state),
        "issue",
        "--agent-key",
        str(state / "agent.pem"),
        "--clearance",
        "4",
        "-o",
        str(out),
    ]

    cli.main([*issue, "--claims", '{"clearance": 2}'])
    capsys.readouterr()
    cli.main(["decode", str(out)])
    assert json.loads(capsys.readouterr().out)["clearance"] == 2

    # clearance 2 against census rows (level 4) is denied on max: the gateway now reads the claim
    body = cli.sign_request(
        priv_from_pem((state / "agent.pem").read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH01"},
        mandate=out.read_text(),
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")

    with pytest.raises(ValueError, match="scope"):
        cli.main([*issue, "--claims", '{"scope": []}'])


def test_clearance_required_and_denied_on_max(gw, tmp_path):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())

    # a mandate issued without the claim is an error the caller must fix, not a guess
    token, _ = cli.issue_mandate(
        state,
        agent.public_key(),
        scope=cli.DEFAULT_SCOPE,
        deny=cli.DEFAULT_DENY,
        ttl=3600,
        purpose="no clearance",
        principal="officer:jsmith",
        org="school:SCH01",
    )
    body = cli.sign_request(
        agent, server="pupil-data", tool="search", arguments={"query": ev.PUPIL, "urn": "SCH01"}, mandate=token
    )
    r, _ = call(client, "search", body=body)
    assert r.json()["decision"]["reason_code"] == "CLEARANCE_MISSING"

    # clearance 2: roster (names, level 2) is allowed, pupil (census, level 4) is denied on max
    out = tmp_path / "low.jwt"
    scope = json.dumps([{"server": "pupil-data", "tools": ["roster", "pupil"], "constraints": {"urn": ["SCH01"]}}])
    cli.main(
        [
            "--state",
            str(state),
            "issue",
            "--agent-key",
            str(state / "agent.pem"),
            "--clearance",
            "2",
            "--scope",
            scope,
            "-o",
            str(out),
        ]
    )
    mandate = out.read_text()
    r, _ = call(
        client,
        "roster",
        body=cli.sign_request(
            agent, server="pupil-data", tool="roster", arguments={"urn": "SCH01", "year_group": 11}, mandate=mandate
        ),
    )
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW")
    r, _ = call(
        client,
        "pupil",
        body=cli.sign_request(
            agent, server="pupil-data", tool="pupil", arguments={"pupil_id": ev.PUPIL, "urn": "SCH01"}, mandate=mandate
        ),
    )
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")


def _issue(state, out, clearance, scope=None, role=None):
    argv = ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "--clearance", str(clearance)]
    if scope is not None:
        argv += ["--scope", json.dumps(scope)]
    if role is not None:
        argv += ["--role", role]
    cli.main([*argv, "-o", str(out)])
    return out.read_text()


def test_no_clearance_is_told_and_the_stricter_label_decides(gw, tmp_path):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    search = {"query": ev.PUPIL, "urn": "SCH01"}

    token, _ = cli.issue_mandate(
        state,
        agent.public_key(),
        scope=cli.DEFAULT_SCOPE,
        deny=cli.DEFAULT_DENY,
        ttl=3600,
        purpose="no clearance",
        principal="officer:jsmith",
        org="school:SCH01",
    )
    r, _ = call(
        client,
        "search",
        body=cli.sign_request(agent, server="pupil-data", tool="search", arguments=search, mandate=token),
    )
    d = r.json()["decision"]
    assert (r.status_code, d["reason_code"]) == (403, "CLEARANCE_MISSING")
    # signature and proof of possession passed, so the notice names the agent that asked
    assert d["agent_id"]
    assert d["agent_id"] in d["notice"]
    assert "no clearance" in d["notice"]
    assert "consent" in d["notice"]

    # census rows carry URN at 1, Language at 3 and two columns at 4: the two at 4 decide
    mandate = _issue(state, tmp_path / "two.jwt", 2)
    r, _ = call(
        client,
        "search",
        body=cli.sign_request(agent, server="pupil-data", tool="search", arguments=search, mandate=mandate),
    )
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")
    assert "result" not in r.json()
    s = r.json()["decision"]["sensitivity"]
    assert (s["level"], s["clearance"], s["decided_by"]) == (4, 2, ["Ethnicity", "InCareAtCurrentSchool"])
    assert (s["labels"]["URN"], s["labels"]["Language"]) == (1, 3)


def test_counts_are_labelled_by_their_measure(gw, tmp_path):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    scope = [{"server": "pupil-data", "tools": ["aggregate"], "constraints": {"table": [ev.CENSUS]}}]
    mandate = _issue(state, tmp_path / "counts.jwt", 3, scope)

    def count(measure):
        args = {"table": ev.CENSUS, "group_by": ["URN"], "measure": measure}
        body = cli.sign_request(agent, server="pupil-data", tool="aggregate", arguments=args, mandate=mandate)
        return call(client, "aggregate", body=body)[0].json()["decision"]

    d = count("FSMeligible")
    assert (d["decision"], d["sensitivity"]["decided_by"]) == ("ALLOW", ["count (FSMeligible)"])
    d = count("InCareAtCurrentSchool")
    assert (d["reason_code"], d["sensitivity"]["decided_by"]) == (
        "CLEARANCE_TOO_LOW",
        ["count (InCareAtCurrentSchool)"],
    )


def test_labels_apply_on_the_next_call(gw, tmp_path, monkeypatch):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    manifest = tmp_path / "manifest.json"
    labels = json.loads((SYNTH_ROOT / "synthetic_manifest.json").read_text())
    manifest.write_text(json.dumps(labels))
    monkeypatch.setattr(main, "_CLASSIFICATION_CANDIDATES", [str(manifest)])
    mandate = _issue(state, tmp_path / "one.jwt", 1)

    def get_schools():
        args = {"path": "synthetic/synthetic_schools.csv"}
        body = cli.sign_request(agent, server="pupil-data", tool="get", arguments=args, mandate=mandate)
        return call(client, "get", body=body)[0]

    r = get_schools()
    assert (r.status_code, r.json()["decision"]["sensitivity"]["level"]) == (200, 1)
    # the label changes after the mandate was issued, and the running gateway uses the new one
    labels["classification"]["tables"]["schools"] = 2
    manifest.write_text(json.dumps(labels))
    r = get_schools()
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")


def test_aggregate_needs_same_clearance_as_direct_read(gw, tmp_path):
    """Q8: you may only aggregate a measure you may also read row-by-row (same deny-on-max as Q6)."""
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())

    def counts(clearance, measure):
        out = tmp_path / f"c{clearance}_{measure}.jwt"
        scope = json.dumps(
            [
                {
                    "server": "pupil-data",
                    "tools": ["aggregate"],
                    "constraints": {"table": [ev.CENSUS], "measure": [measure]},
                }
            ]
        )
        cli.main(
            [
                "--state",
                str(state),
                "issue",
                "--agent-key",
                str(state / "agent.pem"),
                "--clearance",
                str(clearance),
                "--scope",
                scope,
                "-o",
                str(out),
            ]
        )
        body = cli.sign_request(
            agent,
            server="pupil-data",
            tool="aggregate",
            arguments={"table": ev.CENSUS, "group_by": ["URN"], "measure": measure},
            mandate=out.read_text(),
        )
        return call(client, "aggregate", body=body)[0]

    # FSMeligible is level 3: clearance 2 denies (would also deny reading the column), 3 allows the counts,
    # rounded to the nearest 10 (617 rows at SCH01)
    r = counts(2, "FSMeligible")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")
    r = counts(3, "FSMeligible")
    assert (r.status_code, r.json()["result"][0]["total"]) == (200, 620)
    # InCareAtCurrentSchool is level 4: clearance 3 is not enough, aggregated or read directly
    r = counts(3, "InCareAtCurrentSchool")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")


_COUNTS_SCOPE = [{"server": "pupil-data", "tools": ["aggregate"], "constraints": {"table": [ev.CENSUS]}}]


def _aggregate(client, call, agent, mandate, **arguments):
    args = {"table": ev.CENSUS, "measure": "FSMeligible", **arguments}
    body = cli.sign_request(agent, server="pupil-data", tool="aggregate", arguments=args, mandate=mandate)
    return call(client, "aggregate", body=body)[0]


def test_counts_are_rounded_so_two_answers_cannot_be_subtracted(gw, tmp_path):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = _issue(state, tmp_path / "counts.jwt", 4, _COUNTS_SCOPE, ROLE)

    def released(**arguments):
        r = _aggregate(client, call, agent, mandate, **arguments)
        assert r.status_code == 200, r.text
        assert r.json()["decision"]["disclosure"] == {"rounded_to": 10}
        return r.json()["result"]

    # SCH02 has 74 meal rows, 69 of them WHIT: exact answers would give away the other 5
    school = released(group_by=["URN"], where={"URN": "SCH02"})
    whit = released(group_by=["URN"], where={"URN": "SCH02", "Ethnicity": "WHIT"})
    assert (school[0]["count"], whit[0]["count"]) == (70, 70)
    # every total and count is a multiple of 10, so no sum or difference of answers comes to 1-9
    cells = released(group_by=["URN", "Ethnicity"])
    assert all(cell["total"] % 10 == 0 and cell["count"] % 10 == 0 for cell in cells)


def test_small_count_lives_in_the_gateway(gw, monkeypatch):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    token, _ = cli.issue_mandate(
        state,
        agent.public_key(),
        scope=_COUNTS_SCOPE,
        deny=cli.DEFAULT_DENY,
        ttl=3600,
        purpose="counts",
        principal="officer:jsmith",
        org="school:SCH01",
        extra={"clearance": 4, "small_count": 1},
    )

    def counts():
        return [cell["count"] for cell in _aggregate(client, call, agent, token, group_by=["URN"]).json()["result"]]

    # the issuer cannot lower the floor
    assert all(count % 10 == 0 for count in counts())
    # the gateway's own setting can
    monkeypatch.setitem(main.state, "small_count", 1)
    assert any(count % 10 for count in counts())


def test_an_aggregate_cannot_single_out_a_pupil(gw, tmp_path):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = _issue(state, tmp_path / "counts.jwt", 4, _COUNTS_SCOPE)
    # each pupil has up to five census rows, so a group of one pupil would still round to 10
    for arguments in ({"group_by": ["Psuedo ID"]}, {"group_by": ["URN"], "where": {"Psuedo ID": ev.PUPIL}}):
        r = _aggregate(client, call, agent, mandate, **arguments)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "TOO_FINE"), arguments

    # a filter is labelled like a column: one ethnic group's count needs the clearance for Ethnicity
    mandate = _issue(state, tmp_path / "three.jwt", 3, _COUNTS_SCOPE)
    r = _aggregate(client, call, agent, mandate, group_by=["URN"], where={"Ethnicity": "WHIT"})
    d = r.json()["decision"]
    assert (r.status_code, d["reason_code"]) == (403, "CLEARANCE_TOO_LOW")
    assert d["sensitivity"]["decided_by"] == ["Ethnicity (filter)"]


def test_level_4_needs_a_role_the_gateway_lists(gw, tmp_path, monkeypatch):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())

    def read(role):
        mandate = _issue(state, tmp_path / "pupil.jwt", 4, role=role)
        args = {"query": ev.PUPIL, "urn": "SCH01"}
        body = cli.sign_request(agent, server="pupil-data", tool="search", arguments=args, mandate=mandate)
        return call(client, "search", body=body)[0]

    # census rows carry Ethnicity and InCareAtCurrentSchool at level 4: clearance 4 alone does not open them
    for role in (None, "teacher"):
        r = read(role)
        d = r.json()["decision"]
        assert (r.status_code, d["reason_code"]) == (403, "ROLE_REQUIRED"), role
        assert d["sensitivity"]["decided_by"] == ["Ethnicity", "InCareAtCurrentSchool"]
        assert "result" not in r.json()
    assert read(ROLE).status_code == 200
    # below level 4 no role is read: meal counts are level 3
    mandate = _issue(state, tmp_path / "counts.jwt", 4, _COUNTS_SCOPE)
    assert _aggregate(client, call, agent, mandate, group_by=["URN"]).status_code == 200
    assert client.get("/describe").json()["private_data"]["roles"] == [ROLE]

    # the list is the gateway's: replace it, and the roles swap
    monkeypatch.setitem(main.state, "private_roles", frozenset({"teacher"}))
    assert read("teacher").status_code == 200
    assert read(ROLE).json()["decision"]["reason_code"] == "ROLE_REQUIRED"
    monkeypatch.setenv("GATEWAY_PRIVATE_ROLES", " teacher, dpo ")
    assert main.private_roles_setting() == {"teacher", "dpo"}
    monkeypatch.setenv("GATEWAY_PRIVATE_ROLES", " , ")
    with pytest.raises(ValueError, match="at least one role"):
        main.private_roles_setting()

    # a role that is not a name refuses every call, even one with no level 4 data
    token, _ = cli.issue_mandate(
        state,
        agent.public_key(),
        scope=cli.DEFAULT_SCOPE,
        deny=cli.DEFAULT_DENY,
        ttl=3600,
        purpose="bad role",
        principal="officer:jsmith",
        org="school:SCH01",
        extra={"clearance": 4, "role": [ROLE]},
    )
    body = cli.sign_request(agent, server="pupil-data", tool="get", arguments={"path": ev.SCHOOLS}, mandate=token)
    r, _ = call(client, "get", body=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "ROLE_INVALID")


def _signed(agent, mandate, tool, **arguments):
    return cli.sign_request(agent, server="pupil-data", tool=tool, arguments=arguments, mandate=mandate)


def test_refusal_does_not_depend_on_whether_rows_matched(gw, tmp_path):
    """Q6: clearance is decided before the call, so a refusal says nothing about the data."""
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    scope = [{"server": "pupil-data", "tools": ["search", "pupil"], "constraints": {"urn": ["SCH01"]}}]
    mandate = _issue(state, tmp_path / "two.jwt", 2, scope)
    # a pupil who is there and one who is not get the same answer, and neither call reaches the data
    for query in (ev.PUPIL, "P9999"):
        r, _ = call(client, "search", body=_signed(agent, mandate, "search", query=query, urn="SCH01"))
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW"), query
        assert "the call could return" in r.json()["decision"]["detail"]
    for pupil_id in (ev.PUPIL, "P9999"):
        r, _ = call(client, "pupil", body=_signed(agent, mandate, "pupil", pupil_id=pupil_id, urn="SCH01"))
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW"), pupil_id


def test_search_query_is_one_value_of_three_characters(gw):
    client, call, _ = gw
    for query in (",", "P0004,F", "P0004,F,WHIT", "P0", "ab"):
        r, _ = call(client, "search", urn="SCH01", query=query)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "TOO_MUCH"), query
    r, _ = call(client, "search", urn="SCH01", query="Y11")
    assert r.status_code == 200


def test_malformed_requests_are_refused_not_500(gw):
    client, call, _ = gw

    def b64(obj):
        return cli.b64u(json.dumps(obj).encode())

    header = b64({"typ": "mandate+jwt", "alg": "EdDSA"})
    junk = {"server": "pupil-data", "tool": "search", "arguments": {"query": "SPR"}, "nonce": "n", "ts": 0, "sig": "x"}
    for mandate in ("", "x", "a.b.c", f"{header}.{b64({})}.x", f"{header}.{b64({'iss': [1]})}.x"):
        r = client.post("/tools/call", json={**junk, "mandate": mandate})
        assert r.status_code == 403, mandate
        assert r.json()["decision"]["decision"] == "DENY"
    _, body = call(client, "search", query="SPR", urn="SCH01")
    for ts in (10**400, -(10**400)):
        r = client.post("/tools/call", json={**body, "ts": ts})
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")
    r = client.post("/tools/call", json={**body, "nonce": "n" * 129})
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")


def test_replay_is_refused_after_a_restart(gw):
    client, call, state = gw
    r, body = call(client, "search", query="SPR", urn="SCH01")
    assert r.status_code == 200
    main.load_state(state)  # a fresh Gateway, as after a restart or on another worker
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")


def test_small_groups_are_withheld_not_just_rounded(gw, tmp_path):
    client, call, state = gw
    agent = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = _issue(state, tmp_path / "counts.jwt", 4, _COUNTS_SCOPE, ROLE)
    # Greystone has one pupil in care, five census rows: rounding alone showed the group with total 0
    r = _aggregate(
        client,
        call,
        agent,
        mandate,
        group_by=["URN", "InCareAtCurrentSchool"],
        measure="InCareAtCurrentSchool",
        where={"URN": "SCH07"},
    )
    assert r.status_code == 200, r.text
    assert [row["InCareAtCurrentSchool"] for row in r.json()["result"]] == ["0"]
    assert "withheld" in r.json()["decision"]["detail"]
    assert all(row["total"] >= 10 for row in r.json()["result"])


def test_every_decision_is_audited_with_the_pupils_returned(gw):
    client, call, state = gw
    call(client, "search", query=ev.PUPIL, urn="SCH01")
    call(client, "search", query="SPR", urn="SCH02")
    lines = [json.loads(line) for line in (state / "audit.jsonl").read_text().splitlines()]
    allowed, refused = lines[-2:]
    assert (allowed["decision"], allowed["pupils"]) == ("ALLOW", [ev.PUPIL])
    assert allowed["agent_id"]  # names the key, so the attacking team
    assert "Ethnicity" in allowed["columns"]
    assert (refused["decision"], refused["reason_code"], refused["pupils"]) == ("DENY", "CONSTRAINT_VIOLATED", [])


def test_labels_fail_closed():
    from gateway.lib.gateway_verify import result_levels  # noqa: PLC0415

    columns = {"Ethnicity": 4, "URN": 1}
    tables = {"schools": 1}

    def level(tool, result, **arguments):
        return max(result_levels(tool, arguments, result, columns, tables, 4).values(), default=0)

    # shapes with no keys to read a label from
    assert level("search", [["P0011", "ASIA"]]) == 4
    assert level("search", "P0011 ASIA") == 4
    assert level("search", [{"URN": {"Ethnicity": "ASIA"}}]) == 4
    # special keys count only in the tool they belong to
    assert level("search", [{"total": "ASIA"}]) == 4
    assert level("search", [{"letter": "ASIA"}]) == 4
    assert level("aggregate", [{"URN": "SCH01", "total": 30}], group_by=["URN"]) == 1
    # only the manifest is a public non-CSV file
    assert level("get", {"x": 1}, path="synthetic/synthetic_manifest.json") == 1
    assert level("get", {"x": 1}, path="writes/corrections.jsonl") == 4


def test_lost_labels_keep_the_last_good_copy(gw, monkeypatch):
    client, call, _ = gw
    monkeypatch.setattr(main, "_CLASSIFICATION_CANDIDATES", ["/no/such/manifest.json"])
    r, _ = call(client, "get", path=ev.SCHOOLS)
    assert r.status_code == 200, r.text
    assert "FileNotFoundError" in main.state["labels_error"]


def test_eval_set_passes_against_template_gateway(gw, tmp_path):
    client, _, state = gw
    ev.main(["build", "--state", str(state), "-o", str(tmp_path / "pack")])

    def post(body):
        r = client.post("/tools/call", json=body)
        return r.status_code, r.json()

    results = ev.run_cases(tmp_path / "pack", post)
    assert [line for ok, line in results if not ok] == []
    assert len(results) == len(ev.VALID) + len(ev.INVALID) + len(ev.BUILD)
