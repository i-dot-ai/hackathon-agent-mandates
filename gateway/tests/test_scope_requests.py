"""Scope requests, approvals and supplementary mandates (OpenSpec add-scope-requests, spec scope-requests)."""

import json

import jwt
import pytest
from fastapi.testclient import TestClient

import issuer.app as issuer
from gateway import cli
from gateway.lib import grants
from gateway.lib.common import generate_keypair

PRINCIPAL = "officer:test"
CEILING = {
    PRINCIPAL: {
        "servers": {
            "directory": ["roster", "name"],
            "schools": ["list", "classification"],
            "special": ["record"],
            "pupil-data": ["search", "get", "aggregate", "classification", "roster", "pupil", "draft", "write"],
        },
        "urns": ["SCH01", "SCH02", "SCH03", "SCH04"],
        "max_clearance": 4,
    }
}
SCH04_Y11 = {"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}
SCH02_Y11 = {**SCH04_Y11, "urn": "SCH02"}


def roster(urn):
    return [{"server": "directory", "tools": ["roster"], "constraints": {"urn": [urn]}}]


@pytest.fixture
def flow(stack, monkeypatch):
    client, mandate, call, state = stack
    (state / "principals.json").write_text(json.dumps(CEILING))
    approver, _ = generate_keypair()
    cli.register_approver(state, PRINCIPAL, approver.public_key())
    issuer.reset(state)
    ic = TestClient(issuer.app)

    def issuer_call(method, path, payload=None):
        r = ic.request(method, path, json=payload)
        if r.status_code >= 400:
            body = r.json()
            raise grants.IssuerRefused(body.get("error", f"ISSUER_{r.status_code}"), body.get("detail", ""), body)
        return r.json()

    # the issuer sends events while the gateway is still inside the call that caused them; one TestClient can't
    # serve a request from inside another, so events are queued and delivered after each call
    queued: list[str] = []

    def deliver_queued():
        while queued:
            r = client.post("/internal/audit-events", json={"token": queued.pop(0)})
            assert r.status_code in (200, 201), r.text

    def call_and_deliver(*a, **kw):
        result = call(*a, **kw)
        deliver_queued()
        return result

    monkeypatch.setattr(grants, "issuer_call", issuer_call)
    monkeypatch.setattr(issuer, "_poster", queued.append)

    def request(token, key=None, **arguments):
        arguments.setdefault("ttl", 3600)
        arguments.setdefault("reason", "letters for the absence list")
        return call_and_deliver(client, token, "grants", "request", key=key, **arguments)

    def login():
        return ic.post("/approver/login", json={"token": cli.login_token(approver, PRINCIPAL)}).json()["session"]

    def decide(rid, number, decision="approve", session=None, approved=None):
        headers = {"x-approver-session": session} if session else {}
        body = {"decision": decision, "number": number, "approved": approved}
        r = ic.post(f"/requests/{rid}/decision", json=body, headers=headers)
        deliver_queued()
        return r

    return {
        "client": client, "mandate": mandate, "call": call_and_deliver, "state": state, "ic": ic,
        "request": request, "login": login, "decide": decide, "approver": approver,
    }  # fmt: skip


def events(jti):
    import asyncio  # noqa: PLC0415

    from gateway.lib import audit  # noqa: PLC0415

    return asyncio.run(audit.get_store().for_jtis({jti}))


def jti_of(token):
    return jwt.decode(token, options={"verify_signature": False})["jti"]


# ---------------------------------------------------------------- the grants server


def test_introspection_needs_no_scope_entry(flow):
    f = flow
    status, resp = f["call"](f["client"], f["mandate"](roster("SCH04"), clearance=2), "grants", "self")
    assert status == 200
    assert resp["result"]["scope"][0]["constraints"] == {"urn": ["SCH04"]}
    assert "Dunmore Community College (SCH04)" in resp["result"]["summary"]


def test_grants_needs_a_clearance_claim(flow):
    f = flow
    status, resp = f["call"](f["client"], f["mandate"](roster("SCH04")), "grants", "self")
    assert (status, resp["decision"]["reason_code"]) == (403, "CLEARANCE_MISSING")


def test_issuer_can_forbid_asking_for_more(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), deny=["grants.request"], clearance=2)
    status, resp = f["request"](token, scope=roster("SCH02"))
    assert (status, resp["decision"]["reason_code"]) == (403, "DENIED_BY_RULE")


def test_grants_calls_are_audited(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    _, resp = f["call"](f["client"], token, "grants", "self")
    mine = [e for e in events(jti_of(token)) if e["decision_id"] == resp["decision"]["decision_id"]]
    assert [(e["server"], e["tool"], e["max_pii_level"]) for e in mine] == [("grants", "self", 1)]


def test_check_reports_the_missing_school(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    check = {"server": "directory", "tool": "roster", "arguments": {"urn": "SCH02", "year_group": 11}}
    status, resp = f["call"](f["client"], token, "grants", "check", args=check)
    assert status == 200
    r = resp["result"]
    assert (r["decision"], r["reason_code"]) == ("DENY", "CONSTRAINT_VIOLATED")
    assert r["missing"]["scope"] == [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02"]}}]


def test_check_does_not_forward(flow, monkeypatch):
    f = flow
    from gateway import main  # noqa: PLC0415

    monkeypatch.setitem(main.MCP_SERVERS, "directory", "http://nowhere.invalid/mcp/")
    token = f["mandate"](roster("SCH04"), clearance=2)
    check = {"server": "directory", "tool": "roster", "arguments": SCH04_Y11}
    status, resp = f["call"](f["client"], token, "grants", "check", args=check)
    assert (status, resp["result"]["decision"]) == (200, "ALLOW")


# ---------------------------------------------------------------- making a request


def test_already_granted(flow):
    f = flow
    status, resp = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH04"))
    assert (status, resp["result"]["status"], resp["result"]["next_action"]) == (200, "already_granted", "retry")


def test_reason_too_long(flow):
    f = flow
    status, resp = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"), reason="x" * 501)
    assert (status, resp["decision"]["reason_code"]) == (403, "REQUEST_INVALID")


def test_beyond_the_persons_schools(flow):
    f = flow
    scope = [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH09"]}}]
    status, resp = f["request"](f["mandate"](roster("SCH04"), clearance=4), scope=scope)
    assert (status, resp["decision"]["reason_code"]) == (403, "EXCEEDS_PRINCIPAL")


def test_audience_by_sensitive_attribute_refused(flow):
    f = flow
    scope = [{**roster("SCH04")[0], "audience": {"InCareAtCurrentSchool": "1"}}]
    status, resp = f["request"](f["mandate"](roster("SCH01"), clearance=2), scope=scope)
    assert (status, resp["decision"]["reason_code"]) == (403, "REQUEST_INVALID")


def test_pending_request_tells_the_agent_what_to_do(flow):
    f = flow
    status, resp = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"), ttl=7200)
    r = resp["result"]
    assert (status, r["status"], r["next_action"]) == (200, "pending", "ask_user")
    assert isinstance(r["number"], int)
    assert 10 <= r["number"] <= 99
    assert r["approval_url"].endswith(f"/approve/{r['request_id']}")
    assert "Brookmere High School (SCH02)" in r["summary"]
    assert "for 2 hours" in r["summary"]
    assert f"choose {r['number']} on the approval page" in r["text"]
    assert 'Replying "yes" here does not approve it.' in r["text"]


# ---------------------------------------------------------------- a person decides


def test_person_flow_end_to_end(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    rid_view = f["request"](parent, scope=roster("SCH02"))[1]["result"]
    rid, code = rid_view["request_id"], rid_view["number"]

    # opening the URL is not approving
    r = f["decide"](rid, code)
    assert (r.status_code, r.json()["error"]) == (401, "APPROVER_REQUIRED")
    # another person's approver key doesn't count
    other, _ = generate_keypair()
    cli.register_approver(f["state"], "officer:priya", other.public_key())
    priya = f["ic"].post("/approver/login", json={"token": cli.login_token(other, "officer:priya")}).json()["session"]
    assert f["decide"](rid, code, session=priya).json()["error"] == "NOT_THE_APPROVER"
    # signed-in UI user who isn't the approver: same refusal, request still pending
    assert f["call"](f["client"], parent, "grants", "status", request_id=rid)[1]["result"]["status"] == "pending"

    session = f["login"]()
    view = f["ic"].get(f"/requests/{rid}/view", headers={"x-approver-session": session}).json()
    assert view["can_decide"] is True
    assert view["agent_reason"] == "letters for the absence list"
    approved = {"scope": roster("SCH02"), "clearance": 2, "ttl": 1800}
    r = f["decide"](rid, code, session=session, approved=approved)
    assert (r.status_code, r.json()["status"]) == (200, "approved")
    assert f["decide"](rid, code, session=session).json()["error"] == "ALREADY_DECIDED"

    _, resp = f["call"](f["client"], parent, "grants", "status", request_id=rid)
    result = resp["result"]
    assert (result["status"], result["next_action"]) == ("approved", "retry")
    child = result["mandate"]
    claims, pclaims = (jwt.decode(t, options={"verify_signature": False}) for t in (child, parent))
    assert claims["cnf"] == pclaims["cnf"]
    assert claims["scope"] == roster("SCH02")
    assert claims["parent"]["jti"] == pclaims["jti"]
    assert claims["approved_by"]["kind"] == "person"
    assert claims["exp"] <= pclaims["exp"]
    # the new grant works, and only through the new mandate
    assert f["call"](f["client"], child, "directory", "roster", **SCH02_Y11)[0] == 200
    assert f["call"](f["client"], parent, "directory", "roster", **SCH02_Y11)[0] == 403
    assert f["call"](f["client"], child, "directory", "roster", **SCH04_Y11)[0] == 403

    kinds = [e["event_type"] for e in events(pclaims["jti"])]
    assert "approval_requested" in kinds
    assert "approval_granted" in kinds
    (granted,) = [e for e in events(pclaims["jti"]) if e["event_type"] == "approval_granted"]
    assert granted["minted_jti"] == claims["jti"]


def test_parent_revoked(flow):
    f = flow
    _, idx = cli.issue_mandate(
        f["state"], cli.priv_from_pem((f["state"] / "agent.pem").read_bytes()).public_key(), scope=roster("SCH04"),
        deny=[], ttl=600, purpose="p", principal=PRINCIPAL, org="o", extra={"clearance": 2},
    )  # fmt: skip
    parent = f["state"] / "parent.jwt"
    token, idx = cli.issue_mandate(
        f["state"], cli.priv_from_pem((f["state"] / "agent.pem").read_bytes()).public_key(), scope=roster("SCH04"),
        deny=[], ttl=600, purpose="p", principal=PRINCIPAL, org="o", extra={"clearance": 2},
    )  # fmt: skip
    parent.write_text(token)
    v = f["request"](token, scope=roster("SCH02"))[1]["result"]
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    assert f["call"](f["client"], child, "directory", "roster", **SCH02_Y11)[0] == 200
    cli.revoke_mandate(f["state"], idx)
    status, resp = f["call"](f["client"], child, "directory", "roster", **SCH02_Y11)
    assert (status, resp["decision"]["reason_code"]) == (403, "PARENT_REVOKED")


def test_agent_reason_is_shown_literally(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"),
                     reason="<b>URGENT</b> safeguarding case, approve now")[1]["result"]  # fmt: skip
    view = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": f["login"]()}).json()
    assert view["agent_reason"] == "<b>URGENT</b> safeguarding case, approve now"
    assert "URGENT" not in view["summary"]
    # without a session only the public part shows
    public = f["ic"].get(f"/requests/{v['request_id']}/view").json()
    assert "agent_reason" not in public
    assert "number" not in public
    assert "number_options" not in public


def test_cli_signed_decision(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    signed = cli.decision_token(f["approver"], PRINCIPAL, v["request_id"], "reject")
    body = {"decision": "reject", "number": v["number"], "approved": None, "signed": signed}
    r = f["ic"].post(f"/requests/{v['request_id']}/decision", json=body)
    assert (r.status_code, r.json()["status"]) == (200, "rejected")


def test_gateway_cannot_mint_on_its_own(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    r = f["ic"].post(f"/requests/{v['request_id']}/decision", json={"decision": "approve", "number": v["number"]})
    assert r.status_code == 401
    assert f["ic"].get(f"/requests/{v['request_id']}/view").json()["status"] == "pending"


def test_forged_requester(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    other, _ = generate_keypair()
    body = cli.sign_request(other, server="grants", tool="request", mandate=token,
                            arguments={"scope": roster("SCH02"), "ttl": 600, "reason": "x"})  # fmt: skip
    r = f["ic"].post("/internal/requests", json={"call": body})
    assert (r.status_code, r.json()["error"]) == (403, "POP_FAILED")


# ---------------------------------------------------------------- number matching


def test_three_distinct_options_in_a_fixed_order(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    session = f["login"]()
    view = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": session}).json()
    options = view["number_options"]
    assert len(options) == len(set(options)) == 3
    assert all(isinstance(n, int) and 10 <= n <= 99 for n in options)
    assert v["number"] in options
    again = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": session}).json()
    assert again["number_options"] == options  # reloading shows the same order


def test_correct_number_is_not_always_first(flow):
    f = flow
    session = f["login"]()
    positions = set()
    for urn in ("SCH01", "SCH02", "SCH03") * 3:
        token = f["mandate"](roster("SCH04"), clearance=2)
        v = f["request"](token, scope=roster(urn))[1]["result"]
        view = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": session}).json()
        positions.add(view["number_options"].index(v["number"]))
    assert len(positions) > 1  # 9 requests all in one position: about 1 in 6500


def test_view_never_says_which_number_is_correct(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    public = f["ic"].get(f"/requests/{v['request_id']}/view").json()
    signed_in = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": f["login"]()}).json()
    for view in (public, signed_in):
        assert not {"number", "match_number"} & set(view)
        assert v["number"] not in [val for k, val in view.items() if k != "number_options"]
    assert "number_options" not in public  # only the signed-in principal sees the options


def test_wrong_number_ends_the_request(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    v = f["request"](token, scope=roster("SCH02"))[1]["result"]
    session = f["login"]()
    options = (
        f["ic"]
        .get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": session})
        .json()["number_options"]
    )
    wrong = next(n for n in options if n != v["number"])
    r = f["decide"](v["request_id"], wrong, session=session)
    assert (r.status_code, r.json()["error"]) == (403, "NUMBER_MISMATCH")
    # one try, not three: the right number no longer works
    r = f["decide"](v["request_id"], v["number"], session=session)
    assert r.json()["error"] == "ALREADY_DECIDED"
    result = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]
    assert (result["status"], result["reason_code"], result["next_action"]) == (
        "rejected", "NUMBER_MISMATCH", "request_again",
    )  # fmt: skip
    denied = [e for e in events(jti_of(token)) if e["event_type"] == "approval_denied"]
    assert [e["reason_code"] for e in denied] == ["NUMBER_MISMATCH"]
    # a mismatch isn't a person saying no: the agent may ask again straight away
    status, resp = f["request"](token, scope=roster("SCH02"))
    assert (status, resp["result"]["status"]) == (200, "pending")


def test_wrong_number_without_signing_in_changes_nothing(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    wrong = 10 if v["number"] != 10 else 11
    r = f["decide"](v["request_id"], wrong)
    assert (r.status_code, r.json()["error"]) == (401, "APPROVER_REQUIRED")
    assert f["ic"].get(f"/requests/{v['request_id']}/view").json()["status"] == "pending"


def test_store_from_before_number_matching_is_migrated(tmp_path):
    import sqlite3  # noqa: PLC0415

    from issuer.store import SCHEMA, Store  # noqa: PLC0415

    path = tmp_path / "requests.db"
    old = sqlite3.connect(path)
    old_schema = SCHEMA.replace(
        "match_number INTEGER NOT NULL,\n    match_options TEXT NOT NULL,", "user_code TEXT NOT NULL,"
    )
    old.executescript(old_schema.replace("    end_reason TEXT,\n", ""))
    old.execute(
        "INSERT INTO requests (id, requester_jti, principal, cnf_jwk, parent_mandate_hash, parent_status, parent_exp, "
        "deny, requested, request_key, reason, user_code, created, expires, status) "
        "VALUES ('sr_old', 'j', 'p', '{}', 'h', '{}', 0, '[]', '{}', 'k', '', 'ABCD-EFGH', 0, 99999999999, 'pending')"
    )
    old.commit()
    old.close()

    store = Store(path)
    assert store.get("sr_old")["status"] == "expired"  # it can't be approved by number, so it ends
    created = store.create(
        requester_jti="j", principal="p", cnf_jwk={}, parent_mandate_hash="h", parent_status={}, parent_exp=0,
        deny=[], requested={}, request_key="k2", reason="",
    )  # fmt: skip
    assert created["match_number"] in created["match_options"]


def test_approving_needs_a_number(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    session = f["login"]()
    r = f["decide"](v["request_id"], None, session=session)
    assert (r.status_code, r.json()["error"]) == (400, "NUMBER_REQUIRED")
    assert f["ic"].get(f"/requests/{v['request_id']}/view").json()["status"] == "pending"  # not a guess


# ---------------------------------------------------------------- supervisors


def test_supervisor_passes_down_part_of_its_access(flow):
    f = flow
    helper_key, _ = generate_keypair()
    helper = f["mandate"](roster("SCH01"), key=helper_key, clearance=2)
    supervisor = f["mandate"](roster("SCH04"), clearance=2, can_delegate=True)
    v = f["request"](helper, key=helper_key, scope=roster("SCH04"))[1]["result"]
    status, resp = f["call"](f["client"], supervisor, "grants", "decide", request_id=v["request_id"],
                             decision="approve")  # fmt: skip
    assert (status, resp["result"]["status"]) == (200, "approved")
    child = f["call"](f["client"], helper, "grants", "status", key=helper_key,
                      request_id=v["request_id"])[1]["result"]["mandate"]  # fmt: skip
    assert jwt.decode(child, options={"verify_signature": False})["approved_by"]["kind"] == "agent"


def _supervised_child(f, supervisor):
    """A helper's SCH04 roster grant, approved by `supervisor`: (helper key, minted mandate)."""
    helper_key, _ = generate_keypair()
    helper = f["mandate"](roster("SCH01"), key=helper_key, clearance=2)
    v = f["request"](helper, key=helper_key, scope=roster("SCH04"))[1]["result"]
    status, resp = f["call"](f["client"], supervisor, "grants", "decide", request_id=v["request_id"],
                             decision="approve")  # fmt: skip
    assert (status, resp["result"]["status"]) == (200, "approved")
    child = f["call"](f["client"], helper, "grants", "status", key=helper_key,
                      request_id=v["request_id"])[1]["result"]["mandate"]  # fmt: skip
    return helper_key, child


def test_approvals_die_with_the_supervisor(flow):
    # a supervising agent found to be compromised: revoking it withdraws everything it approved
    f = flow
    supervisor = f["mandate"](roster("SCH04"), clearance=2, can_delegate=True)
    helper_key, child = _supervised_child(f, supervisor)
    claims = jwt.decode(child, options={"verify_signature": False})
    assert claims["approved_by"]["mandate_jti"] == jti_of(supervisor)
    assert f["call"](f["client"], child, "directory", "roster", key=helper_key, **SCH04_Y11)[0] == 200

    sup_idx = jwt.decode(supervisor, options={"verify_signature": False})["status"]["status_list"]["idx"]
    cli.revoke_mandate(f["state"], sup_idx)
    status, resp = f["call"](f["client"], child, "directory", "roster", key=helper_key, **SCH04_Y11)
    assert (status, resp["decision"]["reason_code"]) == (403, "APPROVER_REVOKED")


def test_supervisor_approval_ends_with_the_supervisor(flow):
    f = flow
    supervisor, _ = cli.issue_mandate(
        f["state"], cli.priv_from_pem((f["state"] / "agent.pem").read_bytes()).public_key(), scope=roster("SCH04"),
        deny=[], ttl=120, purpose="p", principal=PRINCIPAL, org="o", extra={"clearance": 2, "can_delegate": True},
    )  # fmt: skip
    _, child = _supervised_child(f, supervisor)  # the helper asked for an hour
    exp = lambda t: jwt.decode(t, options={"verify_signature": False})["exp"]  # noqa: E731
    assert exp(child) <= exp(supervisor)


def test_agent_approved_mandate_without_approver_status_is_refused(flow):
    # a minted mandate that says an agent approved it but can't be traced to that agent's status fails closed
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2,
                         approved_by={"kind": "agent", "id": "x", "mandate_jti": "urn:uuid:gone"})  # fmt: skip
    status, resp = f["call"](f["client"], token, "directory", "roster", **SCH04_Y11)
    assert (status, resp["decision"]["reason_code"]) == (403, "STATUS_UNAVAILABLE")


def test_approval_page_shows_what_was_already_approved(flow):
    # ten narrow approvals must not look like ten small asks: the page lists what earlier approvals still grant
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    session = f["login"]()
    first = f["request"](parent, scope=roster("SCH02"))[1]["result"]
    f["decide"](first["request_id"], first["number"], session=session)
    second = f["request"](parent, scope=roster("SCH03"))[1]["result"]

    view = f["ic"].get(f"/requests/{second['request_id']}/view", headers={"x-approver-session": session}).json()
    (earlier,) = view["already_approved"]
    assert earlier["request_id"] == first["request_id"]
    assert "Brookmere High School (SCH02)" in earlier["summary"]
    assert "already_approved" not in f["ic"].get(f"/requests/{second['request_id']}/view").json()

    # once that mandate is revoked it no longer counts
    child = f["call"](f["client"], parent, "grants", "status", request_id=first["request_id"])[1]["result"]["mandate"]
    child_idx = jwt.decode(child, options={"verify_signature": False})["status"]["status_list"]["idx"]
    cli.revoke_mandate(f["state"], child_idx)
    view = f["ic"].get(f"/requests/{second['request_id']}/view", headers={"x-approver-session": session}).json()
    assert view["already_approved"] == []


def test_narrowed_approval_describes_what_was_approved(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    v = f["request"](parent, scope=roster("SCH02"), ttl=7200)[1]["result"]
    assert "for 2 hours" in v["summary"]
    f["decide"](v["request_id"], v["number"], session=f["login"](),
                approved={"scope": roster("SCH02"), "clearance": 2, "ttl": 1800})  # fmt: skip
    result = f["call"](f["client"], parent, "grants", "status", request_id=v["request_id"])[1]["result"]
    assert "for 30 minutes" in result["summary"]
    assert "for 30 minutes" in jwt.decode(result["mandate"], options={"verify_signature": False})["purpose"]


def test_supervisor_cannot_pass_on_what_it_lacks(flow):
    f = flow
    helper_key, _ = generate_keypair()
    helper = f["mandate"](roster("SCH01"), key=helper_key, clearance=4)
    supervisor = f["mandate"](roster("SCH04"), clearance=2, can_delegate=True)
    special = [{"server": "special", "tools": ["record"], "constraints": {"urn": ["SCH04"]}}]
    v = f["request"](helper, key=helper_key, scope=special, clearance=4)[1]["result"]
    status, resp = f["call"](f["client"], supervisor, "grants", "decide", request_id=v["request_id"],
                             decision="approve")  # fmt: skip
    assert (status, resp["decision"]["reason_code"]) == (403, "EXCEEDS_SUPERVISOR")
    assert f["ic"].get(f"/requests/{v['request_id']}/view").json()["status"] == "pending"


def test_agent_cannot_approve_itself(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2, can_delegate=True)
    v = f["request"](token, scope=roster("SCH02"))[1]["result"]
    status, resp = f["call"](f["client"], token, "grants", "decide", request_id=v["request_id"], decision="approve")
    assert (status, resp["decision"]["reason_code"]) == (403, "SELF_APPROVAL")


# ---------------------------------------------------------------- lifecycle and limits


def test_nobody_answers(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    v = f["request"](token, scope=roster("SCH02"))[1]["result"]
    issuer.store()._exec("UPDATE requests SET expires = 0 WHERE id = ?", (v["request_id"],))  # noqa: SLF001
    result = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]
    assert (result["status"], result["next_action"]) == ("expired", "request_again")
    assert "approval_expired" in [e["event_type"] for e in events(jti_of(token))]


def test_someone_elses_request(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    other = f["mandate"](roster("SCH04"), clearance=2)
    status, resp = f["call"](f["client"], other, "grants", "status", request_id=v["request_id"])
    assert (status, resp["decision"]["reason_code"]) == (403, "OUT_OF_SCOPE")
    assert "result" not in resp


def test_asking_again_after_rejection(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    v = f["request"](token, scope=roster("SCH02"))[1]["result"]
    f["decide"](v["request_id"], v["number"], decision="reject", session=f["login"]())
    status, resp = f["request"](token, scope=roster("SCH02"))
    assert (status, resp["decision"]["reason_code"]) == (403, "RECENTLY_REJECTED")


def test_too_many_pending(flow):
    f = flow
    token = f["mandate"](roster("SCH04"), clearance=2)
    for urn in ("SCH01", "SCH02", "SCH03"):
        assert f["request"](token, scope=roster(urn))[0] == 200
    names = [{"server": "directory", "tools": ["name"], "constraints": {"urn": ["SCH02"]}}]
    status, resp = f["request"](token, scope=names)
    assert (status, resp["decision"]["reason_code"]) == (403, "TOO_MANY_REQUESTS")


# ---------------------------------------------------------------- held calls


WRITE = {"pupil_id": "P0011", "urn": "SCH04", "column": "FSMeligible", "value": "1", "reason": "free meals confirmed"}


def _held(f):
    scope = [{"server": "pupil-data", "tools": ["write"], "constraints": {"urn": ["SCH04"]}}]
    token = f["mandate"](scope, deny=[], clearance=4)
    status, resp = f["call"](f["client"], token, "pupil-data", "write", **WRITE)
    assert (status, resp["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL")
    return token, resp["decision"]["decision_id"]


def test_correction_approved_and_applied_once(flow, tmp_path, monkeypatch):
    f = flow
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    monkeypatch.setattr(routes_mcp, "WRITES_PATH", tmp_path / "corrections.jsonl")
    token, did = _held(f)
    held = {"decision_id": did, "server": "pupil-data", "tool": "write", "arguments": WRITE}
    v = f["request"](token, held=held)[1]["result"]
    view = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": f["login"]()}).json()
    assert view["held_action"] == "Change FSMeligible to 1 for pupil P0011 at Dunmore Community College (SCH04)"
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    status, resp = f["call"](f["client"], child, "pupil-data", "write", **WRITE)
    assert (status, resp["decision"]["reason_code"]) == (200, "PREAPPROVED")
    status, resp = f["call"](f["client"], child, "pupil-data", "write", **WRITE)
    assert (status, resp["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL")
    status, _ = f["call"](f["client"], child, "pupil-data", "write", **{**WRITE, "value": "0"})
    assert status == 202
    exp = jwt.decode(child, options={"verify_signature": False})
    assert exp["exp"] - exp["iat"] <= 300


def test_held_call_with_different_arguments(flow):
    f = flow
    token, did = _held(f)
    held = {"decision_id": did, "server": "pupil-data", "tool": "write", "arguments": {**WRITE, "value": "0"}}
    status, resp = f["request"](token, held=held)
    assert (status, resp["decision"]["reason_code"]) == (403, "REQUEST_INVALID")


# ---------------------------------------------------------------- hardening (review findings)


def test_supervisor_cannot_release_a_held_call(flow):
    f = flow
    helper_key, _ = generate_keypair()
    scope = [{"server": "pupil-data", "tools": ["write"], "constraints": {"urn": ["SCH04"]}}]
    helper = f["mandate"](scope, key=helper_key, deny=[], clearance=4)
    supervisor = f["mandate"](scope, deny=[], clearance=4, can_delegate=True)
    _, held = f["call"](f["client"], helper, "pupil-data", "write", key=helper_key, **WRITE)
    did = held["decision"]["decision_id"]
    v = f["request"](
        helper, key=helper_key, held={"decision_id": did, "server": "pupil-data", "tool": "write", "arguments": WRITE}
    )[1]
    rid = v["result"]["request_id"]
    status, resp = f["call"](f["client"], supervisor, "grants", "decide", request_id=rid, decision="approve")
    assert (status, resp["decision"]["reason_code"]) == (403, "EXCEEDS_SUPERVISOR")
    assert f["ic"].get(f"/requests/{rid}/view").json()["status"] == "pending"


def test_signed_decision_is_bound_to_its_request(flow):
    f = flow
    helper_key, _ = generate_keypair()
    helper = f["mandate"](roster("SCH01"), key=helper_key, clearance=2)
    a = f["request"](helper, key=helper_key, scope=roster("SCH04"))[1]["result"]["request_id"]
    b = f["request"](helper, key=helper_key, scope=roster("SCH02"))[1]["result"]["request_id"]
    supervisor = f["mandate"](roster("SCH02") + roster("SCH04"), clearance=2, can_delegate=True)
    signed_for_a = cli.sign_request(cli.priv_from_pem((f["state"] / "agent.pem").read_bytes()), server="grants",
                                    tool="decide", mandate=supervisor,
                                    arguments={"request_id": a, "decision": "approve"})  # fmt: skip
    r = f["ic"].post(f"/internal/requests/{b}/supervisor-decision", json={"call": signed_for_a})
    assert (r.status_code, r.json()["error"]) == (403, "CALL_INVALID")
    assert f["ic"].get(f"/requests/{b}/view").json()["status"] == "pending"


def test_request_id_cannot_smuggle_a_query(flow):
    f = flow
    victim = f["mandate"](roster("SCH04"), clearance=2)
    v = f["request"](victim, scope=roster("SCH02"))[1]["result"]
    attacker = f["mandate"](roster("SCH04"), clearance=2)
    sneaky = f"{v['request_id']}?requester_jti={jti_of(victim)}&x="
    status, resp = f["call"](f["client"], attacker, "grants", "status", request_id=sneaky)
    assert (status, resp["decision"]["reason_code"]) == (403, "REQUEST_INVALID")


def test_supplementary_mandate_cannot_ask_for_more(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    v = f["request"](parent, scope=roster("SCH02"))[1]["result"]
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], parent, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    status, resp = f["request"](child, scope=roster("SCH03"))
    assert (status, resp["decision"]["reason_code"]) == (403, "REQUEST_INVALID")


def test_ceiling_rechecked_at_approval(flow):
    f = flow
    v = f["request"](f["mandate"](roster("SCH04"), clearance=2), scope=roster("SCH02"))[1]["result"]
    narrower = {PRINCIPAL: {**CEILING[PRINCIPAL], "urns": ["SCH04"]}}
    (f["state"] / "principals.json").write_text(json.dumps(narrower))  # the person lost Brookmere meanwhile
    r = f["decide"](v["request_id"], v["number"], session=f["login"]())
    assert (r.status_code, r.json()["error"]) == (403, "EXCEEDS_PRINCIPAL")
    assert f["ic"].get(f"/requests/{v['request_id']}/view").json()["status"] == "pending"


def test_check_gives_the_safe_counts_answer(flow):
    f = flow
    scope = [{"server": "pupil-data", "tools": ["aggregate"],
              "constraints": {"table": ["personal_data_school_census"]}}]  # fmt: skip
    token = f["mandate"](scope, clearance=4)
    arguments = {"table": "personal_data_school_census", "group_by": ["Psuedo ID"], "measure": "InCareAtCurrentSchool"}
    _, checked = f["call"](f["client"], token, "grants", "check",
                           args={"server": "pupil-data", "tool": "aggregate", "arguments": arguments})  # fmt: skip
    status, real = f["call"](f["client"], token, "pupil-data", "aggregate", args=arguments)
    assert status == 403
    assert checked["result"]["reason_code"] == real["decision"]["reason_code"]
    assert checked["result"]["decision"] == "DENY"


def test_minted_mandate_shares_the_parents_budget_and_rate(flow):
    """run budgets count per family but read their size from the calling mandate (add-run-budgets)."""
    f = flow
    scope = [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02", "SCH04"]},
              "rate": {"per_minute": 5, "max_calls": 50}}]  # fmt: skip
    parent = f["mandate"](scope, clearance=2, budget={"distinct_pupils": 40})
    v = f["request"](parent, scope=roster("SCH02") + roster("SCH01"), clearance=2)[1]["result"]
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], parent, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    claims = jwt.decode(child, options={"verify_signature": False})
    assert claims["budget"] == {"distinct_pupils": 40}
    by_urn = {e["constraints"]["urn"][0]: e for e in claims["scope"]}
    assert by_urn["SCH02"]["rate"] == {"per_minute": 5, "max_calls": 50}  # narrows a parent entry: keeps its rate
    assert "rate" not in by_urn["SCH01"]  # new access: no parent entry to inherit from


# ---------------------------------------------------------------- reuse within a run (add-run-reuse)


def _approve(f, parent, scope, clearance=None):
    args = {"scope": scope} | ({"clearance": clearance} if clearance else {})
    v = f["request"](parent, **args)[1]["result"]
    assert v["status"] == "pending", v
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    minted = f["call"](f["client"], parent, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    return v["request_id"], minted


def _pending(f, parent):
    return f["call"](f["client"], parent, "grants", "self")[1]["result"]["pending_requests"]


def test_asking_again_in_the_run_reuses_the_approval(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    rid, minted = _approve(f, parent, roster("SCH02"))
    requested_before = [e for e in events(jti_of(parent)) if e["event_type"] == "approval_requested"]

    status, resp = f["request"](parent, scope=roster("SCH02"))  # the agent restarted and lost the mandate
    result = resp["result"]
    assert status == 200
    assert (result["status"], result["next_action"]) == ("already_granted", "retry")
    assert (result["mandate"], result["mandate_jti"], result["reused_request_id"]) == (minted, jti_of(minted), rid)
    assert _pending(f, parent) == []
    requested_after = [e for e in events(jti_of(parent)) if e["event_type"] == "approval_requested"]
    assert len(requested_after) == len(requested_before)  # the person wasn't asked again
    assert f["call"](f["client"], result["mandate"], "directory", "roster", **SCH02_Y11)[0] == 200


def test_a_narrower_ask_is_covered_by_the_earlier_approval(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    wide = [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02", "SCH03"]}}]
    rid, minted = _approve(f, parent, wide)
    result = f["request"](parent, scope=roster("SCH02"))[1]["result"]
    assert (result["status"], result["reused_request_id"], result["mandate"]) == ("already_granted", rid, minted)


def test_a_wider_ask_or_higher_clearance_still_asks(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    _approve(f, parent, roster("SCH02"))
    wider = [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02", "SCH03"]}}]
    assert f["request"](parent, scope=wider)[1]["result"]["status"] == "pending"
    higher = f["request"](parent, scope=roster("SCH02"), clearance=4)[1]["result"]
    assert higher["status"] == "pending"


def test_a_revoked_approval_is_not_reused(flow):
    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    _, minted = _approve(f, parent, roster("SCH02"))
    idx = jwt.decode(minted, options={"verify_signature": False})["status"]["status_list"]["idx"]
    cli.revoke_mandate(f["state"], idx)
    result = f["request"](parent, scope=roster("SCH02"))[1]["result"]
    assert result["status"] == "pending"


def test_a_new_run_asks_again(flow):
    f = flow
    first = f["mandate"](roster("SCH04"), clearance=2)
    _approve(f, first, roster("SCH02"))
    second = f["mandate"](roster("SCH04"), clearance=2)  # the next job: a new base mandate, same agent key
    assert f["request"](second, scope=roster("SCH02"))[1]["result"]["status"] == "pending"


def test_a_released_held_call_is_not_reused(flow, tmp_path, monkeypatch):
    f = flow
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    monkeypatch.setattr(routes_mcp, "WRITES_PATH", tmp_path / "corrections.jsonl")
    token, did = _held(f)
    held = {"decision_id": did, "server": "pupil-data", "tool": "write", "arguments": WRITE}
    v = f["request"](token, held=held)[1]["result"]
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    again = f["request"](token, held=held)[1]["result"]
    assert again["status"] == "pending"
    assert again["request_id"] != v["request_id"]


def test_run_wallet_keeps_approvals_across_a_restart(flow, tmp_path):
    from examples.mandate_wallet import RunWallet  # noqa: PLC0415

    f = flow
    parent = f["mandate"](roster("SCH04"), clearance=2)
    _, minted = _approve(f, parent, roster("SCH02"))
    wallet = RunWallet.load(tmp_path / "run_wallet.json", parent)
    assert wallet.pick("directory", "roster", SCH02_Y11) == parent  # nothing held yet: the base mandate
    assert wallet.absorb({"status": "approved", "mandate": minted})
    wallet.save()

    restarted = RunWallet.load(tmp_path / "run_wallet.json", parent)  # the agent restarts
    chosen = restarted.pick("directory", "roster", SCH02_Y11)
    assert chosen == minted
    assert f["call"](f["client"], chosen, "directory", "roster", **SCH02_Y11)[0] == 200
    assert restarted.pick("directory", "roster", SCH04_Y11) == parent  # the base covers its own school

    other_run = RunWallet.load(tmp_path / "run_wallet.json", f["mandate"](roster("SCH04"), clearance=2))
    assert other_run.valid() == []  # a new base mandate starts empty
    assert not other_run.add(minted)  # and won't take another run's mandate


# ---------------------------------------------------------------- several held calls, one approval (add-batch-release)

DRAFT_SCOPE = [{"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": ["SCH04"]}}]


def _pupils_at_sch04(n):
    from gateway.tests.test_budgets import pupils_currently_at  # noqa: PLC0415

    return pupils_currently_at("SCH04", n)


def _held_draft(f, token, pupils):
    args = {"urn": "SCH04", "pupil_ids": pupils, "kind": "absence"}
    status, resp = f["call"](f["client"], token, "pupil-data", "draft", **args)
    assert (status, resp["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL")
    return {"decision_id": resp["decision"]["decision_id"], "server": "pupil-data", "tool": "draft", "arguments": args}


def test_several_held_calls_are_released_with_one_approval(flow):
    f = flow
    token = f["mandate"](DRAFT_SCOPE, deny=[], clearance=4)
    pupils = _pupils_at_sch04(3)
    held = [_held_draft(f, token, [p]) for p in pupils]  # the agent drafted one pupil at a time

    v = f["request"](token, held=held)[1]["result"]
    assert v["status"] == "pending"
    assert _pending(f, token) == [_pending(f, token)[0]]  # one request, one prompt
    view = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": f["login"]()}).json()
    assert len(view["held_actions"]) == 3
    assert view["held_action"] is None
    assert all("Draft absence letters" in a for a in view["held_actions"])
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    assert len(jwt.decode(child, options={"verify_signature": False})["preapproved"]) == 3

    for h in held:  # each released call goes through once
        status, resp = f["call"](f["client"], child, "pupil-data", "draft", **h["arguments"])
        assert (status, resp["decision"]["reason_code"]) == (200, "PREAPPROVED")
    status, resp = f["call"](f["client"], child, "pupil-data", "draft", **held[0]["arguments"])
    assert (status, resp["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL")  # not twice
    other = {"urn": "SCH04", "pupil_ids": _pupils_at_sch04(4)[3:], "kind": "absence"}
    assert f["call"](f["client"], child, "pupil-data", "draft", **other)[0] == 202  # nor one that wasn't approved


def test_twenty_five_pupils_in_one_draft_are_one_approval(flow):
    f = flow
    token = f["mandate"](DRAFT_SCOPE, deny=[], clearance=4)
    pupils = _pupils_at_sch04(25)
    held = _held_draft(f, token, pupils)
    v = f["request"](token, held=held)[1]["result"]
    view = f["ic"].get(f"/requests/{v['request_id']}/view", headers={"x-approver-session": f["login"]()}).json()
    assert all(p in view["held_action"] for p in pupils)  # the person sees every pupil before approving
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    status, resp = f["call"](f["client"], child, "pupil-data", "draft", **held["arguments"])
    assert (status, resp["decision"]["reason_code"]) == (200, "PREAPPROVED")
    assert sorted(r["Psuedo ID"] for r in resp["result"]) == sorted(pupils)


def test_a_batch_must_be_held_calls_of_this_mandate(flow):
    f = flow
    token = f["mandate"](DRAFT_SCOPE, deny=[], clearance=4)
    one = _held_draft(f, token, _pupils_at_sch04(1))
    for held, problem in (
        ([one, one], "named twice"),
        ([one, {**one, "decision_id": "not-a-held-call"}], "no held call"),
        ([one] * 51, "1 to 50"),
        ([], "1 to 50"),
    ):
        status, resp = f["request"](token, held=held)
        assert (status, resp["decision"]["reason_code"]) == (403, "REQUEST_INVALID"), held
        assert problem in resp["decision"]["detail"]


def test_the_agent_is_told_to_batch(flow):
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    f = flow
    tools = {t["name"]: t for t in f["client"].get("/describe").json()["servers"]["pupil-data"]}
    assert "Put every pupil in one call" in tools["draft"]["description"]
    assert "list of up to 50" in grants.GRANTS_TOOLS["request"]
    token = f["mandate"](DRAFT_SCOPE, deny=[], clearance=4)
    held_call = {"server": "pupil-data", "tool": "draft", "arguments": {"urn": "SCH04", "pupil_ids": ["P0011"]}}
    check = f["call"](f["client"], token, "grants", "check", args=held_call)[1]["result"]
    assert "one list" in check["missing"]["held"]
    assert routes_mcp  # the tool module is the one the gateway forwards to


def test_special_category_read_released_once(flow):
    """add-graded-pupil-data: a level 4 read at clearance 4 is held, and approval releases it exactly once."""
    f = flow
    scope = [{"server": "pupil-data", "tools": ["pupil"], "constraints": {"urn": ["SCH04"]}}]
    token = f["mandate"](scope, clearance=4)
    args = {"pupil_id": "P0011", "urn": "SCH04"}
    status, resp = f["call"](f["client"], token, "pupil-data", "pupil", **args)
    assert (status, resp["decision"]["reason_code"]) == (202, "SPECIAL_CATEGORY")
    held = {"decision_id": resp["decision"]["decision_id"], "server": "pupil-data", "tool": "pupil", "arguments": args}
    v = f["request"](token, held=held)[1]["result"]
    f["decide"](v["request_id"], v["number"], session=f["login"]())
    child = f["call"](f["client"], token, "grants", "status", request_id=v["request_id"])[1]["result"]["mandate"]
    status, resp = f["call"](f["client"], child, "pupil-data", "pupil", **args)
    assert (status, resp["decision"]["reason_code"]) == (200, "PREAPPROVED")
    assert "Ethnicity" in resp["result"]
    status, resp = f["call"](f["client"], child, "pupil-data", "pupil", **args)
    assert (status, resp["decision"]["reason_code"]) == (202, "SPECIAL_CATEGORY")


def test_check_suggests_the_mandates_own_clearance_for_pupil_data(flow):
    f = flow
    token = f["mandate"](
        [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH04"]}}], clearance=2
    )
    check = {"server": "pupil-data", "tool": "search", "arguments": {"query": "P0011", "urn": "SCH02"}}
    _, resp = f["call"](f["client"], token, "grants", "check", args=check)
    missing = resp["result"]["missing"]
    assert missing["clearance"] == 2  # not 4: that would hold every read
    assert "lowest clearance" in missing["note"]
