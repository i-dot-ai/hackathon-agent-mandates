"""The local MCP shim (OpenSpec add-scope-requests, task 7.1): an agent asks for more, a person approves, it retries."""

import types

import jwt

from examples import mandate_wallet
from examples.mandate_wallet import RunWallet
from gateway import cli
from gateway.shim import Shim
from gateway.tests import test_scope_requests
from gateway.tests.test_scope_requests import SCH02_Y11, SCH04_Y11, WRITE, roster

flow = test_scope_requests.flow  # the gateway, issuer and approver fixture, shared with the scope-request tests


def gateway_post(f):
    def post(body):
        r = f["client"].post("/tools/call", json=body)
        return r.status_code, r.json()

    return post


def shim_for(f, mandate: str, post=None, wallet_path=None, **kw) -> Shim:
    agent = cli.priv_from_pem((f["state"] / "agent.pem").read_bytes())
    wallet = RunWallet.load(wallet_path or f["state"] / f"wallet-{id(mandate)}.json", mandate)
    return Shim(agent, wallet, post or gateway_post(f), **kw)


def approve(f, view, approved=None):
    r = f["decide"](view["request_id"], view["number"], session=f["login"](), approved=approved)
    assert r.status_code == 200, r.text


def test_refused_roster_leads_to_a_request_an_approval_and_a_retry(flow):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))

    refused = shim.call("directory", "roster", SCH02_Y11)
    assert (refused["status"], refused["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")
    assert "check_access" in refused["next_step"]

    check = shim.check_access("directory", "roster", SCH02_Y11)
    assert check["decision"] == "DENY"
    missing = check["missing"]["scope"]
    assert missing == [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02"]}}]

    asked = shim.request_scopes(scope=missing, reason="absence letters for Brookmere", ttl=1800)
    assert asked["status"] == "pending"
    assert f"choose {asked['number']}" in asked["text"]
    assert "does not approve" in asked["text"]

    approve(f, asked)
    done = shim.await_approval(asked["request_id"], timeout_s=5)
    assert (done["status"], done["next_action"]) == ("approved", "retry")
    assert "mandate" not in done  # the shim keeps the JWT; the agent never handles it

    retried = shim.call("directory", "roster", SCH02_Y11)
    assert (retried["status"], retried["decision"]["reason_code"]) == (200, "IN_SCOPE")
    assert retried["mandate"] == done["mandate_jti"]
    assert retried["result"]
    # the base mandate still serves its own school
    assert shim.call("directory", "roster", SCH04_Y11)["mandate"] == "base"


def test_check_access_sees_supplementary_mandates(flow):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))
    asked = shim.request_scopes(scope=roster("SCH02"), reason="letters")
    approve(f, asked)
    done = shim.await_approval(asked["request_id"], timeout_s=5)
    check = shim.check_access("directory", "roster", SCH02_Y11)
    assert (check["decision"], check["mandate"]) == ("ALLOW", done["mandate_jti"])


def test_my_grants_lists_base_and_supplementary(flow):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))
    assert shim.my_grants()["supplementary"] == []
    asked = shim.request_scopes(scope=roster("SCH02"), reason="letters")
    approve(f, asked)
    shim.await_approval(asked["request_id"], timeout_s=5)
    grants = shim.my_grants()
    assert "Dunmore Community College (SCH04)" in grants["base"]["summary"]
    (extra,) = grants["supplementary"]
    assert "Brookmere High School (SCH02)" in extra["purpose"]


def test_await_approval_gives_up_while_pending(flow):
    f = flow
    clock = {"t": 0.0}
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2),
                    sleep=lambda s: clock.__setitem__("t", clock["t"] + s), now=lambda: clock["t"])  # fmt: skip
    asked = shim.request_scopes(scope=roster("SCH02"), reason="letters")
    waited = shim.await_approval(asked["request_id"], timeout_s=25)
    assert (waited["status"], waited["next_action"]) == ("pending", "ask_user")
    assert clock["t"] >= 25


def test_rejected_request_says_stop(flow):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))
    asked = shim.request_scopes(scope=roster("SCH02"), reason="letters")
    f["decide"](asked["request_id"], asked["number"], decision="reject", session=f["login"]())
    done = shim.await_approval(asked["request_id"], timeout_s=5)
    assert (done["status"], done["next_action"]) == ("rejected", "stop")
    assert shim.my_grants()["supplementary"] == []


def test_expired_supplementary_mandates_are_dropped(flow, monkeypatch):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))
    asked = shim.request_scopes(scope=roster("SCH02"), reason="letters")
    approve(f, asked)
    shim.await_approval(asked["request_id"], timeout_s=5)
    assert len(shim.my_grants()["supplementary"]) == 1
    # long after every mandate's expiry, by the wallet's clock
    monkeypatch.setattr(mandate_wallet, "time", types.SimpleNamespace(time=lambda: 1e12))
    assert shim.my_grants()["supplementary"] == []


def test_approvals_survive_a_restart(flow):
    f = flow
    base = f["mandate"](roster("SCH04"), clearance=2)
    path = f["state"] / "restart-wallet.json"
    first = shim_for(f, base, wallet_path=path)
    asked = first.request_scopes(scope=roster("SCH02"), reason="letters")
    approve(f, asked)
    first.await_approval(asked["request_id"], timeout_s=5)

    restarted = shim_for(f, base, wallet_path=path)  # a new process, same wallet file
    retried = restarted.call("directory", "roster", SCH02_Y11)
    assert (retried["status"], retried["decision"]["reason_code"]) == (200, "IN_SCOPE")
    assert retried["mandate"] != "base"


def test_reused_approval_is_kept_and_never_shown(flow):
    # run reuse (add-run-reuse, on main): grants.request answers already_granted with the earlier mandate in it
    f = flow
    base = f["mandate"](roster("SCH04"), clearance=2)
    earlier = shim_for(f, base, wallet_path=f["state"] / "earlier.json")
    asked = earlier.request_scopes(scope=roster("SCH02"), reason="letters")
    approve(f, asked)
    done = earlier.await_approval(asked["request_id"], timeout_s=5)
    (minted,) = earlier.wallet.valid()

    real = gateway_post(f)

    def reusing_post(body):
        if (body["server"], body["tool"]) == ("grants", "request"):
            return 200, {"decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE"}, "result": {
                "status": "already_granted", "next_action": "retry", "mandate": minted,
                "mandate_jti": done["mandate_jti"], "reused_request_id": asked["request_id"]}}  # fmt: skip
        return real(body)

    fresh = shim_for(f, base, post=reusing_post, wallet_path=f["state"] / "fresh.json")
    reused = fresh.request_scopes(scope=roster("SCH02"), reason="letters again")
    assert reused["status"] == "already_granted"
    assert "mandate" not in reused
    assert minted not in repr(reused)
    assert reused["mandate_jti"] == done["mandate_jti"]
    assert fresh.call("directory", "roster", SCH02_Y11)["status"] == 200


def test_several_held_calls_released_by_one_approval(flow):
    # batch release (add-batch-release): two held drafts, one request, one approval, each released once
    f = flow
    scope = [{"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": ["SCH04"]}}]
    shim = shim_for(f, f["mandate"](scope, deny=[], clearance=2))
    drafts = [{"urn": "SCH04", "pupil_ids": ["P0011"]}, {"urn": "SCH04", "pupil_ids": ["P0012"]}]
    held = []
    for args in drafts:
        out = shim.call("pupil-data", "draft", args)
        assert (out["status"], out["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL")
        held.append(out["held"])

    asked = shim.request_scopes(held=held, reason="absence letters for both")
    assert asked["status"] == "pending"
    approve(f, asked)
    assert shim.await_approval(asked["request_id"], timeout_s=5)["status"] == "approved"

    for args in drafts:
        released = shim.call("pupil-data", "draft", args)
        assert (released["status"], released["decision"]["reason_code"]) == (200, "PREAPPROVED")
    assert shim.call("pupil-data", "draft", drafts[0])["status"] == 202  # once each


def test_mcp_request_scopes_accepts_a_list_of_held_calls(flow):
    import asyncio  # noqa: PLC0415

    from fastmcp import Client  # noqa: PLC0415

    from gateway.shim import build_server  # noqa: PLC0415

    f = flow
    seen = []
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2),
                    post=lambda body: (seen.append(body), (200, {"result": {"status": "pending"}}))[1])  # fmt: skip
    held = [{"decision_id": "d1", "server": "pupil-data", "tool": "draft", "arguments": {"urn": "SCH04"}}]

    async def run():
        async with Client(build_server(shim)) as client:
            return (await client.call_tool("request_scopes", {"reason": "r", "held": held})).data

    assert asyncio.run(run())["status"] == "pending"
    assert seen[-1]["arguments"]["held"] == held


def test_held_call_released_once_through_the_shim(flow, tmp_path, monkeypatch):
    f = flow
    from mcp_server.api import routes_mcp  # noqa: PLC0415

    monkeypatch.setattr(routes_mcp, "WRITES_PATH", tmp_path / "corrections.jsonl")
    scope = [{"server": "pupil-data", "tools": ["write"], "constraints": {"urn": ["SCH04"]}}]
    shim = shim_for(f, f["mandate"](scope, deny=[], clearance=4))

    held = shim.call("pupil-data", "write", WRITE)
    assert (held["status"], held["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL")
    assert held["held"] == {"decision_id": held["decision"]["decision_id"], "server": "pupil-data",
                            "tool": "write", "arguments": WRITE}  # fmt: skip

    asked = shim.request_scopes(held=held["held"], reason="the person asked for this correction")
    approve(f, asked)
    shim.await_approval(asked["request_id"], timeout_s=5)
    released = shim.call("pupil-data", "write", WRITE)
    assert (released["status"], released["decision"]["reason_code"]) == (200, "PREAPPROVED")
    again = shim.call("pupil-data", "write", WRITE)
    assert again["status"] == 202


def test_mcp_server_offers_the_tools(flow):
    import asyncio  # noqa: PLC0415

    from fastmcp import Client  # noqa: PLC0415

    from gateway.shim import build_server  # noqa: PLC0415

    f = flow
    server = build_server(shim_for(f, f["mandate"](roster("SCH04"), clearance=2)))

    async def run():
        async with Client(server) as client:
            names = {t.name for t in await client.list_tools()}
            refused = await client.call_tool("call", {"server": "directory", "tool": "roster", "arguments": SCH02_Y11})
            return names, refused.data

    names, refused = asyncio.run(run())
    assert names == {"call", "my_grants", "check_access", "request_scopes", "await_approval"}
    assert refused["decision"]["reason_code"] == "CONSTRAINT_VIOLATED"


def test_mandates_stay_inside_the_shim(flow):
    f = flow
    base = f["mandate"](roster("SCH04"), clearance=2)
    shim = shim_for(f, base)
    for result in (shim.call("directory", "roster", SCH04_Y11), shim.my_grants(), shim.check_access(
            "directory", "roster", SCH02_Y11)):  # fmt: skip
        assert base not in repr(result)
    assert jwt.decode(base, options={"verify_signature": False})["jti"] == shim.my_grants()["base"]["jti"]


def test_asking_beyond_the_principal_says_what_to_do(flow):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))
    asked = shim.request_scopes(scope=roster("SCH09"), reason="letters")
    assert (asked["status"], asked["reason_code"]) == ("refused", "EXCEEDS_PRINCIPAL")
    assert "Don't ask again" in asked["next_step"]


def test_an_unknown_refusal_still_has_a_next_step(flow):
    f = flow
    shim = shim_for(f, f["mandate"](roster("SCH04"), clearance=2))
    waited = shim.await_approval("urn:uuid:not-a-request", timeout_s=0)
    assert waited["status"] == "refused"
    assert waited["next_step"]
