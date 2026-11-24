"""Gateway authentication checks using temporary keys and an in-process fixture server."""

import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient
from fastmcp import FastMCP

from gateway import cli, main
from gateway.lib.common import b64u, generate_keypair, priv_from_pem, priv_to_pem, sign_bytes
from gateway.lib.gateway_verify import Request


@pytest.fixture
def isolated_gateway(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    agent, _ = generate_keypair()

    def issue(ttl=3600):
        return cli.issue_mandate(
            state,
            agent.public_key(),
            scope=cli.DEFAULT_SCOPE,
            deny=cli.DEFAULT_DENY,
            ttl=ttl,
            purpose="offline authentication eval",
            principal="eval:fixture",
            org="school:SCH01",
            extra={"clearance": 4},
        )

    token, idx = issue()
    upstream_calls = []
    upstream = FastMCP("offline fixture")

    @upstream.tool
    def get(path: str) -> list[dict]:
        upstream_calls.append(path)
        return [{"URN": "SCH01"}]

    @upstream.tool
    def search(query: str, urn: str) -> list[dict]:
        upstream_calls.append(("search", query, urn))
        if (query, urn) == ("P0011", "SCH04"):
            return [{"Psuedo ID": "P0011", "URN": "SCH04", "Ethnicity": "ASIA"}]
        return []

    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setattr(main, "state", {})
    monkeypatch.setattr(main, "MCP_SERVERS", {"pupil-data": upstream})
    with TestClient(main.app, raise_server_exceptions=False) as client:
        yield client, state, agent, token, idx, issue, upstream_calls


def signed_get(agent, token):
    return cli.sign_request(
        agent,
        server="pupil-data",
        tool="get",
        arguments={"path": "synthetic/synthetic_schools.csv"},
        mandate=token,
    )


@pytest.mark.parametrize(
    "attack",
    ["missing-signature", "bad-signature", "wrong-key", "replay", "stale", "future", "changed-arguments"],
)
def test_no_key_requests_are_denied_before_forwarding(isolated_gateway, attack):
    client, _, agent, token, _, _, calls = isolated_gateway
    # A working authorized request prevents a gateway which denies everything from passing.
    body = signed_get(agent, token)
    assert client.post("/tools/call", json=body).status_code == 200
    baseline = len(calls)
    if attack != "replay":
        body = signed_get(agent, token)
    if attack == "missing-signature":
        body["sig"] = ""
    if attack == "bad-signature":
        body["sig"] = b64u(bytes(64))
    if attack == "wrong-key":
        other, _ = generate_keypair()
        body["sig"] = sign_bytes(other, Request(**body).signing_input())
    if attack in ("stale", "future"):
        body["ts"] = int(time.time()) + (600 if attack == "future" else -600)
        body["sig"] = sign_bytes(agent, Request(**body).signing_input())
    if attack == "changed-arguments":
        body["arguments"]["limit"] = 1
    response = client.post("/tools/call", json=body)
    assert (response.status_code, response.json()["decision"]["reason_code"]) == (403, "POP_FAILED")
    assert len(calls) == baseline


@pytest.mark.parametrize("condition", ["expired", "revoked"])
def test_dead_mandates_are_denied_before_forwarding(isolated_gateway, condition):
    client, state, agent, token, idx, issue, calls = isolated_gateway
    assert client.post("/tools/call", json=signed_get(agent, token)).status_code == 200
    baseline = len(calls)
    if condition == "expired":
        token, _ = issue(ttl=-120)
    else:
        cli.revoke_mandate(state, idx)
    response = client.post("/tools/call", json=signed_get(agent, token))
    assert (response.status_code, response.json()["decision"]["reason_code"]) == (403, condition.upper())
    assert len(calls) == baseline


@pytest.mark.parametrize("attack", ["edited-claims", "untrusted-issuer"])
def test_unauthorized_mandates_are_denied_before_forwarding(isolated_gateway, attack):
    client, _, agent, token, _, _, calls = isolated_gateway
    assert client.post("/tools/call", json=signed_get(agent, token)).status_code == 200
    baseline = len(calls)
    claims = jwt.decode(token, options={"verify_signature": False})
    if attack == "edited-claims":
        header, _, signature = token.split(".")
        claims["clearance"] = 1
        token = ".".join([header, b64u(json.dumps(claims).encode()), signature])
        expected = "SIG_INVALID"
    else:
        other, _ = generate_keypair()
        claims["iss"] = "https://untrusted.invalid"
        token = jwt.encode(claims, priv_to_pem(other), algorithm="EdDSA", headers={"typ": "mandate+jwt"})
        expected = "ISSUER_NOT_ACCREDITED"
    response = client.post("/tools/call", json=signed_get(agent, token))
    assert (response.status_code, response.json()["decision"]["reason_code"]) == (403, expected)
    assert len(calls) == baseline


@pytest.mark.parametrize("path", ["/describe", "/demo/issuer", "/demo/trust"])
def test_discovery_responses_keep_issuer_private_key_private(isolated_gateway, path):
    client, state, _, _, _, _, _ = isolated_gateway
    response = client.get(path)
    # the demo routes are not mounted by default; when they are, they must still hide the key
    assert response.status_code == (404 if path.startswith("/demo/") and not main.DEMO_ENABLED else 200)
    issuer = priv_from_pem((state / "issuer_key.pem").read_bytes())
    # Check both the actual PEM and the raw Ed25519 private component, including JWK form.
    assert (state / "issuer_key.pem").read_text().strip() not in response.text
    assert b64u(issuer.private_bytes_raw()) not in response.text


def test_public_demo_routes_cannot_mint_or_use_an_out_of_scope_mandate(isolated_gateway):
    client, _, _, _, _, _, calls = isolated_gateway
    baseline = len(calls)
    issued = client.post("/demo/mandate", json={"urn": "SCH04", "tools": ["search"], "clearance": 4})
    assert issued.status_code in (401, 403, 404)
    response = client.post(
        "/demo/call",
        json={"tool": "search", "arguments": {"query": "P0011", "urn": "SCH04"}},
    )
    assert response.status_code in (401, 403, 404)
    assert client.post("/demo/revoke", json={"idx": 0}).status_code in (401, 403, 404)
    assert len(calls) == baseline


@pytest.mark.parametrize("mandate", ["", "not-a-jwt", "a.b.c"])
def test_malformed_mandate_returns_a_denial_instead_of_http_500(isolated_gateway, mandate):
    client, _, agent, _, _, _, calls = isolated_gateway
    baseline = len(calls)
    response = client.post("/tools/call", json=signed_get(agent, mandate))
    assert response.status_code == 403
    assert response.json()["decision"]["decision"] == "DENY"
    assert len(calls) == baseline


def test_replayed_request_is_denied_after_gateway_state_reload(isolated_gateway):
    client, state, agent, token, _, _, calls = isolated_gateway
    body = signed_get(agent, token)
    first = client.post("/tools/call", json=body)
    assert first.status_code == 200
    baseline = len(calls)
    main.load_state(state)
    replay = client.post("/tools/call", json=body)
    assert (replay.status_code, replay.json()["decision"]["reason_code"]) == (403, "POP_FAILED")
    assert len(calls) == baseline
