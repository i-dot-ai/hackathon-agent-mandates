"""Shared fixtures for add-scope-requests tests: a fresh issuer state, in-process upstreams, a signing caller."""

import pytest
from fastapi.testclient import TestClient

from data_slices import directory, schools, special
from gateway import cli, main
from gateway.lib.common import priv_from_pem
from mcp_server.api.routes_mcp import mcp as pupil_data


@pytest.fixture
def stack(tmp_path, monkeypatch):
    """(client, mandate(scope, deny=..., **claims), call(client, token, server, tool, **args), state dir)."""
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "mandate.jwt")]
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    upstreams = {
        "pupil-data": pupil_data,
        "schools": schools.mcp,
        "directory": directory.mcp,
        "special": special.mcp,
    }
    for name, server in upstreams.items():
        monkeypatch.setitem(main.MCP_SERVERS, name, server)
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())

    def mandate(scope, deny=("*.write", "pii.*"), key=None, principal="officer:test", **claims):
        token, _ = cli.issue_mandate(
            state,
            (key or agent_priv).public_key(),
            scope=scope,
            deny=list(deny),
            ttl=600,
            purpose="scope requests test",
            principal=principal,
            org="school:SCH04",
            extra=claims,
        )
        return token

    def call(client, token, server, tool, *, key=None, args=None, **arguments):
        """`args` passes the tool's arguments as one dict, for tools whose arguments are named server or tool."""
        arguments = args if args is not None else arguments
        body = cli.sign_request(key or agent_priv, server=server, tool=tool, arguments=arguments, mandate=token)
        r = client.post("/tools/call", json=body)
        return r.status_code, r.json()

    with TestClient(main.app) as client:
        yield client, mandate, call, state
