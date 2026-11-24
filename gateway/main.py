"""HTTP wrapper around the gateway pipeline.

POST /tools/call  {server, tool, arguments, mandate, nonce, ts, sig}
  -> verify mandate + proof of possession (gateway/lib/gateway_verify.py)
  -> label what the call could return; refuse before forwarding if that is above the mandate's clearance
  -> ALLOW: forward to the MCP server, check the result's labels again, DENY: 403, STEP_UP: 202
Every decision is appended to the audit log.
"""

import json
import os
import sys
import time
import traceback
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi import Request as HttpRequest
from fastapi.responses import JSONResponse
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import BaseModel

from gateway.cli import sign_request
from gateway.lib.common import generate_keypair, pub_to_jwk
from gateway.lib.gateway_verify import (
    IDENTIFIERS,
    MIN_QUERY,
    PRIVATE_LEVEL,
    PRIVATE_ROLES,
    SMALL_COUNT,
    Decision,
    Gateway,
    Request,
    request_levels,
    result_levels,
    round_counts,
    sensitivity_maps,
    sensitivity_record,
    suppress_small_groups,
)
from gateway.lib.nonce_store import SqliteNonces
from gateway.lib.trust_registry import TrustedList

STATE_DIR = Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state"))
_CLASSIFICATION_CANDIDATES = [
    os.environ.get("CLASSIFICATION_MANIFEST", ""),
    "gateway/manifest.json",
    "mcp_server/data/synthetic/synthetic_manifest.json",
]
# name -> URL (or an in-process FastMCP instance in tests); fastmcp.Client accepts both
MCP_SERVERS: dict[str, object] = dict(
    kv.split("=", 1) for kv in os.environ.get("MCP_SERVERS", "pupil-data=http://backend:8080/mcp/").split(",")
)
# The demo routes mint, sign and revoke mandates with no authentication. Local walkthrough only: never set this
# on a deployed gateway.
DEMO_ENABLED = os.environ.get("GATEWAY_DEMO") == "1"
HTTP_OK = 200
state: dict = {}


class CallBody(BaseModel):
    server: str
    tool: str
    arguments: dict
    mandate: str
    nonce: str
    ts: int
    sig: str


def load_state(state_dir: Path) -> None:
    registry = TrustedList(json.loads((state_dir / "trusted_list.json").read_text()))
    # nonces live in a file, so a replay fails after a restart and across workers on one host
    state["gateway"] = Gateway(registry, status_lists={}, nonces=SqliteNonces(state_dir / "nonces.sqlite"))
    state["status_uri"] = json.loads((state_dir / "status_list.json").read_text())["uri"]
    state["dir"] = state_dir
    # Q6 labels live with the data; the gateway enforces them before the call and against the result
    load_labels()
    state["small_count"] = small_count_setting()
    state["private_roles"] = private_roles_setting()


def small_count_setting() -> int:
    value = int(os.environ.get("GATEWAY_SMALL_COUNT", SMALL_COUNT))
    if value < 1:
        msg = f"GATEWAY_SMALL_COUNT must be at least 1, got {value}"
        raise ValueError(msg)
    return value


def private_roles_setting() -> frozenset[str]:
    raw = os.environ.get("GATEWAY_PRIVATE_ROLES")
    roles = PRIVATE_ROLES if raw is None else frozenset(filter(None, map(str.strip, raw.split(","))))
    if not roles:
        msg = "GATEWAY_PRIVATE_ROLES must name at least one role"
        raise ValueError(msg)
    return roles


def load_labels() -> None:
    """Read the first manifest found. Called on each forwarded call too, so a changed label needs no restart.

    At startup a missing or broken manifest stops the gateway. Later, the last good labels stay in force and the
    error is reported, so a bad edit or a lost mount cannot turn every call into a 500.
    """
    try:
        manifest = next((Path(p) for p in _CLASSIFICATION_CANDIDATES if p and Path(p).is_file()), None)
        if manifest is None:
            msg = f"no classification manifest under {_CLASSIFICATION_CANDIDATES}"
            raise FileNotFoundError(msg)
        classification = json.loads(manifest.read_text())["classification"]
        columns, tables = sensitivity_maps(classification)
        labels = {
            "columns": columns,
            "tables": tables,
            "table_columns": classification["columns"],
            "max_level": max(map(int, classification["levels"])),
            "level_names": {int(level): name for level, name in classification["levels"].items()},
            "labels_file": str(manifest),
        }
    except (OSError, ValueError, KeyError, TypeError) as e:
        if "columns" not in state:
            raise
        state["labels_error"] = f"{type(e).__name__}: {e}"
        sys.stderr.write(f"gateway: labels unavailable, keeping the last good copy ({state['labels_error']})\n")
        return
    state.update(labels)
    state.pop("labels_error", None)


# ---------------------------------------------------------------- audit log


def audit_path() -> Path:
    return Path(os.environ.get("GATEWAY_AUDIT_LOG", state["dir"] / "audit.jsonl"))


def audit(line: dict) -> None:
    """Append one decision. A failed write is reported, not raised: the caller's answer is already decided."""
    try:
        with audit_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": time.time(), **line}, default=str) + "\n")
    except (OSError, KeyError, TypeError, ValueError) as e:
        sys.stderr.write(f"gateway: audit write failed: {e}\n")


def _pupils_and_columns(result) -> tuple[list[str], list[str]]:
    rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
    dicts = [r for r in rows if isinstance(r, dict)]
    pupils = sorted({str(r["Psuedo ID"]) for r in dicts if "Psuedo ID" in r})
    return pupils, sorted({str(k) for r in dicts for k in r})


def respond(body: CallBody, decision: Decision, status: int, result=None, error: str | None = None) -> JSONResponse:
    """The one way out of tools_call: write the audit line, then answer."""
    record = decision.to_dict()
    pupils, columns = _pupils_and_columns(result)
    audit(
        {
            "status": status,
            "server": body.server,
            "tool": body.tool,
            "arguments": body.arguments,
            "nonce": body.nonce,
            "decision": record["decision"],
            "reason_code": record["reason_code"],
            "detail": record.get("detail", ""),
            "agent_id": record.get("agent_id"),
            "mandate_hash": record.get("mandate_hash"),
            "request_hash": record.get("request_hash"),
            "rows": len(result) if isinstance(result, list) else int(result is not None),
            "pupils": pupils,
            "columns": columns,
        }
    )
    payload: dict = {"decision": record}
    if error is not None:
        payload["error"] = error
    if status == HTTP_OK:
        payload["result"] = result
    return JSONResponse(payload, status_code=status)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_state(STATE_DIR)
    yield


# no /docs, /redoc or /openapi.json: /describe is the discovery route, and it lists only what agents need
app = FastAPI(title="mandate gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(Exception)
async def fail_closed(request: HttpRequest, exc: Exception) -> JSONResponse:
    """Last line of defence: an unexpected error is a refusal, not a 500 and not a stack trace."""
    traceback.print_exception(exc, file=sys.stderr)
    if "dir" in state:
        audit(
            {
                "status": 403,
                "path": request.url.path,
                "decision": "DENY",
                "reason_code": "INTERNAL_ERROR",
                "detail": f"{type(exc).__name__}: {exc}",
            }
        )
    return JSONResponse(
        {"decision": {"decision": "DENY", "reason_code": "INTERNAL_ERROR", "detail": type(exc).__name__}},
        status_code=403,
    )


@app.get("/healthcheck")
def healthcheck() -> dict:
    return {"status": "ok"}


@app.get("/describe")
async def describe() -> dict:
    """Discovery for bring-your-own agents: what can be called and how a request must be signed."""
    servers = {}
    for name, target in MCP_SERVERS.items():
        async with Client(target) as client:
            servers[name] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in await client.list_tools()
            ]
    priv, pub = generate_keypair()
    example = sign_request(
        priv,
        server="pupil-data",
        tool="search",
        arguments={"query": "P0004", "urn": "SCH01"},
        mandate="<compact mandate JWT>",
    )
    return {
        "servers": servers,
        "step_up_patterns": state["gateway"].step_up,
        "search": {"rule": f"query is one value of at least {MIN_QUERY} characters, with no comma"},
        "disclosure": {
            "small_count": state["small_count"],
            "rule": "aggregate groups under small_count rows are withheld; the rest have totals and counts "
            "rounded to the nearest multiple of small_count",
            "refused_in_aggregates": sorted(IDENTIFIERS),
        },
        "private_data": {
            "level": PRIVATE_LEVEL,
            "roles": sorted(state["private_roles"]),
            "rule": "a call that could return data at this level needs the clearance and one of these roles in the "
            "mandate's role claim",
        },
        "labels": {
            "rule": "clearance is checked against everything the call could return, before it runs, then against "
            "the result",
            "file": state.get("labels_file"),
            "error": state.get("labels_error"),
        },
        "signing": {
            "alg": "Ed25519 by the key in the mandate's cnf.jwk; sig is base64url without padding",
            "signing_input": "canonical JSON (sorted keys, separators ',' and ':', ensure_ascii=False) of "
            "{server, tool, arguments, mandate_hash, nonce, ts}",
            "mandate_hash": "'sha256:' + hex sha256 of the compact mandate JWT",
            "ts": "unix seconds, within 300s of gateway time; nonce must be unique per request, 1-128 characters",
            "example": {
                "agent_jwk": pub_to_jwk(pub),
                "signing_input": Request(**example).signing_input().decode(),
                "request": example,
            },
        },
    }


def refuse_above_clearance(decision: Decision, levels: dict[str, int], what: str) -> bool:
    """Deny on max: the most sensitive label decides. True, with the decision rewritten, if it is refused."""
    decision.sensitivity = sensitivity_record(levels, state["level_names"], decision.clearance)
    level = decision.sensitivity["level"]
    decided_by = ", ".join(decision.sensitivity["decided_by"])
    if decision.clearance is None or level > decision.clearance:
        decision.decision, decision.reason_code = "DENY", "CLEARANCE_TOO_LOW"
        decision.detail = f"{what} reaches sensitivity {level} above clearance {decision.clearance} ({decided_by})"
        return True
    if level >= PRIVATE_LEVEL and decision.role not in state["private_roles"]:
        decision.decision, decision.reason_code = "DENY", "ROLE_REQUIRED"
        roles = ", ".join(sorted(state["private_roles"]))
        held = f"the role {decision.role}" if decision.role else "no role"
        decision.detail = f"{what} reaches sensitivity {level} ({decided_by}), open to {roles}; the mandate has {held}"
        return True
    return False


@app.post("/tools/call")
async def tools_call(body: CallBody):
    gateway: Gateway = state["gateway"]
    # re-read the published status list each request so `cli revoke` applies without a restart
    gateway.status_lists[state["status_uri"]] = (state["dir"] / "status_list.jwt").read_text().strip()

    decision = gateway.decide(Request(**body.model_dump()))
    if decision.decision == "DENY":
        return respond(body, decision, 403)
    if decision.decision == "STEP_UP":
        return respond(body, decision, 202)

    target = MCP_SERVERS.get(body.server)
    if target is None:
        raise HTTPException(404, f"no MCP server configured for {body.server!r}")

    # Q6: label everything the call could return and decide before it runs, so the answer cannot depend on
    # whether rows matched (an empty result would otherwise be allowed and a matching one refused)
    load_labels()
    possible = request_levels(
        body.tool, body.arguments, state["columns"], state["tables"], state["table_columns"], state["max_level"]
    )
    if refuse_above_clearance(decision, possible, "the call could return data that"):
        return respond(body, decision, 403)

    try:
        async with Client(target) as client:
            result = await client.call_tool(body.tool, body.arguments)
    except ToolError as e:
        return respond(body, decision, 502, error=str(e))

    # second line: the result's own labels, in case the server returned more than it declares
    levels = result_levels(
        body.tool, body.arguments, result.data, state["columns"], state["tables"], state["max_level"]
    )
    if refuse_above_clearance(decision, levels, "result"):
        return respond(body, decision, 403)
    data = result.data
    if body.tool == "aggregate":
        data, withheld = suppress_small_groups(data, state["small_count"])
        data = round_counts(data, state["small_count"])
        decision.disclosure = {"rounded_to": state["small_count"]}
        if withheld:
            decision.detail = f"{withheld} groups under {state['small_count']} rows withheld"
    return respond(body, decision, HTTP_OK, result=data)


if DEMO_ENABLED:
    from gateway.demo import router as demo_router  # imported last: demo imports main lazily

    app.include_router(demo_router)
