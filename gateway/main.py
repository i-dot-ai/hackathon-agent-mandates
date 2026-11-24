"""HTTP wrapper around the gateway pipeline.

POST /tools/call  {server, tool, arguments, mandate, nonce, ts, sig}
  -> verify mandate + proof of possession (gateway/lib/gateway_verify.py)
  -> ALLOW: forward to the MCP server, DENY: 403, STEP_UP: 202
"""

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from http import HTTPStatus
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi import Request as HTTPRequest
from fastapi.responses import JSONResponse
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from pydantic import BaseModel

from gateway.cli import sign_request
from gateway.lib import audit, budgets, graded, grants, safe_counts
from gateway.lib.common import generate_keypair, pub_to_jwk
from gateway.lib.gateway_verify import AuditContext, Gateway, Request
from gateway.lib.grant_issue import BREAKDOWN_MAX_ROWS, grant_for
from gateway.lib.interfaces import SERVER_LEVELS
from gateway.lib.status_list import is_revoked
from gateway.lib.trust_registry import TrustedList
from tool_grants import HEADER as GRANT_HEADER
from tool_grants import ensure_keypair

log = logging.getLogger(__name__)
# answered by the gateway itself, never forwarded (gateway/lib/audit.py)
AUDIT_SERVER = "audit"
AUDIT_TOOLS = {
    "events": "The request log for a principal or a jti: who called, when, from where, what, and the decision.",
    "saw": "What a mandate (jti) received: pupils, columns, highest PII level, call counts, in plain words.",
}

STATE_DIR = Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state"))
# name -> URL (or an in-process FastMCP instance in tests); fastmcp.Client accepts both
MCP_SERVERS: dict[str, object] = dict(
    kv.split("=", 1) for kv in os.environ.get("MCP_SERVERS", "pupil-data=http://backend:8080/mcp/").split(",")
)
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
    # shortcut: nonce replay set lives in Gateway._seen_nonces, in-memory per process; share it before multi-replica
    state["gateway"] = Gateway(registry, status_lists={})
    state["status_uri"] = json.loads((state_dir / "status_list.json").read_text())["uri"]
    state["dir"] = state_dir
    state["limits"] = budgets.State(budgets.load_limits())  # fails startup on an invalid limits file
    # signs one tool grant per forwarded call (add-scope-requests, tool-grants); servers hold tool_grant.pub
    state["grant_key"] = ensure_keypair(state_dir / "tool_grant_key.pem", state_dir / "tool_grant.pub")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_state(STATE_DIR)
    audit.init_store(STATE_DIR)  # SQLite file when GATEWAY_AUDIT_DB is set, in memory otherwise
    yield


app = FastAPI(title="mandate gateway", lifespan=lifespan)


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
    servers[AUDIT_SERVER] = [{"name": n, "description": d} for n, d in AUDIT_TOOLS.items()]
    servers[grants.GRANTS_SERVER] = [{"name": n, "description": d} for n, d in grants.GRANTS_TOOLS.items()]
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
        # data level per server (1 public .. 4 special category); a mandate's clearance must cover it
        "server_levels": {name: SERVER_LEVELS.get(name) for name in servers},
        "step_up_patterns": state["gateway"].step_up,
        # gateway-wide run limits (gateway/config/limits.yaml); a mandate's own budget and rate claims apply on top
        "limits": state["limits"].limits.public(),
        "signing": {
            "alg": "Ed25519 by the key in the mandate's cnf.jwk; sig is base64url without padding",
            "signing_input": "canonical JSON (sorted keys, separators ',' and ':', ensure_ascii=False) of "
            "{server, tool, arguments, mandate_hash, nonce, ts}",
            "mandate_hash": "'sha256:' + hex sha256 of the compact mandate JWT",
            "ts": "unix seconds, within 300s of gateway time; nonce must be unique per request",
            "example": {
                "agent_jwk": pub_to_jwk(pub),
                "signing_input": Request(**example).signing_input().decode(),
                "request": example,
            },
        },
    }


def _source_addr(http: HTTPRequest | None) -> str | None:
    """The caller's address. X-Forwarded-For counts only when the immediate peer is the trusted proxy."""
    if http is None:
        return None
    peer = http.client.host if http.client else None
    trusted = os.environ.get("GATEWAY_TRUSTED_PROXY")
    forwarded = http.headers.get("x-forwarded-for")
    if trusted and peer == trusted and forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return peer


def _mandate_revoked(event: dict) -> bool | None:
    """Whether the mandate behind an audit event is revoked now, from its issuer's signed status list."""
    gateway: Gateway = state["gateway"]
    pub = gateway.registry.issuer_key(event["iss"] or "", event["issuer_kid"] or "")
    sl_jwt = gateway.status_lists.get(state["status_uri"])
    if pub is None or sl_jwt is None or event["status_idx"] is None:
        return None
    try:
        return is_revoked(sl_jwt, event["status_idx"], pub, state["status_uri"])
    except ValueError:
        return None


async def _forward(body: CallBody, ctx: AuditContext, decision_id: str, k: int = safe_counts.DEFAULT_K):
    """(http_status, result data or None, error text or None) for an allowed call."""
    if body.server == AUDIT_SERVER:
        try:
            return 200, await audit.handle(body.tool, body.arguments, _mandate_revoked), None
        except ValueError as e:
            return 400, None, str(e)
    target = MCP_SERVERS.get(body.server)
    if target is None:
        return 404, None, f"no MCP server configured for {body.server!r}"
    counts = safe_counts.applies(body.server, body.tool)
    per_pupil = counts and safe_counts.has_pupils(str(body.arguments.get("table", "")))
    # counts: the one upstream call is the per-pupil breakdown, which never leaves the gateway (add-safe-counts)
    arguments = safe_counts.breakdown_arguments(body.arguments) if per_pupil else body.arguments
    if isinstance(target, str):  # over HTTP the server checks a grant; in-process targets (tests) get none
        grant = grant_for(
            state["grant_key"],
            ctx.claims,
            ctx.entry,
            server=body.server,
            tool=body.tool,
            arguments=arguments,  # what is actually sent, so the server's args_hash check matches
            decision_id=decision_id,
            # the per-pupil breakdown is folded into rounded counts here and never reaches the agent: capping
            # its rows would corrupt the counts, so the cap applies to the folded result instead
            max_rows=BREAKDOWN_MAX_ROWS if per_pupil else None,
        )
        target = StreamableHttpTransport(target, headers={GRANT_HEADER: grant})
    try:
        async with Client(target) as client:
            result = await client.call_tool(body.tool, arguments)
    except ToolError as e:
        return 502, None, str(e)
    if counts:
        rows = safe_counts.release(result.data, body.arguments["group_by"], k, per_pupil=per_pupil)
        return 200, rows, None
    return 200, result.data, None


def _deny(decision, code: str, detail: str):
    return replace(decision, decision="DENY", reason_code=code, detail=detail)


def _response(record: dict, status: int, data, error: str | None, limits: budgets.Limits):
    if status == HTTPStatus.NOT_FOUND:
        raise HTTPException(404, error)
    if error is not None:
        return JSONResponse({"decision": record, "error": error}, status_code=status)
    if status != HTTPStatus.OK:
        headers = {"Retry-After": str(limits.retry_after_seconds)} if record["reason_code"] == "RATE_LIMITED" else None
        return JSONResponse({"decision": record}, status_code=status, headers=headers)
    return {"decision": record, "result": data}


STATUS_FOR = {"ALLOW": HTTPStatus.OK, "STEP_UP": HTTPStatus.ACCEPTED, "DENY": HTTPStatus.FORBIDDEN}
TOO_MANY = {"RATE_LIMITED", "BUDGET_EXHAUSTED"}


async def _grants(body: CallBody, ctx: AuditContext, decision_id: str):
    """(status, data, error, refusal) for an allowed grants call. A refusal from the grants layer becomes this
    call's decision, so the audit event and the response both carry it."""
    outcome = await grants.handle(
        body.tool,
        body.model_dump(),
        ctx.claims,
        decision_id=decision_id,
        step_up=state["gateway"].step_up,
        revoked=lambda _claims: False,  # verify_mandate already refused revoked mandates and dead parents
    )
    if outcome.deny:
        return HTTPStatus.FORBIDDEN, None, None, outcome.deny
    return HTTPStatus.OK, outcome.data, None, None


@app.post("/tools/call")
async def tools_call(body: CallBody, http: HTTPRequest = None):  # None when called in-process (demo)
    gateway: Gateway = state["gateway"]
    limits: budgets.State = state["limits"]
    source = _source_addr(http)
    # re-read the published status list each request so `cli revoke` applies without a restart
    gateway.status_lists[state["status_uri"]] = (state["dir"] / "status_list.jwt").read_text().strip()

    # a flood of unverifiable requests is refused before any signature work (add-run-budgets)
    if budgets.source_over_ceiling(limits, source or "unknown"):
        record = {"decision": "DENY", "reason_code": "RATE_LIMITED", "detail": "unverified requests from this source",
                  "decision_id": str(uuid.uuid4())}  # fmt: skip
        if limits.should_record(f"source:{source}"):
            await _record_or_log(record, AuditContext(), body, source=source, status=HTTPStatus.TOO_MANY_REQUESTS)
        return _response(record, HTTPStatus.TOO_MANY_REQUESTS, None, None, limits.limits)

    decision, ctx, plan, counts = _decide(gateway, limits, body, source)
    if decision.decision != "ALLOW" or plan is None:
        return await _refused(limits, decision, ctx, plan, body, source=source)
    return await _allowed(limits, decision, ctx, plan, body, source=source, counts=counts)


def _decide(gateway: Gateway, limits: budgets.State, body: CallBody, source: str | None):
    """Mandate, signature, scope, then the gateway's own refusals: budget claims, key ceiling, safe counts."""
    decision, ctx = gateway.decide_with_context(Request(**body.model_dump()))
    plan = None
    if not ctx.identity_verified:
        limits.unverified.add(source or "unknown")
    else:
        try:
            plan = budgets.plan_for(limits, ctx.claims, body.server, body.tool, body.arguments)
        except budgets.BudgetInvalid as e:
            decision = _deny(decision, "BUDGET_INVALID", str(e))
        if budgets.key_over_ceiling(limits, ctx.claims.get("agent_id")):
            decision = _deny(decision, "RATE_LIMITED", "agent key ceiling")
    counts = decision.decision == "ALLOW" and safe_counts.applies(body.server, body.tool)
    if counts and (refused := safe_counts.check(body.arguments, ctx.claims)):
        decision = _deny(decision, *refused)
    return decision, ctx, plan, counts


async def _refused(limits: budgets.State, decision, ctx, plan, body: CallBody, *, source: str | None):
    record = {**decision.to_dict(), "decision_id": str(uuid.uuid4())}
    status = HTTPStatus.TOO_MANY_REQUESTS if record["reason_code"] in TOO_MANY else STATUS_FOR[decision.decision]
    ceiling = record["reason_code"] == "RATE_LIMITED"
    caller = f"key:{ctx.claims.get('agent_id')}" if ctx.claims else f"source:{source}"
    if not ceiling or limits.should_record(caller):  # while a ceiling holds, record sparingly
        await _record_or_log(record, ctx, body, source=source, status=status, plan=plan)
    if plan is not None and not ceiling:
        await _alerts(limits, plan, ctx.claims, [])
    return _response(record, status, None, None, limits.limits)


async def _allowed(limits: budgets.State, decision, ctx, plan, body: CallBody, *, source: str | None, counts: bool):
    # assigned before forwarding: the scope-requests change uses it as the tool grant's jti
    decision_id = str(uuid.uuid4())
    async with limits.lock(plan.family):  # check, forward, count and record as one step per budget family
        if refused := await budgets.before_forward(limits, plan):
            decision = _deny(decision, *refused)
            status, data, error = HTTPStatus.TOO_MANY_REQUESTS, None, None
        elif body.server == grants.GRANTS_SERVER:
            status, data, error, by_grants = await _grants(body, ctx, decision_id)
            if by_grants:
                decision = _deny(decision, *by_grants)
        else:
            status, data, error = await _forward(body, ctx, decision_id, safe_counts.k_for(ctx.claims))
            # graded pupil-data: never more than the clearance, even if the server sent it (add-graded-pupil-data)
            if status == HTTPStatus.OK and not counts and (level := graded.level_for(body.server, ctx.claims)):
                query = body.arguments.get("query") if body.tool == "search" else None
                data = graded.strip(data, level, query=query)
        min_level = safe_counts.max_level(body.arguments) if counts else None
        summary = audit.summarise(data, body.server, min_level=min_level) if status == HTTPStatus.OK else None
        if summary is not None and (over := await _pupil_budget(limits, plan, summary)):
            decision, data, summary = _deny(decision, *over), None, None  # withhold the whole result
            status = HTTPStatus.SERVICE_UNAVAILABLE if over[0] == "AUDIT_UNAVAILABLE" else HTTPStatus.TOO_MANY_REQUESTS
        record = {**decision.to_dict(), "decision_id": decision_id}
        try:
            await audit.record(decision=record, ctx=ctx, server=body.server, tool=body.tool, arguments=body.arguments,
                               source_addr=source, http_status=status, summary=summary,
                               scope_entry=plan.entry)  # fmt: skip
        except audit.AuditUnavailable:
            log.exception("audit event not written for decision %s", record["decision_id"])
            if status == HTTPStatus.OK:  # nothing leaves the gateway without its record
                withheld = {**record, "decision": "DENY", "reason_code": "AUDIT_UNAVAILABLE", "detail": ""}
                return JSONResponse({"decision": withheld}, status_code=503)
        if status == HTTPStatus.OK:
            budgets.after_allowed(limits, plan)
    await _alerts(limits, plan, ctx.claims, summary.pupil_ids if summary else [])
    return _response(record, status, data, error, limits.limits)


async def _pupil_budget(limits: budgets.State, plan, summary) -> tuple[str, str] | None:
    try:
        return await budgets.over_pupil_budget(limits, plan, summary.pupil_ids)
    except Exception:  # counting failed: fail closed, nothing leaves
        log.exception("pupil budget check failed")
        return "AUDIT_UNAVAILABLE", ""


async def _record_or_log(record, ctx, body: CallBody, *, source, status, plan=None) -> None:
    """Record a refusal. A refusal is returned even if its event can't be written."""
    try:
        await audit.record(
            decision=record,
            ctx=ctx,
            server=body.server,
            tool=body.tool,
            arguments=body.arguments,
            source_addr=source,
            http_status=status,
            scope_entry=plan.entry if plan else None,
        )
    except audit.AuditUnavailable:
        log.exception("audit event not written for refusal %s", record["decision_id"])


async def _alerts(limits: budgets.State, plan, claims: dict, pupils: list[str]) -> None:
    """Alerts never change a response, and a failure to raise one is only logged."""
    try:
        await budgets.raise_alerts(limits, plan, claims, pupils)
    except Exception:
        log.exception("alert not recorded")


class ExternalEventBody(BaseModel):
    token: str  # an audit-event+jwt signed by a trusted issuer (audit.sign_external_event)


@app.post("/internal/audit-events")
async def internal_audit_event(body: ExternalEventBody):
    """Approval events from the issuer service, added to the audit chain.

    The issuer's signature is the only gate: anyone may call this, but only an event signed by an issuer on the
    trusted list is recorded. The same event (its jti) sent again is acknowledged without a second record.
    """
    try:
        stored, new = await audit.record_signed_external(body.token, state["gateway"].registry)
    except audit.ExternalEventRejected as e:
        status = HTTPStatus.BAD_REQUEST if e.code in ("EVENT_INVALID", "EVENT_REJECTED") else HTTPStatus.FORBIDDEN
        return JSONResponse({"recorded": False, "reason_code": e.code, "detail": e.detail}, status_code=status)
    except audit.AuditUnavailable:
        log.exception("issuer event not written")
        return JSONResponse({"recorded": False, "reason_code": "AUDIT_UNAVAILABLE"}, status_code=503)
    payload = {"recorded": True, "duplicate": not new, "decision_id": stored["decision_id"], "seq": stored["seq"]}
    return JSONResponse(payload, status_code=HTTPStatus.CREATED if new else HTTPStatus.OK)


@app.get("/healthcheck/audit")
def healthcheck_audit() -> dict:
    """Which audit store is in use and whether it survives a restart. No paths, no events."""
    return audit.store_status()


@app.get("/audit/head")
async def audit_head() -> dict:
    """The latest audit event's seq, hash and gateway signature, for anchoring outside the gateway. No data."""
    return await audit.head()


from gateway.demo import router as demo_router  # noqa: E402  (demo imports main lazily)

app.include_router(demo_router)
