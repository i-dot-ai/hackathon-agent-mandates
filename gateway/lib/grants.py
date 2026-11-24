"""The `grants` server, answered by the gateway itself (OpenSpec add-scope-requests, capability scope-requests).

    grants.self     the calling mandate's own grants, structured and in plain words
    grants.check    the decision a call would get, without forwarding it, plus the missing grant
    grants.request  ask for more: a structured grant, or the release of held calls (one, or a list of them)
    grants.status   a request's state, and the new mandate once approved
    grants.decide   a supervising agent's decision on another agent's request

Every grants call arrives through POST /tools/call like any other, so the audit trail records it. Requests and
decisions are forwarded, signed bodies and all, to the issuer service, which re-verifies them itself.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import audit, safe_counts
from .audience import audience_pupils
from .common import canonical, sha256_hex
from .grant_words import grants_words, until
from .graded import GRADED_SERVER, claimless_level
from .interfaces import SERVER_LEVELS
from .scope_math import Invalid, already_granted, validate_entry, validate_request

GRANTS_SERVER = "grants"
GRANTS_TOOLS = {
    "self": "Your own grants: scope, deny rules, clearance, audience, expiry, parent, in plain words.",
    "check": "The decision a call would get (server, tool, arguments), without making it, and what's missing.",
    "request": "Ask for more access (scope, clearance, ttl, reason), or release held calls: held={decision_id, server, "
    "tool, arguments}, or a list of up to 50 of them, approved together in one prompt.",
    "status": "A scope request's state (request_id); returns the new mandate once approved.",
    "decide": "A supervising agent's decision (request_id, decision, approved) on a helper's request.",
}
REQUEST_ID = re.compile(r"^sr_[A-Za-z0-9_-]{6,40}$")
MAX_HELD = 50  # held calls one request may release together, as on the issuer
ISSUER_URL = os.environ.get("ISSUER_URL", "http://issuer:8083").rstrip("/")
NEXT_ACTION = {
    "pending": "ask_user",
    "approved": "retry",
    "rejected": "stop",
    "expired": "request_again",
    "already_granted": "retry",
}


@dataclass
class Outcome:
    """A grants tool's answer: data for a 200, or a refusal the gateway turns into a 403 DENY."""

    data: dict | None = None
    deny: tuple[str, str] | None = None


def refused(code: str, detail: str = "") -> Outcome:
    return Outcome(deny=(code, detail))


# ---------------------------------------------------------------- talking to the issuer


class IssuerRefused(Exception):
    def __init__(self, code: str, detail: str = "", extra: dict | None = None):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.extra = code, detail, extra or {}


def _http(method: str, path: str, payload: dict | None = None) -> dict:
    req = urllib.request.Request(  # noqa: S310
        f"{ISSUER_URL}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"content-type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = json.loads(e.read() or b"{}")
        raise IssuerRefused(body.get("error", f"ISSUER_{e.code}"), body.get("detail", ""), body) from e
    except (urllib.error.URLError, OSError) as e:
        raise IssuerRefused("ISSUER_UNAVAILABLE", type(e).__name__) from e


issuer_call = _http  # tests point this at the issuer app in process


# ---------------------------------------------------------------- the tools


def _self(claims: dict, revoked) -> Outcome:
    scope = claims.get("scope", [])
    entries = []
    for e in scope:
        pupils = audience_pupils(e) if "audience" in e else None
        entries.append({**{k: v for k, v in e.items() if k != "audience"},
                        "audience_size": len(pupils) if pupils is not None else None})  # fmt: skip
    parent = claims.get("parent")
    data = {
        "jti": claims["jti"],
        "scope": entries,
        "deny": claims.get("deny", []),
        "clearance": claims.get("clearance"),
        "expires_at": claims["exp"],
        "parent": parent,
        "revoked": revoked(claims),
        "approved_by": claims.get("approved_by"),
        "preapproved_actions": len(claims.get("preapproved", [])),
        "summary": grants_words(scope, clearance=claims.get("clearance")) + f" Valid {until(claims['exp'])}.",
    }
    try:
        query = urllib.parse.urlencode({"requester_jti": claims["jti"]})
        data["pending_requests"] = issuer_call("GET", f"/internal/requests?{query}")["requests"]
    except IssuerRefused:
        data["pending_requests"] = None
    return Outcome(data=data)


GRADED_NOTE = (
    "pupil-data works at any clearance and returns only the columns up to it: 2 basic details and names, 3 also free "
    "school meals and language, 4 also ethnicity and care status, each such read held for a person's approval. Ask "
    "for the lowest clearance the job needs."
)


def _suggested_clearance(server: str, claims: dict) -> int | None:
    """The clearance to ask for. For graded pupil-data, the mandate's own (or 2): asking for the server's level, 4,
    would make every read wait for special-category approval (add-graded-pupil-data)."""
    level = SERVER_LEVELS.get(server)
    if server == GRADED_SERVER:
        current = claims.get("clearance")
        return current if type(current) is int and 1 <= current <= 4 else claimless_level()  # noqa: PLR2004
    return level


def _missing_grant(server: str, tool: str, arguments: dict, code: str, scope: list[dict], step: str | None,
                   claims: dict | None = None) -> dict:  # fmt: skip
    """The smallest scope entry that would let this call through."""
    pinned = {k: [arguments[k]] for k in ("urn", "path", "table", "measure") if k in arguments}
    entry: dict = {"server": server, "tools": [tool], "constraints": pinned}
    if code == "AUDIENCE_VIOLATED" or (code == "CONSTRAINT_VIOLATED" and "pupil_id" in arguments):
        named = [arguments["pupil_id"]] if "pupil_id" in arguments else list(arguments.get("pupil_ids") or [])
        entry["audience"] = {"pupils": [str(p) for p in named]}
    missing = {"scope": [entry], "clearance": _suggested_clearance(server, claims or {})}
    if server == GRADED_SERVER:
        missing["note"] = GRADED_NOTE
    if step:
        missing["held"] = (
            "this call is held for approval; ask with grants.request and held={decision_id, server, tool, arguments}. "
            "Held several? Pass them as one list to ask once. For letters, put every pupil in one draft call."
        )
    return missing


def _check(claims: dict, arguments: dict, step_up: list[str]) -> Outcome:
    from .gateway_verify import Request, check_request  # noqa: PLC0415  (avoid an import cycle)

    server, tool, args = arguments.get("server"), arguments.get("tool"), arguments.get("arguments", {})
    if not isinstance(server, str) or not isinstance(tool, str) or not isinstance(args, dict):
        return refused("REQUEST_INVALID", "check needs server, tool and arguments")
    hypothetical = Request(server=server, tool=tool, arguments=args, mandate="", nonce="", ts=0, sig="")
    decision, code, detail = check_request(hypothetical, claims["scope"], claims["deny"], step_up, claims)
    # the same safe-counts refusal the real call would get (add-safe-counts)
    if decision == "ALLOW" and safe_counts.applies(server, tool) and (counted := safe_counts.check(args, claims)):
        decision, code, detail = "DENY", counted[0], counted[1]
    data = {"decision": decision, "reason_code": code, "detail": detail}
    if decision == "STEP_UP" or code in {
        "OUT_OF_SCOPE", "CONSTRAINT_VIOLATED", "CONSTRAINT_MISSING", "CLEARANCE_TOO_LOW", "AUDIENCE_VIOLATED",
    }:  # fmt: skip
        data["missing"] = _missing_grant(server, tool, args, code, claims["scope"], decision == "STEP_UP" or None,
                                         claims)  # fmt: skip
    return Outcome(data=data)


def _with_next(view: dict) -> dict:
    status = view.get("status", "pending")
    view["next_action"] = NEXT_ACTION.get(status, "wait")
    if view.get("reason_code") == "NUMBER_MISMATCH":  # a wrong pick on the page, not a person saying no
        view["next_action"] = "request_again"
    view["poll_after_s"] = 10 if status == "pending" else None
    if status == "pending":
        view["text"] = (
            f"Approval needed: {view['summary']}\n"
            f"Open {view['approval_url']}, sign in with your approver key, and choose {view['number']} on the "
            f"approval page. This request expires at {until(view['expires_at']).removeprefix('until ')}.\n"
            'Replying "yes" here does not approve it.'
        )
    return view


async def _held_matches(claims: dict, held: dict) -> str | None:
    """None when `held` names a call this mandate made and had held, with these exact arguments."""
    for k in ("decision_id", "server", "tool", "arguments"):
        if k not in held:
            return f"held needs {k}"
    events = await audit.get_store().for_jtis({claims["jti"]})
    event = next((e for e in events if e["decision_id"] == held["decision_id"]), None)
    if event is None or not event["identity_verified"]:
        return "no held call with that decision_id for this mandate"
    if event["decision"] != "STEP_UP":
        return "that call was not held"
    if (event["server"], event["tool"]) != (held["server"], held["tool"]):
        return "server or tool differ from the held call"
    if event["arg_hash"] != sha256_hex(canonical(held["arguments"])):
        return "arguments differ from the held call"
    return None


async def _request(claims: dict, body: dict, decision_id: str) -> Outcome:
    args = body["arguments"]
    if "parent" in claims:
        return refused("REQUEST_INVALID", "ask with the original mandate, not a supplementary one")
    held = args.get("held")
    if held is not None:
        calls = [held] if isinstance(held, dict) else held
        if not isinstance(calls, list) or not calls or len(calls) > MAX_HELD:
            return refused("REQUEST_INVALID", f"held must be one held call or a list of 1 to {MAX_HELD}")
        for call in calls:
            if not isinstance(call, dict) or (problem := await _held_matches(claims, call)):
                return refused("REQUEST_INVALID", problem if isinstance(call, dict) else "each held call is an object")
    else:
        try:
            scope = args.get("scope")
            validate_request(scope, args.get("clearance"), args.get("ttl", 3600), args.get("reason", ""))
            for entry in scope:
                validate_entry(entry)
        except Invalid as e:
            return refused("REQUEST_INVALID", str(e))
        if already_granted(claims, scope, args.get("clearance")):
            return Outcome(data={"status": "already_granted", "next_action": "retry"})
    try:
        view = issuer_call("POST", "/internal/requests", {"call": body, "ref_decision_id": decision_id})
    except IssuerRefused as e:
        return refused(e.code, e.detail)
    if view.get("status") == "already_granted":
        # reused from an earlier approval in this run (add-run-reuse): the agent gets that mandate back
        reused = {k: view[k] for k in ("mandate", "mandate_jti", "reused_request_id") if k in view}
        return Outcome(data={"status": "already_granted", "next_action": "retry", **reused})
    return Outcome(data=_with_next(view))


def _status(claims: dict, arguments: dict) -> Outcome:
    rid = arguments.get("request_id")
    if not isinstance(rid, str) or not REQUEST_ID.match(rid):
        return refused("REQUEST_INVALID", "status needs a request_id like sr_...")
    query = urllib.parse.urlencode({"requester_jti": claims["jti"]})
    try:
        view = issuer_call("GET", f"/internal/requests/{rid}?{query}")
    except IssuerRefused as e:
        if e.code in ("OUT_OF_SCOPE", "ISSUER_404"):
            return refused("OUT_OF_SCOPE", "no such request for this mandate")
        return refused(e.code, e.detail)
    return Outcome(data=_with_next(view))


def _decide(claims: dict, body: dict) -> Outcome:
    rid = body["arguments"].get("request_id")
    if not isinstance(rid, str) or not REQUEST_ID.match(rid):
        return refused("REQUEST_INVALID", "decide needs a request_id like sr_...")
    if claims.get("can_delegate") is not True:
        return refused("EXCEEDS_SUPERVISOR", "this mandate does not allow delegation")
    try:
        view = issuer_call("POST", f"/internal/requests/{rid}/supervisor-decision", {"call": body})
    except IssuerRefused as e:
        return refused(e.code, e.detail)
    return Outcome(data=_with_next(view))


async def handle(tool: str, body: dict, claims: dict, *, decision_id: str, step_up: list[str], revoked) -> Outcome:
    """Answer an allowed grants.<tool> call. `body` is the agent's signed call, forwarded as is to the issuer."""
    if tool == "self":
        return _self(claims, revoked)
    if tool == "check":
        return _check(claims, body["arguments"], step_up)
    if tool == "request":
        return await _request(claims, body, decision_id)
    if tool == "status":
        return _status(claims, body["arguments"])
    if tool == "decide":
        return _decide(claims, body)
    return refused("OUT_OF_SCOPE", f"grants.{tool}")
