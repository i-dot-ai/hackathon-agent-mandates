"""The issuer service (OpenSpec add-scope-requests, design decisions 3 to 7).

The only process that holds the issuer key. It creates scope requests, records decisions and mints supplementary
mandates, and it takes no one's word for anything:

- A request is created only from the agent's own signed `grants.request` call, forwarded unchanged by the gateway.
  The issuer re-verifies the mandate, the request signature and the nonce itself.
- A mandate is minted only on a decision the issuer verified itself: a person's approver key (a signed decision,
  or a session made from a one-time login token signed with that key), or a supervising agent's own signed
  `grants.decide` call.
- Every approval step goes into the gateway's audit chain as an event signed with the issuer key.

Internal routes (/internal/...) are for the gateway. The approval routes are called by the team UI's server-side
proxy and by `cli approve`; they decide nothing without an approver key or session.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import jwt
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from gateway.cli import _load_status, issue_mandate
from gateway.lib.audit import sign_external_event
from gateway.lib.common import canonical, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from gateway.lib.gateway_verify import Reject, Request, verify_mandate
from gateway.lib.grant_words import action_words, grants_words, marks_level_4
from gateway.lib.scope_math import (
    Invalid,
    already_granted,
    clearance_covers,
    entry_covers,
    narrower_or_equal,
    scope_covers,
    validate_request,
    within_ceiling,
)
from gateway.lib.trust_registry import TrustedList
from issuer.store import MAX_PENDING, MAX_PER_HOUR, NUMBER_MISMATCH, AlreadyDecided, Store

log = logging.getLogger(__name__)

STATE_DIR = Path(os.environ.get("ISSUER_STATE_DIR", "gateway/state"))
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:8081").rstrip("/")
GATEWAY_INTERNAL_URL = os.environ.get("GATEWAY_INTERNAL_URL", "http://gateway:8082").rstrip("/")
REQUEST_WINDOW = 300  # seconds a signed call stays fresh, as at the gateway
HELD_TTL = 300  # a mandate that releases held calls lives at most 5 minutes
MAX_HELD = 50  # held calls one request may release together (add-batch-release)
REUSE_MIN_REMAINING_S = 60  # an earlier approval about to expire is not handed back; asking again is clearer
LOGIN_MAX_AGE = 300
LOGIN_TYP = "approver-login+jwt"
DECISION_TYP = "approver-decision+jwt"

app = FastAPI(title="mandate issuer")
_store: Store | None = None


def store() -> Store:
    global _store  # noqa: PLW0603
    if _store is None:
        _store = Store(os.environ.get("ISSUER_DB", STATE_DIR / "requests.sqlite"))
    return _store


def reset(state_dir: Path, db: str | Path = ":memory:") -> None:
    """Point the service at a state folder and a store (tests)."""
    global STATE_DIR, _store
    STATE_DIR, _store = state_dir, Store(db)


def _json_file(name: str) -> dict:
    path = STATE_DIR / name
    return json.loads(path.read_text()) if path.exists() else {}


class Refused(Exception):
    def __init__(self, code: str, detail: str = "", status: int = 403, **extra):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.status, self.extra = code, detail, status, extra


@app.exception_handler(Refused)
async def _refused(_request, exc: Refused):
    return JSONResponse({"error": exc.code, "detail": exc.detail, **exc.extra}, status_code=exc.status)


# ---------------------------------------------------------------- verifying forwarded calls


def verify_call(call: dict, tool: str) -> dict:
    """Re-verify an agent's signed POST /tools/call body for grants.<tool>. Returns the verified claims."""
    try:
        req = Request(**{k: call[k] for k in ("server", "tool", "arguments", "mandate", "nonce", "ts", "sig")})
    except (KeyError, TypeError) as e:
        raise Refused("CALL_INVALID", "not a signed tools/call body") from e
    if (req.server, req.tool) != ("grants", tool):
        raise Refused("CALL_INVALID", f"expected grants.{tool}")
    registry = TrustedList(_json_file("trusted_list.json"))
    meta = _json_file("status_list.json")
    status_jwt = (STATE_DIR / "status_list.jwt").read_text().strip()
    try:
        claims = verify_mandate(req.mandate, registry, {meta["uri"]: status_jwt})
    except Reject as r:
        raise Refused(r.code, r.detail) from r
    if abs(req.ts - time.time()) > REQUEST_WINDOW:
        raise Refused("POP_FAILED", "request timestamp outside window")
    if not verify_bytes(jwk_to_pub(claims["cnf"]["jwk"]), req.signing_input(), req.sig):
        raise Refused("POP_FAILED", "bad request signature")
    if not store().use_nonce(req.nonce):
        raise Refused("POP_FAILED", "replayed nonce")
    return claims


# ---------------------------------------------------------------- creating a request


def _held_scope(held: dict) -> list[dict]:
    """The one-entry grant that covers a held call: its server and tool, pinned to its school and pupil."""
    pinned = {k: [held["arguments"][k]] for k in ("urn", "pupil_id") if k in held["arguments"]}
    return [{"server": held["server"], "tools": [held["tool"]], "constraints": pinned}]


def held_calls(held) -> list[dict]:
    """The held calls a request releases, as a list: one object (the original shape) or a list of them."""
    if held is None:
        return []
    return [held] if isinstance(held, dict) else list(held)


def _held_list(held) -> list[dict]:
    calls = held_calls(held)
    if not calls or len(calls) > MAX_HELD or not all(isinstance(c, dict) for c in calls):
        raise Refused("REQUEST_INVALID", f"held must be one held call or a list of 1 to {MAX_HELD}")
    for c in calls:
        if not {"decision_id", "server", "tool", "arguments"} <= set(c) or not isinstance(c["arguments"], dict):
            raise Refused("REQUEST_INVALID", "each held call needs decision_id, server, tool and arguments")
    if len({c["decision_id"] for c in calls}) != len(calls):
        raise Refused("REQUEST_INVALID", "the same held call is named twice")
    return calls


def _held_union_scope(calls: list[dict]) -> list[dict]:
    """One entry per distinct held call shape, so the minted mandate covers every released call and no more."""
    seen, scope = set(), []
    for c in calls:
        for entry in _held_scope(c):
            key = canonical(entry)
            if key not in seen:
                seen.add(key)
                scope.append(entry)
    return scope


def held_words(calls: list[dict]) -> list[str]:
    return [action_words(c["server"], c["tool"], c["arguments"]) for c in calls]


def action_hash(server: str, tool: str, arguments: dict, mandate_hash: str) -> str:
    return sha256_hex(canonical({"server": server, "tool": tool, "arguments": arguments, "mandate_hash": mandate_hash}))


def agent_view(r: dict) -> dict:
    """What the requesting agent (and grants.status) sees about a request."""
    view = {
        "request_id": r["id"],
        "status": r["status"],
        "number": r["match_number"],  # the person chooses this one of three on the approval page
        "approval_url": f"{FRONTEND_URL}/approve/{r['id']}",
        "summary": summary_of(r),
        "approvers": [r["principal"], "a supervising agent with can_delegate"],
        "expires_at": r["expires"],
    }
    if r.get("end_reason"):
        view["reason_code"] = r["end_reason"]
    if r["status"] == "approved" and r.get("minted"):
        view["mandate"] = r["minted"]
        view["mandate_jti"] = r["minted_jti"]
    return view


class CreateBody(BaseModel):
    call: dict
    ref_decision_id: str | None = None


@app.post("/internal/requests")
def create_request(body: CreateBody):
    claims = verify_call(body.call, "request")
    if "parent" in claims:
        # one level of delegation: a supplementary mandate can't ask for more (its grandchild would outlive a
        # revocation of the original, which the parent check doesn't follow)
        raise Refused("REQUEST_INVALID", "ask with the original mandate, not a supplementary one")
    args = body.call["arguments"]
    held = _held_list(args["held"]) if args.get("held") is not None else None
    clearance, ttl, reason = args.get("clearance"), args.get("ttl", 3600), args.get("reason", "")
    scope = _held_union_scope(held) if held else args.get("scope")
    try:
        validate_request(scope, clearance, HELD_TTL if held else ttl, reason)
    except Invalid as e:
        raise Refused("REQUEST_INVALID", str(e)) from e
    if not held and already_granted(claims, scope, clearance):
        return {"status": "already_granted"}
    # an earlier approval in this run that still holds covers it: hand that back instead of asking again
    if not held and (earlier := _reusable_approval(claims["jti"], scope, clearance)):
        return earlier
    principal = (claims.get("delegator") or {}).get("principal", "")
    if over := within_ceiling(_json_file("principals.json").get(principal), scope, clearance):
        raise Refused("EXCEEDS_PRINCIPAL", over)

    mandate_hash = sha256_hex(body.call["mandate"].encode())
    request_key = sha256_hex(canonical({"scope": scope, "clearance": clearance, "held": held}))
    counts = store().counts(claims["jti"], request_key)
    if counts["recently_rejected"]:
        raise Refused("RECENTLY_REJECTED", "the same request was rejected in the last hour")
    if counts["pending"] >= MAX_PENDING or counts["last_hour"] >= MAX_PER_HOUR:
        raise Refused("TOO_MANY_REQUESTS", f"{counts['pending']} pending, {counts['last_hour']} in the last hour")

    if held and len(held) == 1:
        summary = "Release one held call: " + held_words(held)[0]
        public_summary = f"Release one held call to {held[0]['server']}.{held[0]['tool']}"
    elif held:
        summary = f"Release {len(held)} held calls, each once: " + "; ".join(held_words(held))
        tools = sorted({f"{c['server']}.{c['tool']}" for c in held})
        public_summary = f"Release {len(held)} held calls to {', '.join(tools)}"
    else:
        # no clearance asked for: the minted mandate keeps the requester's, so describe that one
        effective = clearance if clearance is not None else claims.get("clearance")
        summary = grants_words(scope, clearance=effective, ttl=ttl)
        public_summary = summary  # argument values only after sign-in
    r = store().create(
        requester_jti=claims["jti"],
        requester_agent_id=claims.get("agent_id"),
        principal=principal,
        org=(claims.get("delegator") or {}).get("org"),
        cnf_jwk=claims["cnf"]["jwk"],
        parent_mandate_hash=mandate_hash,
        parent_status=claims["status"]["status_list"],
        parent_exp=claims["exp"],
        parent_clearance=claims.get("clearance"),
        deny=claims.get("deny", []),
        requested={
            "scope": scope,
            "clearance": clearance,
            "ttl": HELD_TTL if held else ttl,
            "summary": summary,
            "public_summary": public_summary,
            "parent_scope": claims.get("scope", []),
            "parent_budget": claims.get("budget"),  # run budgets: copied unchanged into what's minted
            "level_4": marks_level_4(scope, clearance if clearance is not None else claims.get("clearance")),
        },
        request_key=request_key,
        held=held,
        reason=reason,
        ref_decision_id=body.ref_decision_id,
    )
    store().enqueue({"event_type": "approval_requested", "request": r, "reason_code": "REQUESTED"})
    flush_events()
    return agent_view(r)


def _reusable_approval(requester_jti: str, scope: list[dict], clearance: int | None) -> dict | None:
    """The newest approval in this run (same base mandate) whose minted mandate still verifies and covers the ask.

    Held-call releases are never reused: they pre-approve one exact action once. The minted mandate is verified
    again (signature, expiry, its own revocation and its parent's), so a revoked or expired approval asks afresh.
    """
    registry = TrustedList(_json_file("trusted_list.json"))
    meta = _json_file("status_list.json")
    status_jwt = (STATE_DIR / "status_list.jwt").read_text().strip()
    for r in store().approved_for(requester_jti):
        try:
            minted = verify_mandate(r["minted"], registry, {meta["uri"]: status_jwt})
        except Reject:
            continue
        if minted["exp"] - time.time() < REUSE_MIN_REMAINING_S:
            continue
        if already_granted(minted, scope, clearance):
            return {
                "status": "already_granted",
                "mandate": r["minted"],
                "mandate_jti": r["minted_jti"],
                "reused_request_id": r["id"],
            }
    return None


@app.get("/internal/requests")
def list_requests(requester_jti: str):
    rows = store().pending_for(requester_jti)
    return {"requests": [agent_view(r) for r in rows]}


@app.get("/internal/requests/{rid}")
def request_status(rid: str, requester_jti: str):
    r = store().get(rid)
    flush_events()
    if r is None or r["requester_jti"] != requester_jti:
        raise Refused("OUT_OF_SCOPE", "no such request for this mandate", status=404)
    return agent_view(r)


# ---------------------------------------------------------------- decisions


def _approved_grant(r: dict, narrowed: dict | None) -> dict:
    requested = {k: r["requested"][k] for k in ("scope", "clearance", "ttl")}
    if requested["clearance"] is None:  # no clearance asked for: the parent's carries over
        requested["clearance"] = r["parent_clearance"]
    if narrowed is None:
        return requested
    approved = {
        "scope": narrowed.get("scope", requested["scope"]),
        "clearance": narrowed.get("clearance", requested["clearance"]),
        "ttl": narrowed.get("ttl", requested["ttl"]),
    }
    if not narrower_or_equal(requested, approved):
        raise Refused("NOT_NARROWER", "an approval can only grant less than was asked")
    return approved


def _with_parent_rate(entry: dict, parent_scope: list[dict]) -> dict:
    """The entry, with the rate of the parent entry it narrows (if any, and if it has none of its own)."""
    if "rate" in entry:
        return entry
    for held in parent_scope:
        if "rate" in held and entry_covers(held, entry):
            return {**entry, "rate": held["rate"]}
    return entry


def summary_of(r: dict) -> str:
    """The request in words: what was approved once it is, what was asked for until then."""
    approved = r.get("approved")
    if r["status"] != "approved" or not approved or r["held"]:
        return r["requested"]["summary"]
    clearance = approved.get("clearance")
    clearance = clearance if clearance is not None else r.get("parent_clearance")  # what the minted mandate carries
    return grants_words(approved["scope"], clearance=clearance, ttl=approved.get("ttl"))


def mint_for(r: dict, approved: dict, approved_by: dict, *, not_after: int | None = None) -> tuple[str, str]:
    """`not_after`: a supervising agent's expiry; what it approves can't outlive it."""
    now = int(time.time())
    ttl = min(approved["ttl"], r["parent_exp"] - now)
    if not_after is not None:
        ttl = min(ttl, not_after - now)
    if r["held"]:
        ttl = min(ttl, HELD_TTL)
    if ttl <= 0:
        raise Refused("PARENT_EXPIRED", "the requesting mandate has expired")
    extra = {
        "parent": {"jti": r["requester_jti"], "status": r["parent_status"], "mandate_hash": r["parent_mandate_hash"]},
        "approved_by": {**approved_by, "request_id": r["id"]},
    }
    # run budgets count per family but read their size from the calling mandate, so a child carries its
    # parent's budget unchanged, and each entry that narrows a parent entry keeps that entry's rate
    if r["requested"].get("parent_budget") is not None:
        extra["budget"] = r["requested"]["parent_budget"]
    scope = [_with_parent_rate(e, r["requested"]["parent_scope"]) for e in approved["scope"]]
    clearance = approved["clearance"] if approved["clearance"] is not None else r["parent_clearance"]
    if clearance is not None:
        extra["clearance"] = clearance
    if r["held"]:  # each released call once: one action hash per held call
        extra["preapproved"] = [
            action_hash(h["server"], h["tool"], h["arguments"], r["parent_mandate_hash"]) for h in held_calls(r["held"])
        ]
    token, _idx = issue_mandate(
        STATE_DIR,
        jwk_to_pub(r["cnf_jwk"]),
        scope=scope,
        deny=r["deny"],
        ttl=ttl,
        purpose=summary_of(r)[:500],  # r is already decided, so these are the approved grant's words
        principal=r["principal"],
        org=r["org"] or "",
        extra=extra,
    )
    jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    return token, jti


def _check_mintable(r: dict, approved: dict) -> None:
    """Everything that could stop minting, checked before the decision is recorded, so an approval never
    strands a request as approved with no mandate."""
    if r["parent_exp"] - int(time.time()) <= 0:
        raise Refused("PARENT_EXPIRED", "the requesting mandate has expired")
    if over := within_ceiling(_json_file("principals.json").get(r["principal"]), approved["scope"],
                              approved["clearance"]):  # fmt: skip
        raise Refused("EXCEEDS_PRINCIPAL", over)


def _approve_or_reject(
    r: dict, decision: str, approved_by: dict, narrowed: dict | None, *, not_after: int | None = None
) -> dict:
    if decision not in ("approve", "reject"):
        raise Refused("DECISION_INVALID", "decision must be approve or reject")
    if decision == "reject":
        try:
            r = store().decide(r["id"], "rejected", approved_by)
        except AlreadyDecided as e:
            raise Refused("ALREADY_DECIDED", r["id"]) from e
        store().enqueue({"event_type": "approval_denied", "request": r, "reason_code": "REJECTED",
                         "approver": approved_by})  # fmt: skip
        flush_events()
        return agent_view(r)
    approved = _approved_grant(r, narrowed)
    _check_mintable(r, approved)  # the person's ceiling is re-read here: it may have changed since the request
    try:
        r = store().decide(r["id"], "approved", approved_by, approved)
    except AlreadyDecided as e:
        raise Refused("ALREADY_DECIDED", r["id"]) from e
    token, jti = mint_for(r, approved, approved_by, not_after=not_after)
    store().set_minted(r["id"], jti, token)
    r = store().get(r["id"])
    store().enqueue({"event_type": "approval_granted", "request": r, "reason_code": "APPROVED",
                     "approver": approved_by, "minted_jti": jti})  # fmt: skip
    flush_events()
    return agent_view(r)


class SupervisorBody(BaseModel):
    call: dict


@app.post("/internal/requests/{rid}/supervisor-decision")
def supervisor_decision(rid: str, body: SupervisorBody):
    claims = verify_call(body.call, "decide")
    r = store().get(rid)
    if r is None:
        raise Refused("OUT_OF_SCOPE", "no such request", status=404)
    args = body.call["arguments"]

    def refuse(code: str, detail: str, **extra):
        store().refuse(rid, code)
        raise Refused(code, detail, **extra)

    if args.get("request_id") != rid:
        refuse("CALL_INVALID", "the signed decision names a different request")
    if r["status"] != "pending":
        refuse("ALREADY_DECIDED", r["status"])
    if r["held"]:
        refuse("EXCEEDS_SUPERVISOR", "releasing a held call needs a person", next_action="ask_user")
    if claims.get("can_delegate") is not True:
        refuse("EXCEEDS_SUPERVISOR", "the supervisor's mandate does not allow delegation", next_action="ask_user")
    if (claims.get("delegator") or {}).get("principal") != r["principal"]:
        refuse("EXCEEDS_SUPERVISOR", "a different person's mandate", next_action="ask_user")
    if claims.get("agent_id") == r["requester_agent_id"]:
        refuse("SELF_APPROVAL", "an agent can't approve its own request")
    approved = _approved_grant(r, args.get("approved"))
    if args.get("decision") == "approve" and not (
        scope_covers(claims.get("scope", []), approved["scope"])
        and clearance_covers(claims.get("clearance"), approved["clearance"], approved["scope"])
    ):
        refuse("EXCEEDS_SUPERVISOR", "the supervisor's own mandate doesn't cover this", next_action="ask_user")
    # the minted mandate carries the supervisor's status, so the gateway can withdraw it with the supervisor
    who = {"kind": "agent", "id": claims.get("agent_id"), "mandate_jti": claims["jti"],
           "status": claims["status"]["status_list"]}  # fmt: skip
    return _approve_or_reject(r, args.get("decision"), who, args.get("approved"), not_after=claims["exp"])


# ---------------------------------------------------------------- the person: login, view, decision


def _approver_pub(principal: str):
    jwk = _json_file("approvers.json").get(principal)
    return jwk_to_pub(jwk) if jwk else None


class LoginBody(BaseModel):
    token: str


@app.post("/approver/login")
def approver_login(body: LoginBody):
    """Swap a one-time login token, signed with a person's approver key, for a short approver session."""
    try:
        unverified = jwt.decode(body.token, options={"verify_signature": False})
        principal = unverified["sub"]
        pub = _approver_pub(principal)
        if pub is None:
            raise Refused("APPROVER_UNKNOWN", principal, status=401)
        claims = jwt.decode(body.token, pub_to_pem(pub), algorithms=["EdDSA"], options={"require": ["exp", "jti"]})
    except Refused:
        raise
    except (jwt.PyJWTError, KeyError) as e:
        raise Refused("LOGIN_INVALID", type(e).__name__, status=401) from e
    if jwt.get_unverified_header(body.token).get("typ") != LOGIN_TYP:
        raise Refused("LOGIN_INVALID", "wrong token type", status=401)
    if claims["exp"] - claims.get("iat", claims["exp"]) > LOGIN_MAX_AGE:
        raise Refused("LOGIN_INVALID", "login tokens live at most 5 minutes", status=401)
    if not store().use_login_token(claims["jti"]):
        raise Refused("LOGIN_REUSED", "this login link was already used", status=401)
    return store().new_session(principal)


def still_granted(r: dict) -> list[dict]:
    """Earlier approvals for the same mandate whose minted mandates still work (not expired, not revoked, parent
    and approver alive), so many narrow approvals can be seen together instead of each looking small. Held-call
    releases are left out (store.approved_for): they release exact calls once and grant no standing access."""
    registry = TrustedList(_json_file("trusted_list.json"))
    meta = _json_file("status_list.json")
    status_lists = {meta["uri"]: (STATE_DIR / "status_list.jwt").read_text().strip()}
    live = []
    for earlier in store().approved_for(r["requester_jti"]):
        if earlier["id"] == r["id"]:
            continue
        try:
            claims = verify_mandate(earlier["minted"], registry, status_lists)
        except Reject:
            continue
        live.append({"request_id": earlier["id"], "summary": summary_of(earlier), "expires_at": claims["exp"]})
    return live


@app.get("/requests/{rid}/view")
def request_view(rid: str, x_approver_session: str | None = Header(default=None)):
    """What the approval page shows. Argument values and the agent's reason only with an approver session."""
    r = store().get(rid)
    flush_events()
    if r is None:
        raise HTTPException(404, "no such request")
    principal = store().session_principal(x_approver_session)
    view = {
        "request_id": r["id"],
        "status": r["status"],
        "summary": r["requested"]["public_summary"],
        "expires_at": r["expires"],
        "principal": r["principal"],
        "level_4": r["requested"]["level_4"],
        "signed_in_as": principal,
        "can_decide": principal == r["principal"] and r["status"] == "pending",
    }
    if principal == r["principal"]:
        view.update(
            # all three, in the order fixed when the request was made; nothing in the view says which is right
            number_options=r["match_options"] if r["status"] == "pending" else None,
            summary=r["requested"]["summary"],
            current=grants_words(r["requested"]["parent_scope"], clearance=r["parent_clearance"]),
            already_approved=still_granted(r),
            requested=r["requested"],
            agent_id=r["requester_agent_id"],
            agent_reason=r["reason"],  # the agent's own words: shown as plain text, never trusted
            held_action=held_words(held_calls(r["held"]))[0] if len(held_calls(r["held"])) == 1 else None,
            held_actions=held_words(held_calls(r["held"])) if r["held"] else None,
        )
    return view


class DecisionBody(BaseModel):
    decision: str
    number: int | None = None  # the number chosen from the three on the page; needed to approve
    approved: dict | None = None
    signed: str | None = None  # a decision JWT signed with the approver key (cli approve)


@app.post("/requests/{rid}/decision")
def person_decision(rid: str, body: DecisionBody, x_approver_session: str | None = Header(default=None)):
    r = store().get(rid)
    if r is None:
        raise HTTPException(404, "no such request")

    def refuse(code: str, detail: str, status: int = 403):
        store().refuse(rid, code)
        raise Refused(code, detail, status=status)

    principal = None
    if body.signed:
        pub = _approver_pub(r["principal"])
        try:
            claims = jwt.decode(body.signed, pub_to_pem(pub), algorithms=["EdDSA"]) if pub else None
        except jwt.PyJWTError:
            claims = None
        ok = (
            claims
            and jwt.get_unverified_header(body.signed).get("typ") == DECISION_TYP
            and claims.get("sub") == r["principal"]
            and claims.get("request_id") == rid
            and claims.get("decision") == body.decision
            and claims.get("approved_hash") == sha256_hex(canonical(body.approved))
            and store().use_login_token(claims.get("jti", ""))
        )
        principal = r["principal"] if ok else None
    else:
        principal = store().session_principal(x_approver_session)
    if principal is None:
        refuse("APPROVER_REQUIRED", "sign in with your approver key to decide", status=401)
    if principal != r["principal"]:
        refuse("NOT_THE_APPROVER", f"this request is for {r['principal']}")
    if r["status"] != "pending":
        refuse("ALREADY_DECIDED", r["status"])
    person = {"kind": "person", "id": principal}
    if body.decision == "approve":  # rejecting needs no number: saying no is the safe direction
        _check_number(r, body.number, person)
    return _approve_or_reject(r, body.decision, person, body.approved)


def _check_number(r: dict, number: int | None, person: dict) -> None:
    """Called only once the right person is signed in, so a stranger's wrong guess can't end the request.

    A wrong pick ends the request: one guess, not three. It isn't the person saying no, so the agent may ask
    again straight away (it doesn't count towards RECENTLY_REJECTED)."""
    if number is None:
        store().refuse(r["id"], "NUMBER_REQUIRED")
        raise Refused("NUMBER_REQUIRED", "choose the number the agent gave you", status=400)
    if number == r["match_number"]:
        return
    try:
        r = store().decide(r["id"], "rejected", person, end_reason=NUMBER_MISMATCH)
    except AlreadyDecided as e:
        raise Refused("ALREADY_DECIDED", r["id"]) from e
    store().refuse(r["id"], NUMBER_MISMATCH)
    # no approver on the event, so its reason code is NUMBER_MISMATCH rather than NUMBER_MISMATCH_BY_PERSON
    store().enqueue({"event_type": "approval_denied", "request": r, "reason_code": NUMBER_MISMATCH})
    flush_events()
    raise Refused(NUMBER_MISMATCH, "not the number the agent gave; the request has ended, so ask the agent again")


@app.get("/healthcheck")
def healthcheck() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------- audit events to the gateway


def _issuer_key():
    status, meta = _load_status(STATE_DIR)
    return status.priv, meta


def sign_event(event: dict) -> str:
    """An approval event signed with the issuer key, in the audit trail's own format (audit.sign_external_event).

    The event's outbox ID is its UUID, so a retried delivery is recorded once.
    """
    priv, meta = _issuer_key()
    r = event["request"]
    approver = event.get("approver") or {}
    person = approver.get("kind") == "person"
    return sign_external_event(
        priv,
        iss=meta["issuer"],
        kid=meta["kid"],
        event_type=event["event_type"],
        mandate_jti=r["requester_jti"],
        server="grants",
        tool="request",
        ref_decision_id=r.get("ref_decision_id") or f"request:{r['id']}",
        reason_code=event["reason_code"] + ("_BY_PERSON" if person else "_BY_AGENT" if approver else ""),
        # who decided: the person, or the supervising agent's key; otherwise the requester
        principal=approver.get("id") if person else r["principal"],
        agent_id=approver.get("id") if approver and not person else r["requester_agent_id"],
        event_id=event["id"],
        minted_jti=event.get("minted_jti"),  # approval_granted: the supplementary mandate it produced
        ttl=86400,  # the outbox may retry for up to a day
    )


_poster = None  # tests replace this to deliver events in process


def flush_events() -> int:
    """Send unsent events to the gateway; anything that fails stays queued for the next attempt."""
    sent = 0
    for outbox_id, event in store().unsent():
        token = sign_event(event)
        try:
            if _poster is not None:
                _poster(token)
            else:
                req = urllib.request.Request(  # noqa: S310
                    f"{GATEWAY_INTERNAL_URL}/internal/audit-events",
                    data=json.dumps({"token": token}).encode(),
                    headers={"content-type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=2):  # noqa: S310
                    pass
        except (urllib.error.URLError, OSError, RuntimeError):
            log.warning("audit event not delivered yet; will retry", exc_info=True)
            break
        store().mark_sent(outbox_id)
        sent += 1
    return sent
