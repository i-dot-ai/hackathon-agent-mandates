"""Gateway verification pipeline.

    receive (request, mandate)
      -> verify mandate: issuer accredited / signature / time / revocation
      -> verify proof of possession (request signed by cnf key, fresh nonce and ts)
      -> check request against scope, deny and constraints
      -> decision record {ALLOW | DENY | STEP_UP, reason_code, ...}

Reason codes are stable strings so the audit log and Day 2 scorecard can
count them. Order of checks is deliberate: cheapest and most definitive first.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import posixpath
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import jwt

from .common import canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .audience import check_audience
from .grants import GRANTS_SERVER, GRANTS_TOOLS
from .graded import special_category_read
from .interfaces import check_clearance
from .status_list import is_revoked

POLICY_VERSION = "2026-11-18.1"
CLOCK_SKEW = 30
# Most rows one call may ask for (the MCP server's own default).
# shortcut: per call only, many small calls still add up (question 11); add a per-mandate budget for that
MAX_ROWS = 100
# scope-constrained arguments the audit trail may record by value: they say whose data a call concerned
AUDITED_SCOPE_KEYS = ("urn", "pupil_id")

log = logging.getLogger(__name__)


class Reject(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class Decision:
    decision: str  # ALLOW | DENY | STEP_UP
    reason_code: str
    policy_version: str
    mandate_hash: str
    request_hash: str
    agent_id: str | None
    ts: float
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditContext:
    """What the audit trail needs about a call beyond the Decision. Never returned to the caller.

    `claims` is set only when the mandate and the request signature both verified (identity_verified). Before
    that, `claimed_jti` / `claimed_iss` hold whatever the mandate says, read without trusting it.
    """

    identity_verified: bool = False
    claims: dict | None = None
    kid: str | None = None
    claimed_jti: str | None = None
    claimed_iss: str | None = None
    scope_values: dict[str, str] = field(default_factory=dict)
    entry: dict | None = None  # the scope entry that allowed or held the call; the tool grant derives from it


def _claimed_identity(token: str) -> tuple[str | None, str | None, str | None]:
    """(jti, iss, kid) as the mandate states them, unverified; Nones when it doesn't parse."""
    try:
        hdr = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001  (anything unparseable just has no claimed identity)
        return None, None, None
    as_str = lambda v: v if isinstance(v, str) else None  # noqa: E731
    return as_str(payload.get("jti")), as_str(payload.get("iss")), as_str(hdr.get("kid"))


def _scope_values(req: Request, scope: list[dict]) -> dict[str, str]:
    """Values of the audited keys that some scope entry for this server and tool constrains."""
    constrained = {
        k
        for entry in scope
        if entry.get("server") == req.server and req.tool in entry.get("tools", [])
        for k in entry.get("constraints", {})
    }
    return {k: str(req.arguments[k]) for k in AUDITED_SCOPE_KEYS if k in constrained and k in req.arguments}


@dataclass
class Request:
    """What the agent sends to the gateway for a tools/call."""

    server: str
    tool: str
    arguments: dict
    mandate: str  # compact JWT
    nonce: str
    ts: int
    sig: str  # Ed25519 over canonical(signing_input()) by cnf key

    def signing_input(self) -> bytes:
        return canonical(
            {
                "server": self.server,
                "tool": self.tool,
                "arguments": self.arguments,
                "mandate_hash": sha256_hex(self.mandate.encode()),
                "nonce": self.nonce,
                "ts": self.ts,
            }
        )


# ---------------------------------------------------------------- mandate


def verify_mandate(token: str, registry, status_lists: dict[str, str]) -> dict:
    """Returns the verified claims. Raises Reject."""
    hdr = jwt.get_unverified_header(token)
    if hdr.get("typ") != "mandate+jwt":
        raise Reject("WRONG_TOKEN_TYPE", hdr.get("typ"))
    unverified = jwt.decode(token, options={"verify_signature": False})

    pub = registry.issuer_key(unverified["iss"], hdr.get("kid", ""))
    if pub is None:
        raise Reject("ISSUER_NOT_ACCREDITED", unverified["iss"])
    try:
        claims = jwt.decode(
            token,
            pub_to_pem(pub),
            algorithms=["EdDSA"],
            options={"verify_exp": False, "verify_nbf": False, "require": ["exp", "iss", "jti"]},
        )
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))

    now = time.time()
    if claims.get("nbf", 0) > now + CLOCK_SKEW:
        raise Reject("NOT_YET_VALID", claims["jti"])
    # no skew on expiry: a mandate is dead the second it expires (the skew only forgives early clocks on nbf)
    if claims["exp"] <= now:
        raise Reject("EXPIRED", claims["jti"])

    sl = claims["status"]["status_list"]
    sl_jwt = status_lists.get(sl["uri"])
    if sl_jwt is None:
        raise Reject("STATUS_UNAVAILABLE", sl["uri"])  # fail closed
    try:
        if is_revoked(sl_jwt, sl["idx"], pub, sl["uri"]):
            raise Reject("REVOKED", claims["jti"])
    except ValueError as e:
        raise Reject("STATUS_UNAVAILABLE", str(e))
    # a supplementary mandate dies with the one it was minted from (add-scope-requests)
    if (parent := claims.get("parent")) is not None:
        psl = (parent.get("status") or {}) if isinstance(parent, dict) else {}
        parent_jwt = status_lists.get(psl.get("uri"))
        if parent_jwt is None or "idx" not in psl:
            raise Reject("STATUS_UNAVAILABLE", f"parent status list {psl.get('uri')}")
        try:
            if is_revoked(parent_jwt, psl["idx"], pub, psl["uri"]):
                raise Reject("PARENT_REVOKED", parent.get("jti", ""))
        except ValueError as e:
            raise Reject("STATUS_UNAVAILABLE", str(e))
    # ...and with the supervising agent that approved it: revoking a compromised supervisor withdraws its approvals
    approved_by = claims.get("approved_by")
    if isinstance(approved_by, dict) and approved_by.get("kind") == "agent":
        asl = approved_by.get("status") if isinstance(approved_by.get("status"), dict) else {}
        approver_jwt = status_lists.get(asl.get("uri"))
        if approver_jwt is None or "idx" not in asl:
            raise Reject("STATUS_UNAVAILABLE", f"approver status list {asl.get('uri')}")  # fail closed
        try:
            if is_revoked(approver_jwt, asl["idx"], pub, asl["uri"]):
                raise Reject("APPROVER_REVOKED", approved_by.get("mandate_jti", ""))
        except ValueError as e:
            raise Reject("STATUS_UNAVAILABLE", str(e))
    return claims


# ---------------------------------------------------------------- scope


def check_request(
    req: Request,
    scope: list[dict],
    deny: list[str],
    step_up_patterns: list[str],
    claims: dict,
    matched: list | None = None,
) -> tuple[str, str, str]:
    """(decision, reason_code, detail). When the call is allowed or held, the accepting scope entry is appended
    to `matched`, so the tool grant can be derived from exactly what allowed it."""
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    # clearance before scope, so no shape of scope entries can route around it
    if refused := check_clearance(req.server, claims, req.tool):
        return refused
    # the gateway's own grants server needs no scope entry: it only ever concerns the calling mandate
    if req.server == GRANTS_SERVER:
        return ("ALLOW", "IN_SCOPE", "") if req.tool in GRANTS_TOOLS else ("DENY", "OUT_OF_SCOPE", name)
    # Each entry is a whole grant: the call is allowed if any one entry accepts every argument it constrains,
    # so a request cannot take urn from one entry and path from another.
    refused = None  # the first matching entry's reason, reported when no entry accepts the call
    for entry in scope:
        if entry["server"] != req.server or req.tool not in entry["tools"]:
            continue
        for k, allowed in entry.get("constraints", {}).items():
            if k not in req.arguments:
                refused = refused or ("DENY", "CONSTRAINT_MISSING", k)
                break
            value = req.arguments[k]
            if k == "path" and isinstance(value, str):
                # one file, one spelling: "./a//b" and "a/x/../b" compare as "a/b". Anything still starting
                # with ".." or "/" cannot equal an allowed relative path, so it stays denied.
                # shortcut: lexical only, agrees with the MCP server's resolve() while the data dir has no symlinks
                value = posixpath.normpath(value)
            if str(value) not in set(map(str, allowed)):
                refused = refused or ("DENY", "CONSTRAINT_VIOLATED", f"{k}={req.arguments[k]!r}")
                break
        else:
            # whose data: an entry with an audience only covers the pupils it lists (mandate-audience)
            if outside := check_audience(entry, req.arguments):
                refused = refused or outside
                continue
            limit = req.arguments.get("limit", MAX_ROWS)
            if type(limit) is not int or not 0 <= limit <= MAX_ROWS:
                return "DENY", "TOO_MUCH", f"limit={limit!r}, at most {MAX_ROWS}"
            if req.tool == "search" and not str(req.arguments.get("query", "")).strip():
                return "DENY", "TOO_MUCH", "empty query matches every row"
            if matched is not None:
                matched.append(entry)
            # special category is asked for call by call (add-graded-pupil-data)
            if special_category_read(req.server, req.tool, req.arguments, claims):
                return "STEP_UP", "SPECIAL_CATEGORY", f"{req.server}.{req.tool} returns level 4 data"
            for pat in step_up_patterns:
                if fnmatch.fnmatch(name, pat):
                    return "STEP_UP", "SENSITIVE_TOOL", pat
            return "ALLOW", "IN_SCOPE", ""
    return refused or ("DENY", "OUT_OF_SCOPE", name)


# ---------------------------------------------------------------- pre-approved held calls


def action_hash(server: str, tool: str, arguments: dict, mandate_hash: str) -> str:
    """What one held call was: server, tool, exact arguments and the mandate it was held under. No nonce or ts,
    so the approved retry of the same call has the same hash."""
    return sha256_hex(canonical({"server": server, "tool": tool, "arguments": arguments, "mandate_hash": mandate_hash}))


class PreapprovalUses:
    """Which pre-approved actions have been used. SQLite at GATEWAY_STATE_DB (durable), else memory."""

    def __init__(self, path: str | None):
        self._mem: set[tuple[str, str]] = set()
        self._db = None
        if path:
            import sqlite3  # noqa: PLC0415

            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS preapproval_uses (jti TEXT NOT NULL, action_hash TEXT NOT NULL, "
                "used_at REAL NOT NULL, PRIMARY KEY (jti, action_hash))"
            )

    def use(self, jti: str, ah: str) -> bool:
        """True the first time; False if this mandate already used this pre-approval."""
        if self._db is None:
            if (jti, ah) in self._mem:
                return False
            self._mem.add((jti, ah))
            return True
        import sqlite3  # noqa: PLC0415

        try:
            self._db.execute("INSERT INTO preapproval_uses VALUES (?, ?, ?)", (jti, ah, time.time()))
        except sqlite3.IntegrityError:
            return False
        return True


# ---------------------------------------------------------------- the pipeline


class Gateway:
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft", "special.*"]
        self._seen_nonces: set[str] = set()
        self.preapproval_uses = PreapprovalUses(os.environ.get("GATEWAY_STATE_DB"))

    def _preapproved(self, req: Request, claims: dict) -> str | None:
        """The action hash when this held call is pre-approved by the mandate and not yet used, else None.

        Using it is recorded here, before the call is forwarded, so it goes through once.
        """
        preapproved = claims.get("preapproved") or []
        parent_hash = (claims.get("parent") or {}).get("mandate_hash")
        if not preapproved or not parent_hash:
            return None
        ah = action_hash(req.server, req.tool, req.arguments, parent_hash)
        if ah not in preapproved:
            return None
        return ah if self.preapproval_uses.use(claims["jti"], ah) else None

    def decide(self, req: Request) -> Decision:
        return self.decide_with_context(req)[0]

    def decide_with_context(self, req: Request) -> tuple[Decision, AuditContext]:
        base = dict(
            policy_version=POLICY_VERSION,
            mandate_hash=sha256_hex(req.mandate.encode()),
            request_hash=sha256_hex(req.signing_input()),
            ts=time.time(),
        )
        ctx = AuditContext()
        try:
            claims = verify_mandate(req.mandate, self.registry, self.status_lists)
            jwk = claims["cnf"]["jwk"]
            if abs(req.ts - time.time()) > 300:
                raise Reject("POP_FAILED", "request timestamp outside window")
            if req.nonce in self._seen_nonces:
                raise Reject("POP_FAILED", "replayed nonce")
            if not verify_bytes(jwk_to_pub(jwk), req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {jwk_thumbprint(jwk)}")
            self._seen_nonces.add(req.nonce)
            ctx.identity_verified, ctx.claims = True, claims
            ctx.kid = jwt.get_unverified_header(req.mandate).get("kid")  # header was checked with the signature

            ctx.scope_values = _scope_values(req, claims["scope"])
            matched: list[dict] = []
            decision, code, detail = check_request(
                req, claims["scope"], claims["deny"], self.step_up, claims, matched
            )
            ctx.entry = matched[0] if matched else None
            if decision == "STEP_UP" and (ah := self._preapproved(req, claims)):
                decision, code, detail = "ALLOW", "PREAPPROVED", ah
            return Decision(decision, code, agent_id=claims["agent_id"], detail=detail, **base), ctx
        except Reject as r:
            result = Decision("DENY", r.code, agent_id=None, detail=r.detail, **base)
        except Exception:  # anything else (an unparseable mandate, a malformed claim) fails closed, never a 500
            log.warning("unexpected error deciding a call", exc_info=True)
            result = Decision("DENY", "MANDATE_MALFORMED", agent_id=None, **base)
        if not ctx.identity_verified:
            ctx.claims = None
            ctx.claimed_jti, ctx.claimed_iss, ctx.kid = _claimed_identity(req.mandate)
        return result, ctx
