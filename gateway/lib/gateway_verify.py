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
import posixpath
import time
import zlib
from dataclasses import asdict, dataclass

import jwt

from .common import canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .nonce_store import MemoryNonces
from .status_list import is_revoked

POLICY_VERSION = "2026-11-18.1"
CLOCK_SKEW = 30
# Most rows one call may ask for (the MCP server's own default).
# shortcut: per call only, many small calls still add up (question 11); add a per-mandate budget for that
MAX_ROWS = 100
# Smallest count released as itself. Every aggregate total and count is rounded to the nearest multiple, the
# large ones too, so two answers cannot be subtracted to recover a small one. main.py lets GATEWAY_SMALL_COUNT
# replace it; no mandate claim can.
# shortcut: counts are census rows, and one pupil can be five of them
SMALL_COUNT = 10
# Columns that name one pupil: an aggregate grouped or filtered by one is that pupil's record.
IDENTIFIERS = frozenset({"Psuedo ID", "DisplayName"})
# A result at PRIVATE_LEVEL needs one of PRIVATE_ROLES as well as the clearance. The issuer signs the role the person
# holds into the agent's mandate; the gateway says which roles open the data. main.py lets GATEWAY_PRIVATE_ROLES
# replace the list; no mandate claim can.
PRIVATE_LEVEL = 4
PRIVATE_ROLES = frozenset({"safeguarding-lead"})
# Files `get` may label below max_level without a table label. Any other non-CSV file is unlabelled, so level 4.
PUBLIC_FILES = frozenset({"synthetic/synthetic_manifest.json"})
# What each row-returning tool can hand back, by table (all its columns) or column name. The gateway decides
# clearance from this before forwarding, so the answer cannot depend on what the data holds (question 6).
# A tool missing here, and not handled in request_levels, is unlabelled and needs max_level.
TOOL_RETURNS = {
    "search": ("personal_data_school_census",),
    "pupil": ("personal_data_school_census", "display_names", "personal_data_deprivation"),
    "roster": ("Psuedo ID", "DisplayName"),
    "draft": ("Psuedo ID", "letter"),
}
# Shortest search query: below this a substring matches most rows of the school.
MIN_QUERY = 3
# Longest nonce the gateway stores.
MAX_NONCE = 128
# Anything raised while parsing a hostile request is a refusal, never a 500.
_MALFORMED = (jwt.PyJWTError, KeyError, TypeError, ValueError, OverflowError, AttributeError)


class Reject(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class Decision:
    decision: str            # ALLOW | DENY | STEP_UP
    reason_code: str
    policy_version: str
    mandate_hash: str
    request_hash: str
    agent_id: str | None
    ts: float
    clearance: int | None = None  # from the mandate; main.py enforces it against the result
    role: str | None = None  # from the mandate; main.py checks it when the result reaches PRIVATE_LEVEL
    detail: str = ""
    notice: str = ""  # for the person whose data it is, when an agent asks without clearance
    sensitivity: dict | None = None  # the labels on the result and the ones that decided
    disclosure: dict | None = None  # how the result was changed before release

    def to_dict(self) -> dict:
        raw = asdict(self)
        for key in ("role", "notice", "sensitivity", "disclosure"):
            if not raw[key]:
                del raw[key]
        return raw


@dataclass
class Request:
    """What the agent sends to the gateway for a tools/call."""
    server: str
    tool: str
    arguments: dict
    mandate: str             # compact JWT
    nonce: str
    ts: int
    sig: str                 # Ed25519 over canonical(signing_input()) by cnf key

    def signing_input(self) -> bytes:
        return canonical({
            "server": self.server, "tool": self.tool, "arguments": self.arguments,
            "mandate_hash": sha256_hex(self.mandate.encode()), "nonce": self.nonce, "ts": self.ts,
        })


# ---------------------------------------------------------------- mandate

def verify_mandate(token: str, registry, status_lists: dict[str, str]) -> dict:
    """Returns the verified claims. Raises Reject."""
    hdr = jwt.get_unverified_header(token)
    if hdr.get("typ") != "mandate+jwt":
        raise Reject("WRONG_TOKEN_TYPE", hdr.get("typ"))
    unverified = jwt.decode(token, options={"verify_signature": False})
    iss, kid = unverified.get("iss"), hdr.get("kid", "")
    if not isinstance(iss, str) or not isinstance(kid, str):
        raise Reject("MALFORMED", "iss and kid must be strings")

    pub = registry.issuer_key(iss, kid)
    if pub is None:
        raise Reject("ISSUER_NOT_ACCREDITED", iss)
    try:
        claims = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                            options={"verify_exp": False, "verify_nbf": False, "require": ["exp", "iss", "jti"]})
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))

    now = time.time()
    if claims.get("nbf", 0) > now + CLOCK_SKEW:
        raise Reject("NOT_YET_VALID", claims["jti"])
    if claims["exp"] < now - CLOCK_SKEW:
        raise Reject("EXPIRED", claims["jti"])

    sl = claims["status"]["status_list"]
    sl_jwt = status_lists.get(sl["uri"])
    if sl_jwt is None:
        raise Reject("STATUS_UNAVAILABLE", sl["uri"])     # fail closed
    try:
        if is_revoked(sl_jwt, sl["idx"], pub, sl["uri"]):
            raise Reject("REVOKED", claims["jti"])
    except (ValueError, KeyError, TypeError, jwt.PyJWTError, zlib.error) as e:
        # a stale, forged or half-written list fails closed
        raise Reject("STATUS_UNAVAILABLE", str(e))
    return claims


# ---------------------------------------------------------------- scope

# A wrong value is more useful than a missing one when several entries all fail.
_FAIL_RANK = {"CONSTRAINT_VIOLATED": 2, "CONSTRAINT_MISSING": 1}


def _norm_path(value: str) -> str:
    """Same file, different spelling. `..` and absolute paths stay visibly out of the tree.

    Lexical only: it agrees with the data server's resolve() while the data directory has no symlinks.
    """
    return posixpath.normpath(value)


def _constraint_holds(key: str, raw, allowed) -> bool:
    if key == "path":
        return _norm_path(str(raw)) in {_norm_path(str(item)) for item in allowed}
    return str(raw) in {str(item) for item in allowed}


def _identifiers(arguments: dict) -> list[str]:
    group_by, where = arguments.get("group_by"), arguments.get("where")
    fields = [*(group_by if isinstance(group_by, list) else []), *(where if isinstance(where, dict) else [])]
    return [field for field in fields if isinstance(field, str) and field in IDENTIFIERS]


def check_request(req: Request, scope: list[dict], deny: list[str], step_up_patterns: list[str]) -> tuple[str, str, str]:
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    # Each entry is a whole grant: the call is allowed if any one entry accepts every argument it constrains,
    # so a request cannot take urn from one entry and path from another.
    failure: tuple[str, str, str] | None = None
    for entry in scope:
        if entry["server"] != req.server or req.tool not in entry["tools"]:
            continue
        entry_fail: tuple[str, str, str] | None = None
        for key, allowed in entry.get("constraints", {}).items():
            if key not in req.arguments:
                entry_fail = ("DENY", "CONSTRAINT_MISSING", key)
                break
            if not _constraint_holds(key, req.arguments[key], allowed):
                entry_fail = ("DENY", "CONSTRAINT_VIOLATED", f"{key}={req.arguments[key]!r}")
                break
        if entry_fail is not None:
            if failure is None or _FAIL_RANK.get(entry_fail[1], 0) > _FAIL_RANK.get(failure[1], 0):
                failure = entry_fail
            continue
        limit = req.arguments.get("limit", MAX_ROWS)
        if type(limit) is not int or not 0 <= limit <= MAX_ROWS:
            return "DENY", "TOO_MUCH", f"limit={limit!r}, at most {MAX_ROWS}"
        # An empty search matches every row of the granted school. Question 0 searches all have a query.
        if req.tool == "search":
            query = str(req.arguments.get("query", "")).strip()
            if not query:
                return "DENY", "TOO_MUCH", "empty query matches every row"
            # rows are matched as one comma-joined string: a comma matches every row, and a query with commas
            # tests several columns at once ("P0011,F,ASIA")
            if "," in query:
                return "DENY", "TOO_MUCH", "a query may not contain a comma"
            if len(query) < MIN_QUERY:
                return "DENY", "TOO_MUCH", f"query must be at least {MIN_QUERY} characters"
        named = _identifiers(req.arguments) if req.tool == "aggregate" else []
        if named:
            return "DENY", "TOO_FINE", f"{named[0]} makes each group one pupil"
        for pat in step_up_patterns:
            if fnmatch.fnmatch(name, pat):
                return "STEP_UP", "SENSITIVE_TOOL", pat
        return "ALLOW", "IN_SCOPE", ""
    return failure or ("DENY", "OUT_OF_SCOPE", name)


# ---------------------------------------------------------------- classification (question 6)

def sensitivity_maps(classification: dict) -> tuple[dict[str, int], dict[str, int]]:
    """Column and table -> PII level, from the manifest's classification block."""
    columns: dict[str, int] = {}
    for cols in classification["columns"].values():
        for col, level in cols.items():
            columns[col] = max(columns.get(col, 0), level)
    return columns, classification["tables"]


def result_max_level(tool: str, arguments: dict, result, columns: dict[str, int],
                     tables: dict[str, int], max_level: int) -> int:
    """The highest sensitivity the result carries. Deny-on-max: this one number decides.

    Unknown column keys fail closed at max_level: a column with no label is not public.
    """
    return max(result_levels(tool, arguments, result, columns, tables, max_level).values(), default=0)


UNLABELLED = "(unlabelled value)"


def _filter_levels(tool: str, arguments: dict, columns: dict[str, int], max_level: int) -> dict[str, int]:
    where = arguments.get("where") if tool == "aggregate" else None
    if where is None:
        return {}
    if not isinstance(where, dict):
        return {"where (filter)": max_level}
    # a count of one ethnic group says as much about ethnicity as grouping by it, with or without rows
    return {f"{k} (filter)": columns.get(str(k), max_level) for k in where}


def result_levels(tool: str, arguments: dict, result, columns: dict[str, int],
                  tables: dict[str, int], max_level: int) -> dict[str, int]:
    """Each labelled part of the result and its level: a column, or the whole table for `get`.

    Fails closed: a value with no label, a row that is not a flat dict, or a file not listed is max_level.
    """
    if result is None:
        return {}
    if tool == "get":
        path = _norm_path(str(arguments.get("path", "")))
        if not path.endswith(".csv"):
            return {path: 1 if path in PUBLIC_FILES else max_level}
        stem = path.rsplit("/", 1)[-1].removeprefix("synthetic_").removesuffix(".csv")
        return {stem: tables.get(stem, max_level)}
    rows = result if isinstance(result, list) else [result]
    levels: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            levels[UNLABELLED] = max_level              # a bare string or list: nothing to read a label from
            continue
        for key, value in row.items():
            name = _key_name(tool, str(key), arguments)
            level = max_level if isinstance(value, (dict, list)) else _key_level(
                tool, str(key), arguments, columns, max_level)
            levels[name] = max(levels.get(name, 0), level)
    levels.update(_filter_levels(tool, arguments, columns, max_level))
    return levels


def request_levels(tool: str, arguments: dict, columns: dict[str, int], tables: dict[str, int],
                   table_columns: dict[str, dict], max_level: int) -> dict[str, int]:
    """Everything the call could return, labelled before it runs (question 6).

    Deciding on the result alone turns the decision into an oracle: an empty result is allowed and a matching
    one refused, so the refusal says what the rows hold. Labels use the same names as result_levels.
    """
    if tool == "get":
        return result_levels("get", arguments, [], columns, tables, max_level)
    if tool == "aggregate":
        group_by, measure = arguments.get("group_by", []), str(arguments.get("measure", ""))
        if not isinstance(group_by, list):
            return {"group_by": max_level}
        levels = {str(g): columns.get(str(g), max_level) for g in group_by}
        levels.update({"total": 1, f"count ({measure})": columns.get(measure, max_level)})
        levels.update(_filter_levels(tool, arguments, columns, max_level))
        return levels
    if tool == "write":
        column = str(arguments.get("column", ""))
        level = columns.get(column, max_level)
        return {f"before ({column})": level, f"after ({column})": level}
    parts = TOOL_RETURNS.get(tool)
    if parts is None:
        return {f"{tool} (no declared result)": max_level}
    levels = {}
    for part in parts:
        names = table_columns.get(part, {part: None})
        for name in names:
            levels[name] = _key_level(tool, name, arguments, columns, max_level)
    return levels


def suppress_small_groups(result, base: int) -> tuple[list | object, int]:
    """Drop every aggregate group of fewer than base rows. Returns (rows kept, groups dropped).

    Rounding alone is not enough: a group shown with total 0 still says at least one pupil has that combination.
    """
    if not isinstance(result, list):
        return result, 0
    kept = [row for row in result if not (isinstance(row, dict) and type(row.get("total")) is int
                                          and row["total"] < base)]
    return kept, len(result) - len(kept)


def round_counts(result, base: int):
    """Every aggregate total and count to the nearest multiple of base, halves up."""
    if not isinstance(result, list):
        return result

    def near(value):
        return (value + base // 2) // base * base if type(value) is int else value

    return [
        {k: near(v) if k in ("total", "count") else v for k, v in row.items()} if isinstance(row, dict) else row
        for row in result
    ]


def sensitivity_record(levels: dict[str, int], level_names: dict[int, str], clearance: int | None) -> dict:
    """The decision's account of the result: every label, and the most restrictive ones, which decide."""
    top = max(levels.values(), default=0)
    return {
        "level": top,
        "label": level_names.get(top, "no labelled data"),
        "clearance": clearance,
        "decided_by": sorted(name for name, level in levels.items() if top and level == top),
        "labels": levels,
    }


# Result keys that are not columns, and the one tool each belongs to. In any other tool's result they are looked
# up like any column, so a server cannot launder data through a key called "total".
_SPECIAL_KEYS = {"total": "aggregate", "count": "aggregate", "before": "write", "after": "write", "letter": "draft"}


def _special(tool: str, key: str) -> bool:
    return _SPECIAL_KEYS.get(key) == tool


def _key_name(tool: str, key: str, arguments: dict) -> str:
    if _special(tool, key) and key == "count":
        return f"count ({arguments.get('measure', '')})"
    if _special(tool, key) and key in ("before", "after"):
        return f"{key} ({arguments.get('column', '')})"
    return key


def _key_level(tool: str, key: str, arguments: dict, columns: dict[str, int], max_level: int) -> int:
    if _special(tool, key):
        if key == "total":                             # aggregate group size
            return 1
        if key == "count":                             # aggregate: how many match `measure`
            return columns.get(str(arguments.get("measure", "")), max_level)
        if key in ("before", "after"):                 # write result echoes the corrected column
            return columns.get(str(arguments.get("column", "")), max_level)
        if key == "letter":                            # draft text embeds a display name
            return 2
    return columns.get(key, max_level)


def no_clearance_notice(claims: dict, req: Request) -> str:
    """What the person whose data it is should be told. The agent did prove who it is."""
    principal = (claims.get("delegator") or {}).get("principal", "an unnamed principal")
    return (
        f"An authenticated agent ({claims['agent_id']}) acting for {principal} asked for "
        f"{req.server}.{req.tool}. Its mandate has no clearance and no explicit consent from the person "
        "whose data it is, so the gateway refused the call."
    )


# ---------------------------------------------------------------- the pipeline

class Gateway:
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None,
                 nonces=None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        # main.py passes a SQLite store in the state dir, so a replay fails after a restart and across workers
        self.nonces = nonces if nonces is not None else MemoryNonces()

    def decide(self, req: Request) -> Decision:
        base = dict(policy_version=POLICY_VERSION, mandate_hash=sha256_hex(req.mandate.encode()),
                    request_hash=sha256_hex(req.signing_input()), ts=time.time())
        try:
            claims = verify_mandate(req.mandate, self.registry, self.status_lists)
            jwk = claims["cnf"]["jwk"]
            now = int(time.time())  # int minus int: a huge ts cannot overflow a float
            if type(req.ts) is not int or abs(req.ts - now) > 300:
                raise Reject("POP_FAILED", "request timestamp outside window")
            if not isinstance(req.nonce, str) or not 0 < len(req.nonce) <= MAX_NONCE:
                raise Reject("POP_FAILED", f"nonce must be 1-{MAX_NONCE} characters")
            if not verify_bytes(jwk_to_pub(jwk), req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {jwk_thumbprint(jwk)}")
            # claimed only once the signature holds, so junk requests cannot fill the store
            if not self.nonces.claim(req.nonce, now):
                raise Reject("POP_FAILED", "replayed nonce")

            # Question 6: no clearance claim is an error, not an assumption. The caller
            # fixes the mandate (re-issue with --claims '{"clearance": N}'), not the gateway.
            clearance = claims.get("clearance")
            if clearance is None:
                return Decision("DENY", "CLEARANCE_MISSING", agent_id=claims["agent_id"],
                                detail="re-issue the mandate with a clearance claim (1-4)",
                                notice=no_clearance_notice(claims, req), **base)
            if not isinstance(clearance, int) or not 1 <= clearance <= 4:
                raise Reject("CLEARANCE_INVALID", f"clearance={clearance!r} outside 1-4")
            role = claims.get("role")
            if role is not None and not (isinstance(role, str) and role):
                raise Reject("ROLE_INVALID", f"role={role!r} is not a role name")

            decision, code, detail = check_request(req, claims["scope"], claims["deny"], self.step_up)
            return Decision(decision, code, agent_id=claims["agent_id"], clearance=clearance, role=role,
                            detail=detail, **base)
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, **base)
        except _MALFORMED as e:
            # not a JWT, a claim of the wrong type, a ts too large for a float: refused, never a 500
            return Decision("DENY", "MALFORMED", agent_id=None, detail=type(e).__name__, **base)
