"""Attack our own gateway before another team does: each case is a request that should not get data or a 500.

    uv run python -m day_2_attack.self_attack            # against http://localhost:8082, issuer state gateway/state

It mints short-lived mandates from the local issuer state, fires every case, prints HELD or LANDED, and revokes
what it minted. HELD means: no 500, no flag in the response, and no 200 where a refusal was expected. It only works
against a gateway that trusts this laptop's issuer, so it is for self-testing, not for attacking other teams.
"""
# ruff: noqa: T201, E501, N806  (a script that prints, with one case per line; M and CASES keep their names)

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from gateway.cli import DEFAULT_DENY, DEFAULT_SCOPE, issue_mandate, load_or_create_key, revoke_mandate, sign_request

URL = os.environ.get("GATEWAY_URL", "http://localhost:8082")
STATE = Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state"))
CENSUS = "personal_data_school_census"
NAMES = "synthetic/synthetic_display_names.csv"
SCHOOLS = "synthetic/synthetic_schools.csv"
# day_2_attack/ATTACK_SCORING.md: the flag pupil's name and deprivation score, and the named in-care pupil
FLAGS = ["Zara Okafor", "0.2505", "Mason Owusu", "P0586"]
PD = "pupil-data"

minted: list[int] = []
_agent = None


def agent_key():
    """The shared agent key, loaded (or created) on first use, never at import."""
    global _agent  # noqa: PLW0603
    if _agent is None:
        _agent = load_or_create_key(STATE / "agent.pem")
    return _agent


def mint(scope, *, deny=DEFAULT_DENY, principal="officer:jsmith", key=None, ttl=600, org="school:SCH01",
         purpose="self attack", state=None, **claims) -> str:  # fmt: skip
    """Mint a mandate from the issuer state for `key` (default: the shared agent key); revoked by the caller."""
    pub = (key or agent_key()).public_key()
    token, idx = issue_mandate(state or STATE, pub, scope=scope, deny=deny, ttl=ttl, purpose=purpose,
                               principal=principal, org=org, extra=claims)  # fmt: skip
    minted.append(idx)
    return token


def jti(token: str) -> str:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["jti"]


def post_full(path: str, data: bytes, url: str | None = None) -> tuple[int, str, dict]:
    """(status, body text, response headers); status 0 when nothing answered."""
    req = urllib.request.Request((url or URL) + path, data=data, headers={"content-type": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
            return r.status, r.read().decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)
    except OSError as e:
        return 0, f"no answer: {e}", {}


def post(path: str, data: bytes) -> tuple[int, str]:
    status, text, _ = post_full(path, data)
    return status, text


def signed(mandate: str, server: str, tool: str, arguments: dict, *, key=None, **override) -> bytes:
    body = sign_request(key or agent_key(), server=server, tool=tool, arguments=arguments, mandate=mandate)
    return json.dumps({**body, **override}).encode()


def build_cases() -> tuple[dict, list]:
    """The mandates and cases of the self-attack, minted on call (appended to `minted`)."""
    M = {
        "default": mint(DEFAULT_SCOPE),
        "counts": mint([{"server": PD, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}]),
        "counts4": mint([{"server": PD, "tools": ["aggregate"]}], clearance=4),
        "budget": mint(
            [{"server": PD, "tools": ["search"], "constraints": {"urn": ["SCH01"]}}], budget={"distinct_pupils": 5}
        ),
        "audit": mint(
            [{"server": "audit", "tools": ["events", "saw"], "constraints": {"principal": ["officer:jsmith"]}}],
            clearance=2,
        ),
        "dir2": mint(
            [{"server": "directory", "tools": ["roster", "name"], "constraints": {"urn": ["SCH01"]}}], clearance=2
        ),
        "other": mint(DEFAULT_SCOPE, principal="officer:priya"),
    }
    OTHER_JTI = jti(M["other"])
    d = M["default"]
    tampered = d.split(".")
    tampered[1] = base64.urlsafe_b64encode(
        json.dumps({**json.loads(base64.urlsafe_b64decode(tampered[1] + "==")), "scope": [{"server": PD, "tools": ["search"]}]}).encode()
    ).rstrip(b"=").decode()  # fmt: skip
    replayed = signed(d, PD, "search", {"query": "P0004", "urn": "SCH01"})
    census_where = {"table": CENSUS, "measure": "FSMeligible"}

    # (group, what the attacker tries, request bytes, expect): expect is "refuse" (anything but 200) or "any" (a 200
    # is fine as long as no flag comes back). A 500, or a flag in the body, always counts as LANDED.
    CASES = [
        # ---- default mandate: reach another school or the names file
        (
            "scope",
            "search the flag pupil's school",
            signed(d, PD, "search", {"query": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        ("scope", "search with no urn", signed(d, PD, "search", {"query": "P0011"}), "refuse"),
        (
            "scope",
            "urn as a list holding both schools",
            signed(d, PD, "search", {"query": "P0011", "urn": ["SCH01", "SCH04"]}),
            "refuse",
        ),
        (
            "scope",
            "urn null (the server reads that as every school)",
            signed(d, PD, "search", {"query": "P0011", "urn": None}),
            "refuse",
        ),
        (
            "scope",
            "allowed urn, flag pupil's ID as the query",
            signed(d, PD, "search", {"query": "P0011", "urn": "SCH01"}),
            "any",
        ),
        (
            "scope",
            "a tool the mandate does not list: pupil",
            signed(d, PD, "pupil", {"pupil_id": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        (
            "scope",
            "a tool the mandate does not list: roster",
            signed(d, PD, "roster", {"urn": "SCH04", "year_group": 11}),
            "refuse",
        ),
        (
            "scope",
            "tool name with a trailing space",
            signed(d, PD, "search ", {"query": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        (
            "scope",
            "another server, no clearance: directory.name",
            signed(d, "directory", "name", {"pupil_id": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        (
            "scope",
            "another server, no clearance: special.record",
            signed(d, "special", "record", {"pupil_id": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        (
            "scope",
            "a server the gateway does not know",
            signed(d, "pupil-data/../directory", "name", {"pupil_id": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        ("path", "names file through ..", signed(d, PD, "get", {"path": "synthetic/../" + NAMES}), "refuse"),
        (
            "path",
            "names file behind the allowed file",
            signed(d, PD, "get", {"path": SCHOOLS + "/../synthetic_display_names.csv"}),
            "refuse",
        ),
        (
            "path",
            "names file, percent-encoded ..",
            signed(d, PD, "get", {"path": "synthetic/%2e%2e/" + NAMES}),
            "refuse",
        ),
        ("path", "names file, backslashes", signed(d, PD, "get", {"path": "synthetic\\..\\" + NAMES}), "refuse"),
        ("path", "names file, absolute", signed(d, PD, "get", {"path": "/app/mcp_server/data/" + NAMES}), "refuse"),
        (
            "path",
            "names file hidden after a null byte",
            signed(d, PD, "get", {"path": SCHOOLS + "\x00/../" + NAMES}),
            "refuse",
        ),
        ("path", "path as a list", signed(d, PD, "get", {"path": [SCHOOLS, NAMES]}), "refuse"),
        ("bulk", "limit 1000", signed(d, PD, "search", {"query": "SPR", "urn": "SCH01", "limit": 1000}), "refuse"),
        (
            "bulk",
            "limit as a string",
            signed(d, PD, "search", {"query": "SPR", "urn": "SCH01", "limit": "1000"}),
            "refuse",
        ),
        (
            "bulk",
            "limit as a float",
            signed(d, PD, "search", {"query": "SPR", "urn": "SCH01", "limit": 1000.0}),
            "refuse",
        ),
        ("bulk", "whitespace query", signed(d, PD, "search", {"query": " \t", "urn": "SCH01"}), "refuse"),
        # ---- gateway breaks
        ("break", "mandate is not a JWT", signed("x", PD, "search", {"query": "P0004", "urn": "SCH01"}), "refuse"),
        (
            "break",
            "mandate with edited scope, old signature",
            signed(".".join(tampered), PD, "search", {"query": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        (
            "break",
            "mandate with alg none",
            signed(
                base64.urlsafe_b64encode(b'{"alg":"none","typ":"mandate+jwt"}').rstrip(b"=").decode()
                + "."
                + d.split(".")[1]
                + ".",
                PD,
                "search",
                {"query": "P0004", "urn": "SCH01"},
            ),
            "refuse",
        ),
        ("break", "first use of a signed request (sets up the replay)", replayed, "any"),
        ("break", "the same signed request again", replayed, "refuse"),
        ("break", "stale timestamp", signed(d, PD, "search", {"query": "P0004", "urn": "SCH01"}, ts=1), "refuse"),
        (
            "break",
            "signature from nobody",
            signed(d, PD, "search", {"query": "P0004", "urn": "SCH01"}, sig="AAAA"),
            "refuse",
        ),
        (
            "break",
            "arguments changed after signing",
            signed(d, PD, "search", {"query": "P0004", "urn": "SCH01"})
            .replace(b"P0004", b"P0011")
            .replace(b"SCH01", b"SCH04"),
            "refuse",
        ),
        (
            "crash",
            "lone surrogate in an argument",
            signed(d, PD, "get", {"path": "x"}).replace(b'"x"', b'"\\ud800"'),
            "refuse",
        ),
        (
            "crash",
            "lone surrogate in the nonce",
            signed(d, PD, "get", {"path": SCHOOLS}, nonce="n").replace(b'"n"', b'"\\ud800"'),
            "refuse",
        ),
        (
            "crash",
            "NaN in an argument",
            signed(d, PD, "search", {"query": "SPR", "urn": "SCH01"}).replace(b'"SPR"', b"NaN"),
            "refuse",
        ),
        (
            "crash",
            "timestamp too big for a float",
            signed(d, PD, "search", {"query": "SPR", "urn": "SCH01"}, ts=10**400),
            "refuse",
        ),
        (
            "crash",
            "arguments nested 5000 deep",
            b'{"server":"pupil-data","tool":"search","mandate":"x","nonce":"n","ts":1,"sig":"s","arguments":{"a":'
            + b"[" * 5000
            + b"]" * 5000
            + b"}}",
            "refuse",
        ),
        ("crash", "query is an object", signed(d, PD, "search", {"query": {"a": 1}, "urn": "SCH01"}), "refuse"),
        ("crash", "audit event endpoint, junk token", ("/internal/audit-events", b'{"token": "x"}'), "refuse"),
        # ---- the demo router mints and signs for anyone who can reach it
        (
            "demo",
            "mint a mandate for the flag pupil's school",
            ("/demo/mandate", b'{"urn": "SCH04", "tools": ["search", "pupil"]}'),
            "refuse",
        ),
        (
            "demo",
            "call through the demo's own key",
            ("/demo/call", b'{"tool": "pupil", "arguments": {"pupil_id": "P0011", "urn": "SCH04"}}'),
            "refuse",
        ),
        ("demo", "revoke somebody's mandate (an unused index)", ("/demo/revoke", b'{"idx": 9999}'), "refuse"),
        # ---- safe counts: pin a fact to one pupil
        (
            "counts",
            "group by pupil",
            signed(M["counts"], PD, "aggregate", {**census_where, "group_by": ["Psuedo ID"]}),
            "refuse",
        ),
        (
            "counts",
            "filter to one pupil",
            signed(
                M["counts"], PD, "aggregate", {**census_where, "group_by": ["URN"], "where": {"Psuedo ID": "P0011"}}
            ),
            "refuse",
        ),
        (
            "counts",
            "in-care count without clearance 4",
            signed(
                M["counts"], PD, "aggregate", {"table": CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool"}
            ),
            "refuse",
        ),
        (
            "counts",
            "group by ethnicity without clearance 4",
            signed(M["counts"], PD, "aggregate", {**census_where, "group_by": ["URN", "Ethnicity"]}),
            "refuse",
        ),
        (
            "counts",
            "three group_by columns",
            signed(
                M["counts"],
                PD,
                "aggregate",
                {**census_where, "group_by": ["URN", "Gender", "AgeAtStartOfAcademicYear"]},
            ),
            "refuse",
        ),
        (
            "counts",
            "group_by as a string",
            signed(M["counts"], PD, "aggregate", {**census_where, "group_by": "Psuedo ID"}),
            "refuse",
        ),
        (
            "counts",
            "another table than the mandate's",
            signed(
                M["counts"], PD, "aggregate", {"table": "display_names", "group_by": ["Gender"], "measure": "Gender"}
            ),
            "refuse",
        ),
        (
            "counts",
            "clearance 4: name as a group",
            signed(
                M["counts4"],
                PD,
                "aggregate",
                {"table": "display_names", "group_by": ["DisplayName"], "measure": "Gender"},
            ),
            "refuse",
        ),
        (
            "counts",
            "clearance 4: deprivation score as a group (flag 0.2505)",
            signed(
                M["counts4"],
                PD,
                "aggregate",
                {
                    "table": "personal_data_deprivation",
                    "group_by": ["DeprivationScore"],
                    "measure": "DeprivationDecile",
                },
            ),
            "any",
        ),
        (
            "counts",
            "clearance 4: the one in-care pupil at SCH07",
            signed(
                M["counts4"],
                PD,
                "aggregate",
                {"table": CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool", "where": {"URN": "SCH07"}},
            ),
            "count-hidden",
        ),
        (
            "counts",
            "clearance 4: in care by gender at SCH07",
            signed(
                M["counts4"],
                PD,
                "aggregate",
                {
                    "table": CENSUS,
                    "group_by": ["URN", "Gender"],
                    "measure": "InCareAtCurrentSchool",
                    "where": {"URN": "SCH07"},
                },
            ),
            "count-hidden",
        ),
        # ---- the audit server: read somebody else's log
        (
            "audit",
            "own log (baseline)",
            signed(M["audit"], "audit", "events", {"principal": "officer:jsmith", "limit": 1}),
            "any",
        ),
        (
            "audit",
            "another person's log",
            signed(M["audit"], "audit", "events", {"principal": "officer:priya"}),
            "refuse",
        ),
        ("audit", "by jti alone, no principal", signed(M["audit"], "audit", "events", {"jti": OTHER_JTI}), "refuse"),
        (
            "audit",
            "own principal, another person's jti",
            signed(M["audit"], "audit", "saw", {"principal": "officer:jsmith", "jti": OTHER_JTI}),
            "empty-saw",
        ),
        (
            "audit",
            "principal as a list",
            signed(M["audit"], "audit", "events", {"principal": ["officer:jsmith", "officer:priya"]}),
            "refuse",
        ),
        (
            "audit",
            "since is a number",
            signed(M["audit"], "audit", "events", {"principal": "officer:jsmith", "since": 5}),
            "any",
        ),
        (
            "audit",
            "since is an object",
            signed(M["audit"], "audit", "events", {"principal": "officer:jsmith", "since": {"a": 1}}),
            "any",
        ),
        (
            "audit",
            "a tool that does not exist",
            signed(M["audit"], "audit", "events ", {"principal": "officer:jsmith"}),
            "refuse",
        ),
        (
            "audit",
            "audit log with the default mandate",
            signed(d, "audit", "events", {"principal": "officer:jsmith"}),
            "refuse",
        ),
        # ---- clearance 2 directory mandate, one school
        (
            "clearance",
            "name at another school",
            signed(M["dir2"], "directory", "name", {"pupil_id": "P0011", "urn": "SCH04"}),
            "refuse",
        ),
        (
            "clearance",
            "pupil-data with clearance 2",
            signed(M["dir2"], PD, "search", {"query": "P0011", "urn": "SCH01"}),
            "refuse",
        ),
        (
            "clearance",
            "special.record with clearance 2",
            signed(M["dir2"], "special", "record", {"pupil_id": "P0011", "urn": "SCH01"}),
            "refuse",
        ),
        (
            "clearance",
            "flag pupil's name asked for at the allowed school",
            signed(M["dir2"], "directory", "name", {"pupil_id": "P0011", "urn": "SCH01"}),
            "any",
        ),
    ]
    return M, CASES


def verdict(status: int, text: str, expect: str) -> str:
    if status in (0, 500) or any(flag in text for flag in FLAGS):
        return "LANDED"
    if expect == "refuse" and status == 200:  # noqa: PLR2004
        return "LANDED"
    if expect == "count-hidden" and status == 200 and any(r.get("count") for r in json.loads(text)["result"]):  # noqa: PLR2004
        return "LANDED"
    if expect == "empty-saw" and status == 200 and json.loads(text)["result"]["calls"]["allowed"]:  # noqa: PLR2004
        return "LANDED"
    return "HELD"


def run() -> int:
    M, CASES = build_cases()
    landed = 0
    for group, name, request, expect in CASES:
        path, data = request if isinstance(request, tuple) else ("/tools/call", request)
        status, text = post(path, data)
        result = verdict(status, text, expect)
        if path == "/demo/mandate" and status == 200:  # noqa: PLR2004
            minted.append(json.loads(text)["status_idx"])  # the gateway minted it for us: revoke it with ours
        landed += result == "LANDED"
        try:
            reason = json.loads(text).get("decision", {}).get("reason_code") or text[:70]
        except ValueError:
            reason = text[:70]
        print(f"{result:6} {group:9} {status} {str(reason)[:40]:40} {name}")
    # the budget mandate allows 5 distinct pupils: 3 are fine, the call that would make it more must return nothing
    budget = []
    for limit in (3, 10):
        status, text = post(
            "/tools/call", signed(M["budget"], PD, "search", {"query": "SPR", "urn": "SCH01", "limit": limit})
        )
        budget.append((status, json.loads(text)["decision"]["reason_code"], len(json.loads(text).get("result") or [])))
    held = budget[0][0] == 200 and budget[1][0] != 200 and budget[1][2] == 0  # noqa: PLR2004
    landed += not held
    print(f"{'HELD' if held else 'LANDED':6} budget    5-pupil budget, a 3-row call then a 10-row call: {budget}")
    print(f"\n{landed} landed out of {len(CASES) + 1}")
    return landed


if __name__ == "__main__":
    try:
        code = run()
    finally:
        for idx in minted:
            revoke_mandate(STATE, idx)
        print(f"revoked the {len(minted)} mandates this run minted")
    sys.exit(1 if code else 0)
