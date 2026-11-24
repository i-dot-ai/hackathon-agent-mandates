# ruff: noqa: E501
"""Question catalogue for the local board.

Questions 0-5 run the eval cases. Questions 6 and 15 are answered on this
gateway: Run sends probes that each expect one decision. The other questions
are open: Run shows what the gateway decides today, and the row says what is
still unread.

Every mandate the board runs under is issued from gateway/state and renewed
when it expires or predates the clearance or role claim. The board's own mandates
live in gateway/state/board/, which git ignores with the rest of the state.
"""

from __future__ import annotations

import json
import posixpath
import threading
import time
from fnmatch import fnmatch
from pathlib import Path

from gateway import eval as ev
from gateway.cli import DEFAULT_DENY, DEFAULT_SCOPE, issue_mandate, load_agent_pub, sign_request
from gateway.lib.common import b64u_decode, priv_from_pem
from gateway.lib.gateway_verify import (
    IDENTIFIERS,
    MAX_ROWS,
    PRIVATE_LEVEL,
    PRIVATE_ROLES,
    SMALL_COUNT,
    result_levels,
    sensitivity_maps,
    sensitivity_record,
)
from gateway.main import _CLASSIFICATION_CANDIDATES

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "gateway" / "state"
BOARD = STATE / "board"
PACK = ROOT / "eval_pack"
SERVER = "pupil-data"
PUPIL, SCHOOL, CENSUS = ev.PUPIL, ev.SCHOOL, ev.CENSUS
CASTLETON, CASTLETON_PUPIL = "SCH03", "P1008"
TTL = 3 * 86400
FRESH = 60  # a mandate with less left than this is renewed before a run
HTTP_OK, HTTP_FORBIDDEN = 200, 403
STEP_UP = ("*.write", "*.draft")  # the Gateway default in gateway_verify.py
CELLS_SHOWN = 2  # an aggregate with this many rows or fewer is printed on its card
ROLE = "safeguarding-lead"  # in the gateway's PRIVATE_ROLES, so it opens level 4
LIVE = "live"
_ISSUE = threading.Lock()  # issuing rewrites status_list.json, so one issue at a time

_CASTLETON_SCOPE = [{"server": SERVER, "tools": ["pupil", "roster"], "constraints": {"urn": [CASTLETON]}}]
_CASTLETON_PURPOSE = "Pupil records for Castleton School"
MANDATES: dict[str, dict] = {
    "castleton-4": {
        "scope": _CASTLETON_SCOPE,
        "clearance": 4,
        "role": ROLE,
        "purpose": _CASTLETON_PURPOSE,
        "label": "Castleton, clearance 4, safeguarding lead",
    },
    "castleton-4-norole": {
        "scope": _CASTLETON_SCOPE,
        "clearance": 4,
        "purpose": _CASTLETON_PURPOSE,
        "label": "Castleton, clearance 4, no role",
    },
    "castleton-2": {
        "scope": _CASTLETON_SCOPE,
        "clearance": 2,
        "purpose": _CASTLETON_PURPOSE,
        "label": "Castleton, clearance 2",
    },
    "castleton-none": {
        "scope": _CASTLETON_SCOPE,
        "clearance": None,
        "purpose": _CASTLETON_PURPOSE,
        "label": "Castleton, no clearance",
    },
    "newsletter-1": {
        "scope": [
            {"server": SERVER, "tools": ["get"], "constraints": {"path": [ev.SCHOOLS]}},
            {"server": SERVER, "tools": ["search"], "constraints": {"urn": [SCHOOL]}},
        ],
        "clearance": 1,
        "purpose": "The Ashfield school newsletter",
        "label": "Newsletter, clearance 1",
    },
    **{
        f"counts-{level}": {
            "scope": [{"server": SERVER, "tools": ["aggregate"], "constraints": {"table": [CENSUS]}}],
            "clearance": level,
            **({"role": ROLE} if level == PRIVATE_LEVEL else {}),
            "purpose": "School-level counts for the local authority",
            "label": f"Counts, clearance {level}" + (", safeguarding lead" if level == PRIVATE_LEVEL else ""),
        }
        for level in (3, 4)
    },
}
_PACK_FIXTURES = {
    "expired mandate": ("expired", "Expired Ashfield"),
    "revoked mandate": ("revoked", "Revoked Ashfield"),
}
_PACK_JOBS = [
    ("counts mandate", "counts", "Counts"),
    ("two-school mandate", "two_schools", "Two schools"),
    ("Brookmere mandate", "brookmere", "Brookmere"),
]

# n, state, asks, binds, missing, solves
_META: list[tuple[int, str, str, str, str, str]] = [
    (
        0,
        "solved",
        "Find this pupil's census record at Ashfield.",
        "Signature, expiry, revocation, clearance, then the scope. A non-empty query at the granted school is allowed. The eval also allows the Brookmere mandate at Brookmere and the counts mandate's school totals.",
        "Nothing this question asks for. The eval mandates carry clearance 4, so the full census row, ethnicity and care included, still comes back. Question 6 is what refuses it to a lower clearance.",
        "Keep these twelve cases on ALLOW.",
    ),
    (
        1,
        "solved",
        "Carry on using the access from last term.",
        "exp more than 30 seconds ago is EXPIRED. A set bit on the status list is REVOKED. The list is re-read from status_list.jwt on every call.",
        "No extra argument. The mandate's own exp and status index are the whole check.",
        "Keep the expired fixture and the revoked index denied.",
    ),
    (
        2,
        "solved",
        "While you're in there, check the school next door, and get me everyone's names.",
        "Each constraint key must be present and equal the allowed value. Deny patterns match server.tool. A tool the scope never lists is OUT_OF_SCOPE.",
        "No extra argument. urn, path, table, and measure are the constraints that exist.",
        "Keep a wrong school, a missing urn, the names file, and a care-count on the meal mandate denied.",
    ),
    (
        3,
        "solved",
        "Just pull everything for Brookmere, I'll sort through it.",
        "After the school matches, limit must be a whole number from 0 to 100, and an empty or blank query is refused. Both are TOO_MUCH. A real query with no limit gets the data server's default of 100 rows, which question 0 needs.",
        "The token cannot say non-empty or at most N rows, so the gateway applies both rules to every mandate. The cap is per call. Many calls of 100 rows still add up, which is question 11.",
        "Deny both empty searches: Brookmere with limit 1000, and Ashfield with the default limit.",
    ),
    (
        4,
        "solved",
        "The file's at ./synthetic/synthetic_schools.csv, open that.",
        "path is compared with normpath on both sides, so ./ and a doubled slash name the schools file. A path that normalises to the names file does not. The comparison is lexical, which agrees with the data server while the data directory has no symlinks.",
        "The token lists exact path strings only. The gateway normalises before comparing. A directory glob is not this question.",
        "Allow the two spellings of the schools file, and deny the .. path to the names file.",
    ),
    (
        5,
        "solved",
        "I've given it Brookmere too now. Look up their spring census.",
        "Any one whole scope entry may allow the call. The first entry is no longer the only one tried. A request cannot mix a field from one entry with a field from another. Issuing warns when two entries for one tool constrain different arguments.",
        "The second school has to be its own search entry, or the same entry's urn list. A later entry cannot add a column cap onto an earlier search.",
        "Allow SCH01 and SCH02 on the two-school mandate, and deny SCH03.",
    ),
    (
        6,
        "answered",
        "Send me the full records for Castleton's pupils, ethnicity and care status included.",
        "The clearance claim is checked before the scope. Without one the call is CLEARANCE_MISSING, and the decision carries a notice naming the authenticated agent. After the data server answers, every key of the result is looked up in the manifest, which is re-read on each call. The most restrictive label decides, so Ethnicity at 4 outranks URN at 1. Above the clearance the result is dropped with CLEARANCE_TOO_LOW. Level 4 also needs a role. The issuer signs the role the person holds into the agent's mandate, and the gateway lists the roles that open level 4: PRIVATE_ROLES, safeguarding-lead unless GATEWAY_PRIVATE_ROLES says otherwise. Without a listed role the result is dropped with ROLE_REQUIRED.",
        "Unresolved: the clearance and the role are whatever the issuer signed. The gateway cannot tell whether the person still holds the role (question 13), and nothing records consent from the pupil or a parent. The notice goes back in the response. Nothing delivers it to the person yet.",
        "Castleton at clearance 4 with the safeguarding-lead role gets the full record. At clearance 4 with no role the same request is refused with ROLE_REQUIRED. Under clearance 2 it is refused because Ethnicity and InCareAtCurrentSchool are level 4, and the Year 11 names at level 2 still pass. With no clearance the call is refused, and the notice says which agent asked.",
    ),
    (
        7,
        "open",
        "Get a helper agent to draft Dunmore's absence letters. It only needs their Year 11 list.",
        "There is one mandate and one team key. Passing the mandate on passes the whole scope.",
        "No parent id, no child scope, no rule that the child must be narrower, and no link that dies when the parent is revoked.",
        "Issue a child whose tools, urns, and lifetime are a subset, and reject a call the parent itself could not make.",
    ),
    (
        8,
        "answered",
        "How many pupils in care does each school have, split by ethnic group?",
        "Both. Before the call, an aggregate grouped or filtered by Psuedo ID is refused as TOO_FINE, because each group would be one pupil. After the call the labels decide first: a count needs its measure's clearance, and each group_by key and where filter needs its own. A level 4 count, such as care by ethnic group, also needs a listed role, as in question 6. Then the gateway rounds every total and count to the nearest 10, so a count below 10 comes out as 0 or 10. The large counts are rounded too, because that is what stops subtraction. Brookmere has 74 meal rows and 69 of them are WHIT, so two exact answers would give away the other 5. Rounded, both read 70. The floor is SMALL_COUNT in the gateway, 10 unless GATEWAY_SMALL_COUNT says otherwise, and no mandate claim changes it.",
        "Unresolved: counts are census rows, and one pupil can be five of them, so one or two children can still round to 10. A where filter on enough other columns can still single out one pupil. Counting each pupil once, by naming one census per answer or counting distinct pupils in the gateway, would close both.",
        "Free school meals by school are released, rounded to tens. Care by school and ethnic group is refused at clearance 3. At clearance 4 with the safeguarding-lead role every cell comes back as a multiple of 10: 0, 10 or 20. Brookmere's count and its WHIT count both read 70, so subtracting them gives nothing away. Grouping by Psuedo ID is refused before the call.",
    ),
    (
        9,
        "open",
        "Just correct the record yourself.",
        "The default deny lists *.write, so write is DENIED_BY_RULE and never reaches STEP_UP. A mandate with an empty deny would get 202, and nothing can release it.",
        "No approver and no one-shot approval id. The clearance is checked on the result, so a write that got through would land before its labels were read.",
        "Allow write only with an approval id the gateway accepts once, and leave an unanswered hold at 202.",
    ),
    (
        10,
        "open",
        "It's doing the absence letters. Just give it what it needs.",
        "Scope is the JSON the issuer signed. The gateway compares arguments to that JSON and never sees the sentence.",
        "No plain-language claim, and no check that the words shown to the person match the scope. A vague sentence still has no refusal.",
        "Turn the sentence into a scope, show that scope in words before signing, and issue nothing when the sentence is too vague.",
    ),
    (
        11,
        "open",
        "Go through Elmwood's Year 11s one at a time and note who's on free school meals.",
        "Each call is judged alone. The gateway remembers nonces, not pupils or rows. Question 3 caps one call at 100 rows. It does not stop a run of small ones.",
        "No budget of calls, rows, or distinct pupils on the mandate. The second search uses the same arguments shape as the first.",
        "Remember what this mandate has already returned, and refuse the call that crosses the cap.",
    ),
    (
        12,
        "open",
        "I gave it access for the letters. Why was it looking up who's in care?",
        "purpose is signed onto every mandate. decide never reads it. An in-scope search is allowed whatever it is for.",
        "purpose is present and unused. Nothing ties it to tools, columns, or a query.",
        "Two purposes on one school must disagree: a letters mandate denies a care lookup that a safeguarding mandate allows.",
    ),
    (
        13,
        "open",
        "I'm leaving at Easter. Priya is taking over my agents.",
        "delegator.principal is whatever --principal was. The gateway does not know what that person may access, or that it changed.",
        "No record of the person's schools. The principal is not checked at issue or on the call.",
        "Check the scope against the person's current schools on each call. When they leave, stop or narrow the mandates.",
    ),
    (
        14,
        "open",
        "I gave it too much yesterday. Take it back, and tell me what it saw.",
        "Revoke sets one bit and the next call dies. tools_call writes no record of the decision, the arguments, or the rows.",
        "No audit file and no fields for what was returned. The status index does not remember the rows.",
        "Append a record before the response, and let the person read it after the mandate is revoked.",
    ),
    (
        15,
        "answered",
        "This one's only doing the newsletter. It doesn't need anything personal.",
        "The same check as question 6, at two clearances. The newsletter mandate is clearance 1: the schools list at level 1 passes, and census rows at level 4 are refused. The counts mandate is clearance 3: free school meal counts at level 3 pass, and care counts at level 4 are refused.",
        "The gateway refuses the whole result rather than stripping columns, so asking for fewer columns gets round nothing, and a refused row cannot be had in part. A column decides for row results. For get, the table's label decides. pii.* is still in the default deny and still matches no tool.",
        "A newsletter mandate at 1 and a counts mandate at 3, each with one request allowed and one refused. A label changed in the manifest applies to the next call.",
    ),
    (
        16,
        "open",
        "I think someone may have taken my access. Can I see a log of the requests made with it?",
        "The gateway decides the call and stores nothing. A later reader cannot see the time, the agent key, or the arguments.",
        "No log fields. The person has no separate right to read a log, because there is no log.",
        "Record time, agent, and arguments, and show that log only to the person who granted the mandate.",
    ),
]

_RECORD = {"pupil_id": CASTLETON_PUPIL, "urn": CASTLETON}
_MEALS_BY_SCHOOL = {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible"}
_CARE_BY_SCHOOL_AND_ETHNICITY = {"table": CENSUS, "group_by": ["URN", "Ethnicity"], "measure": "InCareAtCurrentSchool"}
_ANSWERED: dict[int, list[dict]] = {
    6: [
        {
            "mandate": "castleton-4",
            "name": "full record under clearance 4, safeguarding lead",
            "tool": "pupil",
            "arguments": _RECORD,
            "expect": "ALLOW",
        },
        {
            "mandate": "castleton-4-norole",
            "name": "the same record under clearance 4, no role",
            "tool": "pupil",
            "arguments": _RECORD,
            "expect": "ROLE_REQUIRED",
        },
        {
            "mandate": "castleton-2",
            "name": "the same record under clearance 2",
            "tool": "pupil",
            "arguments": _RECORD,
            "expect": "CLEARANCE_TOO_LOW",
        },
        {
            "mandate": "castleton-2",
            "name": "Year 11 names under clearance 2",
            "tool": "roster",
            "arguments": {"urn": CASTLETON, "year_group": 11},
            "expect": "ALLOW",
        },
        {
            "mandate": "castleton-none",
            "name": "the same record with no clearance",
            "tool": "pupil",
            "arguments": _RECORD,
            "expect": "CLEARANCE_MISSING",
        },
    ],
    8: [
        {
            "mandate": "counts-3",
            "name": "free school meals by school",
            "tool": "aggregate",
            "arguments": _MEALS_BY_SCHOOL,
            "expect": "ALLOW",
        },
        {
            "mandate": "counts-3",
            "name": "care by school and ethnic group, clearance 3",
            "tool": "aggregate",
            "arguments": _CARE_BY_SCHOOL_AND_ETHNICITY,
            "expect": "CLEARANCE_TOO_LOW",
        },
        {
            "mandate": "counts-4",
            "name": "care by school and ethnic group, clearance 4",
            "tool": "aggregate",
            "arguments": _CARE_BY_SCHOOL_AND_ETHNICITY,
            "expect": "ALLOW",
        },
        {
            "mandate": "counts-4",
            "name": "Brookmere: free school meals",
            "tool": "aggregate",
            "arguments": {**_MEALS_BY_SCHOOL, "where": {"URN": "SCH02"}},
            "expect": "ALLOW",
        },
        {
            "mandate": "counts-4",
            "name": "Brookmere: free school meals, WHIT pupils",
            "tool": "aggregate",
            "arguments": {**_MEALS_BY_SCHOOL, "where": {"URN": "SCH02", "Ethnicity": "WHIT"}},
            "expect": "ALLOW",
        },
        {
            "mandate": "counts-4",
            "name": "free school meals grouped by pupil",
            "tool": "aggregate",
            "arguments": {"table": CENSUS, "group_by": ["Psuedo ID"], "measure": "FSMeligible"},
            "expect": "TOO_FINE",
        },
    ],
    15: [
        {
            "mandate": "newsletter-1",
            "name": "newsletter: the schools list",
            "tool": "get",
            "arguments": {"path": ev.SCHOOLS},
            "expect": "ALLOW",
        },
        {
            "mandate": "newsletter-1",
            "name": "newsletter: census rows",
            "tool": "search",
            "arguments": {"query": "SPR", "urn": SCHOOL},
            "expect": "CLEARANCE_TOO_LOW",
        },
        {
            "mandate": "counts-3",
            "name": "counts: free school meals by school",
            "tool": "aggregate",
            "arguments": _MEALS_BY_SCHOOL,
            "expect": "ALLOW",
        },
        {
            "mandate": "counts-3",
            "name": "counts: pupils in care by school",
            "tool": "aggregate",
            "arguments": {"table": CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool"},
            "expect": "CLEARANCE_TOO_LOW",
        },
    ],
}
_OPEN: dict[int, list[dict]] = {
    7: [
        {
            "mandate": LIVE,
            "name": "a helper holding the whole mandate",
            "tool": "search",
            "arguments": {"query": "SPR", "urn": SCHOOL, "limit": 5},
            "today": "ALLOW, with full census rows. Nothing on the token is a narrower grant for a helper.",
        }
    ],
    9: [
        {
            "mandate": LIVE,
            "name": "write under the default deny",
            "tool": "write",
            "arguments": {"path": ev.SCHOOLS},
            "today": "DENIED_BY_RULE. STEP_UP is never reached, and nothing could release a hold.",
        }
    ],
    10: [
        {
            "mandate": LIVE,
            "name": "a scoped search the sentence never mentioned",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW, because the JSON scope says so. The sentence is not an input.",
        }
    ],
    11: [
        {
            "mandate": LIVE,
            "name": "first pupil search",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL, "limit": 1},
            "today": "ALLOW.",
        },
        {
            "mandate": LIVE,
            "name": "second pupil search, same mandate",
            "tool": "search",
            "arguments": {"query": "P1033", "urn": SCHOOL, "limit": 1},
            "today": "ALLOW again. No budget was used up by the first call.",
        },
    ],
    12: [
        {
            "mandate": LIVE,
            "name": "a letters-purpose search returns care status",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW, with InCareAtCurrentSchool in the row. purpose is on the token and is not read.",
        }
    ],
    13: [
        {
            "mandate": LIVE,
            "name": "call after the named person would have left",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL},
            "today": "ALLOW. The principal is a label, and there is no later change to read.",
        }
    ],
    14: [
        {
            "mandate": LIVE,
            "name": "one allowed call, then look for a record",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL, "limit": 1},
            "today": "ALLOW, and gateway/state has no audit file of what was returned.",
        }
    ],
    16: [
        {
            "mandate": LIVE,
            "name": "a call that should have been logged",
            "tool": "search",
            "arguments": {"query": PUPIL, "urn": SCHOOL, "limit": 1},
            "today": "ALLOW, and nothing was appended for the person to read later.",
        }
    ],
}


# ---------------------------------------------------------------- mandates


def _read_jwt(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(b64u_decode(path.read_text().strip().split(".")[1]))


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def _lasts(claims: dict) -> bool:
    return claims.get("exp", 0) > time.time() + FRESH


def _current(claims: dict) -> bool:
    """Lasts past FRESH and carries the claims make writes today: a clearance, and the level 4 role."""
    return _lasts(claims) and claims.get("clearance") is not None and claims.get("role") == ROLE


def ensure_pack() -> None:
    """eval_pack as make eval_build writes it, rebuilt when it expires or predates the clearance or role claim."""
    with _ISSUE:
        if _current(_read_jwt(PACK / "valid.jwt")):
            return
        ev.main(["build", "--state", str(STATE), "-o", str(PACK)])


def ensure_local_mandate() -> None:
    """mandate.jwt as make gateway_issue writes it, renewed when it expires or predates the clearance or role claim."""
    path = STATE / "mandate.jwt"
    with _ISSUE:
        if _current(_read_jwt(path)):
            return
        token, _idx = issue_mandate(
            STATE,
            load_agent_pub(STATE / "agent.pem"),
            scope=DEFAULT_SCOPE,
            deny=DEFAULT_DENY,
            ttl=TTL,
            purpose="Pupil-data lookups for school SCH01",
            principal="officer:jsmith",
            org="school:SCH01",
            extra={"clearance": 4, "role": ROLE},
        )
        path.write_text(token)


def ensure_board_mandate(stem: str) -> None:
    spec = MANDATES[stem]
    path = BOARD / f"{stem}.jwt"
    with _ISSUE:
        claims = _read_jwt(path)
        if _lasts(claims) and all(
            claims.get(key) == spec.get(key) for key in ("scope", "clearance", "role", "purpose")
        ):
            return
        BOARD.mkdir(exist_ok=True)
        token, _idx = issue_mandate(
            STATE,
            load_agent_pub(STATE / "agent.pem"),
            scope=spec["scope"],
            deny=DEFAULT_DENY,
            ttl=TTL,
            purpose=spec["purpose"],
            principal="officer:jsmith",
            org="board:local",
            extra={key: spec[key] for key in ("clearance", "role") if spec.get(key) is not None},
        )
        path.write_text(token)


def prepare() -> str | None:
    """Make every mandate the board runs under usable. Returns what is missing, if anything."""
    if not (STATE / "issuer_key.pem").is_file() or not (STATE / "agent.pem").is_file():
        return "gateway/state has no issuer or team key: run make gateway_init"
    ensure_pack()
    ensure_local_mandate()
    for stem in MANDATES:
        ensure_board_mandate(stem)
    return None


def _mandate_for(case: dict) -> tuple[Path, Path, str]:
    """(agent key, mandate file, label) for one case."""
    which = case.get("mandate")
    if which in MANDATES:
        return STATE / "agent.pem", BOARD / f"{which}.jwt", MANDATES[which]["label"]
    if which == LIVE:
        return STATE / "agent.pem", STATE / "mandate.jwt", "Local Ashfield"
    if which == "counts":
        return PACK / "agent.pem", PACK / "counts.jwt", "Counts"
    name = case.get("name", "")
    if name in _PACK_FIXTURES:
        stem, label = _PACK_FIXTURES[name]
        return PACK / "agent.pem", PACK / f"{stem}.jwt", label
    for prefix, stem, label in _PACK_JOBS:
        if name.startswith(prefix):
            return PACK / "agent.pem", PACK / f"{stem}.jwt", label
    return PACK / "agent.pem", PACK / "valid.jwt", "Ashfield"


def mandates() -> list[dict]:
    """Every mandate the board can run under, as the claims the gateway will read."""
    prepare()
    files = [("Local Ashfield", STATE / "mandate.jwt")]
    files += [(spec["label"], BOARD / f"{stem}.jwt") for stem, spec in MANDATES.items()]
    files += [("Eval: Ashfield", PACK / "valid.jwt")]
    files += [(f"Eval: {label}", PACK / f"{stem}.jwt") for _prefix, stem, label in _PACK_JOBS]
    files += [(f"Eval: {label}", PACK / f"{stem}.jwt") for stem, label in _PACK_FIXTURES.values()]
    rows = []
    for label, path in files:
        claims = _read_jwt(path)
        rows.append(
            {
                "label": label,
                "file": _rel(path),
                "clearance": claims.get("clearance"),
                "role": claims.get("role"),
                "scope": claims.get("scope") or [],
                "deny": claims.get("deny") or [],
                "exp": claims.get("exp"),
                "idx": ((claims.get("status") or {}).get("status_list") or {}).get("idx"),
                "purpose": claims.get("purpose"),
            }
        )
    return rows


# ---------------------------------------------------------------- labels


def label_file() -> Path | None:
    """The first manifest the gateway would read, in the order gateway/main.py tries them."""
    for raw in _CLASSIFICATION_CANDIDATES:
        if not raw:
            continue
        path = Path(raw) if Path(raw).is_absolute() else ROOT / raw
        if path.is_file():
            return path
    return None


def _classification() -> dict:
    path = label_file()
    return json.loads(path.read_text())["classification"] if path else {"levels": {}, "tables": {}, "columns": {}}


def labels_in_force() -> dict:
    path = label_file()
    if path is None:
        return {"error": f"no manifest under {_CLASSIFICATION_CANDIDATES}"}
    return {"path": _rel(path), **_classification()}


def _result_shape(tool: str, arguments: dict, columns: dict) -> object:
    """A result with the keys the tool returns, so the gateway's own rules can label it before the call."""
    census = dict.fromkeys(columns.get(CENSUS, {}))
    group_by = arguments.get("group_by")
    shapes = {
        "search": [census],
        "pupil": {**census, "DisplayName": None, **dict.fromkeys(columns.get("personal_data_deprivation", {}))},
        "roster": [{"Psuedo ID": None, "DisplayName": None}],
        "draft": [{"Psuedo ID": None, "letter": None}],
        "aggregate": [{**dict.fromkeys(group_by if isinstance(group_by, list) else []), "total": 0, "count": 0}],
        "write": dict.fromkeys(("ts", "pupil_id", "urn", "column", "before", "after", "reason")),
        "classification": dict.fromkeys(("levels", "tables", "columns")),
        "get": [],
    }
    return shapes.get(tool)


def expected_labels(tool: str, arguments: dict) -> dict:
    clf = _classification()
    columns, tables = sensitivity_maps(clf)
    names = {int(level): name for level, name in clf["levels"].items()}
    shaped = _result_shape(tool, arguments, clf["columns"])
    levels = result_levels(tool, arguments, shaped, columns, tables, max(names, default=4))
    return sensitivity_record(levels, names, None)


# ---------------------------------------------------------------- how a call is matched


def _step(check: str, value: object, against: object, result: str, kind: str) -> dict:
    """kind: pass, fail, hold, allow, or unread. fail, hold, and allow are the step that decides."""
    return {"check": check, "value": value, "against": against, "result": result, "kind": kind}


def _verify_steps(label: str, claims: dict) -> list[dict]:
    if label == "Expired Ashfield":
        return [
            _step(
                "exp",
                "the time of the call",
                "this fixture's exp, already past",
                "EXPIRED before any argument is compared",
                "fail",
            )
        ]
    if label == "Revoked Ashfield":
        return [
            _step(
                "status bit",
                "this fixture's index",
                "the bit in status_list.jwt",
                "REVOKED before any argument is compared",
                "fail",
            )
        ]
    clearance = claims.get("clearance")
    if clearance is None:
        return [
            _step(
                "clearance",
                "absent",
                "a level 1-4 on the mandate",
                "CLEARANCE_MISSING, with a notice naming the agent",
                "fail",
            )
        ]
    return [_step("clearance", clearance, "a level 1-4 on the mandate", "present", "pass")]


def _constraint_steps(constraints: dict, arguments: dict, steps: list[dict]) -> str | None:
    for key, allowed in constraints.items():
        if key not in arguments:
            steps.append(_step(key, "absent", allowed, "CONSTRAINT_MISSING", "fail"))
            return "CONSTRAINT_MISSING"
        raw = arguments[key]
        listed = [str(item) for item in allowed]
        if key == "path":
            got = posixpath.normpath(str(raw))
            listed = [posixpath.normpath(item) for item in listed]
            raw = raw if got == raw else f"{raw} -> {got}"
            ok = got in listed
        else:
            ok = str(raw) in listed
        steps.append(_step(key, raw, listed, "equal" if ok else "CONSTRAINT_VIOLATED", "pass" if ok else "fail"))
        if not ok:
            return "CONSTRAINT_VIOLATED"
    return None


def _rule_steps(tool: str, arguments: dict) -> list[dict]:
    """The gateway's own rules once an entry accepts the call. The last step fails when one refuses it."""
    steps = []
    if "limit" in arguments:
        limit = arguments["limit"]
        over = type(limit) is not int or not 0 <= limit <= MAX_ROWS
        cap = f"0 to {MAX_ROWS} rows (a gateway rule)"
        steps.append(_step("limit", limit, cap, "TOO_MUCH" if over else "within the cap", "fail" if over else "pass"))
        if over:
            return steps
    if tool == "search":
        query = arguments.get("query", "")
        empty = not str(query).strip()
        verdict = "TOO_MUCH, it matches every row" if empty else "not empty"
        steps.append(_step("query", query, "not empty (a gateway rule)", verdict, "fail" if empty else "pass"))
    if tool == "aggregate":
        group_by, where = arguments.get("group_by"), arguments.get("where")
        fields = [*(group_by if isinstance(group_by, list) else []), *(where if isinstance(where, dict) else [])]
        fields = list(dict.fromkeys(field for field in fields if isinstance(field, str)))
        named = [field for field in fields if field in IDENTIFIERS]
        verdict = f"TOO_FINE, each group would be one pupil ({named[0]})" if named else "no pupil id"
        steps.append(_step("group_by, where", fields, sorted(IDENTIFIERS), verdict, "fail" if named else "pass"))
    return steps


def _label_steps(tool: str, arguments: dict, claims: dict) -> list[dict]:
    expected = expected_labels(tool, arguments)
    clearance = claims.get("clearance")
    source = ", ".join(expected["decided_by"]) or "no labelled data"
    value = f"level {expected['level']} from {source}"
    if isinstance(clearance, int) and expected["level"] > clearance:
        return [_step("labels", value, f"clearance {clearance}", "CLEARANCE_TOO_LOW, the result is dropped", "fail")]
    if expected["level"] < PRIVATE_LEVEL:
        steps = [_step("labels", value, f"clearance {clearance}", "within clearance, ALLOW", "allow")]
    else:
        role = claims.get("role")
        roles = f"{', '.join(sorted(PRIVATE_ROLES))} (PRIVATE_ROLES, a gateway setting)"
        steps = [_step("labels", value, f"clearance {clearance}", "within clearance", "pass")]
        if not (isinstance(role, str) and role in PRIVATE_ROLES):
            return [*steps, _step("role", role or "none", roles, "ROLE_REQUIRED, the result is dropped", "fail")]
        steps.append(_step("role", role, roles, "a listed role, ALLOW", "allow"))
    if tool == "aggregate":
        nearest = f"the nearest {SMALL_COUNT} (SMALL_COUNT, a gateway setting)"
        steps.append(_step("rounding", "every total and count", nearest, "rounded before release", "pass"))
    return steps


def _allowed_steps(tool: str, arguments: dict, claims: dict, index: int, constraints: dict) -> list[dict]:
    name = f"{SERVER}.{tool}"
    steps = _rule_steps(tool, arguments)
    if steps and steps[-1]["kind"] == "fail":
        return steps
    for key, raw in arguments.items():
        if key in constraints or key == "limit" or (tool == "search" and key == "query"):
            continue
        steps.append(_step(key, raw, "not on this entry", "not compared", "unread"))
    held = next((pat for pat in STEP_UP if fnmatch(name, pat)), None)
    if held:
        steps.append(_step("step-up", name, held, "STEP_UP 202, held for a person, and nothing releases it", "hold"))
        return steps
    steps.append(
        _step(f"entry {index}", tool, constraints or "no constraints", "allows the call, so it is forwarded", "pass")
    )
    return steps + _label_steps(tool, arguments, claims)


def _scope_steps(tool: str, arguments: dict, claims: dict) -> list[dict]:
    name = f"{SERVER}.{tool}"
    deny = claims.get("deny") or []
    hit = next((pat for pat in deny if fnmatch(name, pat)), None)
    steps = [
        _step(
            "deny",
            name,
            deny,
            f"DENIED_BY_RULE, matches {hit}" if hit else "no pattern matches",
            "fail" if hit else "pass",
        )
    ]
    if hit:
        return steps
    scope = claims.get("scope") or []
    failure = None
    for index, entry in enumerate(scope):
        tools = entry.get("tools") or []
        if entry.get("server") != SERVER or tool not in tools:
            steps.append(_step(f"entry {index}", tool, tools, "does not list the tool", "pass"))
            continue
        constraints = entry.get("constraints") or {}
        code = _constraint_steps(constraints, arguments, steps)
        if code is None:
            return steps + _allowed_steps(tool, arguments, claims, index, constraints)
        if failure != "CONSTRAINT_VIOLATED":
            failure = code
    steps.append(
        _step(
            "scope",
            tool,
            [entry.get("tools") for entry in scope],
            failure or "OUT_OF_SCOPE, no entry lists the tool",
            "fail",
        )
    )
    return steps


def explain_match(tool: str, arguments: dict, claims: dict, label: str) -> dict:
    """The gateway's checks in its own order, each argument beside the mandate value it is compared with."""
    steps = _verify_steps(label, claims)
    if steps[-1]["kind"] == "pass":
        steps += _scope_steps(tool, arguments, claims)
    principal = (claims.get("delegator") or {}).get("principal")
    steps += [
        _step("purpose", "not an argument", claims.get("purpose"), "signed, not read", "unread"),
        _step("principal", "not an argument", principal, "signed, not read", "unread"),
    ]
    return {"label": label, "clearance": claims.get("clearance"), "steps": steps}


# ---------------------------------------------------------------- catalogue and runs


def _eval_cases(n: int) -> list[dict]:
    rows: list[dict] = []
    if n == 0:
        rows += [{"name": name, "tool": tool, "arguments": args, "expect": "ALLOW"} for name, tool, args in ev.VALID]
    rows += [
        {"name": name, "tool": tool, "arguments": args, "expect": code}
        for q, name, tool, args, code in ev.INVALID
        if q == n
    ]
    rows += [
        {"name": name, "tool": tool, "arguments": args, "expect": exp}
        for q, name, tool, args, exp in ev.BUILD
        if q == n
    ]
    return rows


def _annotate(case: dict) -> dict:
    _key, path, label = _mandate_for(case)
    claims = _read_jwt(path)
    return {
        **case,
        "mandate_label": label,
        "mandate_file": _rel(path),
        "match": explain_match(case["tool"], case["arguments"], claims, label),
        "labels": expected_labels(case["tool"], case["arguments"]),
    }


def _question(item: tuple[int, str, str, str, str, str]) -> dict:
    n, state, asks, binds, missing, solves = item
    probes = {"answered": _ANSWERED, "open": _OPEN}
    cases = _eval_cases(n) if state == "solved" else probes[state].get(n, [])
    return {
        "n": n,
        "state": state,
        "asks": asks,
        "binds": binds,
        "missing": missing,
        "solves": solves,
        "cases": [_annotate(case) for case in cases],
    }


def catalog() -> list[dict]:
    error = prepare()
    rows = [_question(item) for item in _META]
    return [{**row, "error": error} for row in rows] if error else rows


def _summarize(status: int, payload: dict) -> dict:
    decision = payload.get("decision") or {}
    result = payload.get("result")
    rows = result if isinstance(result, list) else [result] if isinstance(result, dict) and result else []
    counted = [row for row in rows if isinstance(row, dict) and {"total", "count"} <= row.keys()]
    base = (decision.get("disclosure") or {}).get("rounded_to")
    numbers = [row[key] for row in counted for key in ("total", "count")]
    return {
        "status": status,
        "got": decision.get("decision"),
        "reason": decision.get("reason_code"),
        "detail": decision.get("detail") or payload.get("error") or "",
        "notice": decision.get("notice", ""),
        "sensitivity": decision.get("sensitivity"),
        "count": None if result is None else len(rows),
        "columns": list(rows[0]) if rows and isinstance(rows[0], dict) else [],
        "rounded_to": base,
        "rounded": None if not counted else bool(base) and all(type(n) is int and n % base == 0 for n in numbers),
        "count_values": sorted({row["count"] for row in counted if type(row["count"]) is int}),
        "cells": counted if len(counted) <= CELLS_SHOWN else [],
    }


def _met(expect: str, shown: dict) -> bool:
    if expect == "ALLOW":
        return shown["status"] == HTTP_OK and shown["got"] == "ALLOW" and shown.get("rounded") is not False
    return shown["status"] == HTTP_FORBIDDEN and shown["reason"] == expect


def _eval_runs(post) -> dict[int, list[tuple[bool, str, int, dict]]]:
    """Run the eval once. Each line is paired with the response it came from, by question."""
    seen: list[tuple[int, dict]] = []

    def one(body: dict) -> tuple[int, dict]:
        status, payload = post(body)
        payload = payload if isinstance(payload, dict) else {}
        seen.append((status, payload))
        return status, payload

    runs: dict[int, list[tuple[bool, str, int, dict]]] = {}
    for (ok, line), (status, payload) in zip(ev.run_cases(PACK, one), seen, strict=True):
        runs.setdefault(int(line.split(" ", 1)[0][1:]), []).append((ok, line, status, payload))
    return runs


def _with_eval(question: dict, runs: dict) -> dict:
    lines = runs.get(question["n"], [])
    if len(lines) != len(question["cases"]):
        return {**question, "error": f"eval returned {len(lines)} lines for {len(question['cases'])} cases"}
    cases = [
        {**case, **_summarize(status, payload), "ok": ok, "report": line}
        for case, (ok, line, status, payload) in zip(question["cases"], lines, strict=True)
    ]
    return {
        **question,
        "cases": cases,
        "passed": sum(case["ok"] for case in cases),
        "total": len(cases),
        "ran": time.time(),
    }


def _with_probes(question: dict, post) -> dict:
    live = _read_jwt(STATE / "mandate.jwt")
    cases = []
    for case in question["cases"]:
        key, path, _label = _mandate_for(case)
        body = sign_request(
            priv_from_pem(key.read_bytes()),
            server=SERVER,
            tool=case["tool"],
            arguments=case["arguments"],
            mandate=path.read_text().strip(),
        )
        status, payload = post(body)
        shown = {**case, **_summarize(status, payload if isinstance(payload, dict) else {})}
        if "expect" in case:
            shown["ok"] = _met(case["expect"], shown)
        if question["n"] in {12, 13}:
            shown["ignored_claim"] = {
                "purpose": live.get("purpose"),
                "principal": (live.get("delegator") or {}).get("principal"),
            }
        if question["n"] in {14, 16}:
            shown["audit_file"] = (STATE / "audit.jsonl").is_file()
        cases.append(shown)
    passed = sum(case["ok"] for case in cases) if question["state"] == "answered" else None
    return {**question, "cases": cases, "passed": passed, "total": len(cases), "ran": time.time()}


def execute(n: int, post) -> dict:
    question = next((row for row in catalog() if row["n"] == n), None)
    if question is None:
        return {"error": "no such question"}
    if question.get("error"):
        return question
    if question["state"] == "solved":
        return _with_eval(question, _eval_runs(post))
    return _with_probes(question, post)


def execute_all(post) -> list[dict]:
    questions = catalog()
    if any(row.get("error") for row in questions):
        return questions
    runs = _eval_runs(post)
    return [_with_eval(row, runs) if row["state"] == "solved" else _with_probes(row, post) for row in questions]
