"""Plain words for grants, generated from the structured scope (OpenSpec add-scope-requests).

Whatever a person reads before approving comes from here, never from the agent's own text, so the description
matches what will be enforced. Used by the gateway (grants.self) and the issuer (request summary, approval view).
"""

from __future__ import annotations

import csv
import os
import time
from functools import lru_cache
from pathlib import Path

SCHOOLS_PATH = Path(
    os.environ.get(
        "GATEWAY_SCHOOLS_PATH",
        Path(__file__).resolve().parents[2] / "mcp_server/data/synthetic/synthetic_schools.csv",
    )
)

TOOL_WORDS = {
    ("pupil-data", "search"): "Search pupils' census records",
    ("pupil-data", "get"): "Read data files",
    ("pupil-data", "aggregate"): "Count pupils by group",
    ("pupil-data", "classification"): "Read the data sensitivity labels",
    ("pupil-data", "roster"): "List Year 10 and 11 pupils' IDs and names",
    ("pupil-data", "pupil"): "Read pupils' records",
    ("pupil-data", "draft"): "Draft letters home",
    ("pupil-data", "write"): "Correct pupils' census records",
    ("schools", "list"): "List schools",
    ("schools", "classification"): "Read the data sensitivity labels",
    ("directory", "roster"): "List Year 10 and 11 pupils' IDs and names",
    ("directory", "name"): "Look up pupils' names",
    ("special", "record"): "Read pupils' ethnicity and care status",
    ("audit", "events"): "Read the request log",
    ("audit", "saw"): "See what an agent received",
}
LEVEL_4_SERVERS = {"special"}  # always level 4; pupil-data only at clearance 4 (graded)
# graded pupil-data (add-graded-pupil-data): what a read returns at each clearance, so the words never say more or less
GRADED_SERVER = "pupil-data"
GRADED_TOOLS = {"search", "pupil"}
GRADED_WORDS = {
    1: "with school and term only, no pupil details",
    2: "with basic details only, not free school meals, language, ethnicity or care status",
    3: "including free school meals and language, but not ethnicity or care status",
    4: "including ethnicity and care status, each such read held for a person's approval",
}
# tools whose data belongs to a school: without a urn constraint they reach all twelve
PER_SCHOOL_TOOLS = {"search", "aggregate", "roster", "pupil", "draft", "write", "name", "record"}


@lru_cache
def school_names() -> dict[str, str]:
    try:
        with SCHOOLS_PATH.open(newline="") as f:
            return {r["URN"]: r["SchoolName"] for r in csv.DictReader(f)}
    except OSError:
        return {}


def school(urn: str) -> str:
    name = school_names().get(urn)
    return f"{name} ({urn})" if name else urn


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _graded_level(clearance: int | None) -> int:
    from .graded import claimless_level  # noqa: PLC0415  (graded imports audit; keep this module light)

    return clearance if type(clearance) is int and 1 <= clearance <= 4 else claimless_level()  # noqa: PLR2004


def entry_words(entry: dict, clearance: int | None = None) -> str:
    """One scope entry as a sentence fragment: what, where, for whom. `clearance` is the grant's effective one."""
    server = entry.get("server", "?")
    tools = entry.get("tools", [])
    what = _join([TOOL_WORDS.get((server, t), f"Use {server}.{t}") for t in tools]) or f"Use {server}"
    parts = [what]
    if server == GRADED_SERVER and set(tools) & GRADED_TOOLS:
        parts.append(GRADED_WORDS[_graded_level(clearance)])
    constraints = entry.get("constraints", {})
    if urns := constraints.get("urn"):
        parts.append("at " + _join([school(str(u)) for u in urns]))
    elif set(tools) & PER_SCHOOL_TOOLS:
        # saying nothing would read as narrower than what is enforced
        parts.append("at every school")
    others = {k: v for k, v in constraints.items() if k != "urn"}
    for k, values in others.items():
        parts.append(f"where {k} is " + _join([str(v) for v in values]))
    pupils = (entry.get("audience") or {}).get("pupils")
    if isinstance(pupils, list):
        parts.append(f"for {len(pupils)} named pupil" + ("" if len(pupils) == 1 else "s"))
    if type(max_rows := entry.get("max_rows")) is int:
        parts.append(f"(at most {max_rows} rows a call)")
    if isinstance(rate := entry.get("rate"), dict):
        limits = []
        if "per_minute" in rate:
            limits.append(f"at most {rate['per_minute']} calls a minute")
        if "max_calls" in rate:
            limits.append(f"{rate['max_calls']} calls in all")
        if limits:
            parts.append("(" + ", ".join(limits) + ")")
    return " ".join(parts)


def until(exp: int | float | None) -> str:
    if not exp:
        return ""
    return "until " + time.strftime("%H:%M on %d %b", time.localtime(exp))


def lifetime(seconds: int) -> str:
    if seconds % 3600 == 0:
        h = seconds // 3600
        return f"for {h} hour" + ("" if h == 1 else "s")
    m = max(1, round(seconds / 60))
    return f"for {m} minute" + ("" if m == 1 else "s")


def grants_words(scope: list[dict], *, clearance: int | None = None, exp=None, ttl: int | None = None) -> str:
    sentences = [entry_words(e, clearance) for e in scope]
    text = ". ".join(sentences)
    if ttl:
        text += f", {lifetime(ttl)}"
    elif exp:
        text += f", {until(exp)}"
    if clearance is not None:
        text += f". Highest data level: {clearance}"
    return text + "."


def marks_level_4(scope: list[dict], clearance: int | None) -> bool:
    """Whether a grant reaches special category data (level 4): the special server, or clearance 4."""
    return any(e.get("server") in LEVEL_4_SERVERS for e in scope) or clearance == 4  # noqa: PLR2004


def action_words(server: str, tool: str, arguments: dict) -> str:
    """A held call in plain words, with every argument value shown as plain text."""
    if (server, tool) == ("pupil-data", "write"):
        return (
            f"Change {arguments.get('column')} to {arguments.get('value')} for pupil {arguments.get('pupil_id')} "
            f"at {school(str(arguments.get('urn')))}"
        )
    if tool == "draft":
        ids = arguments.get("pupil_ids") or []
        return f"Draft {arguments.get('kind', 'absence')} letters for {_join([str(p) for p in ids])} at " + school(
            str(arguments.get("urn"))
        )
    if tool == "record":
        return f"Read the ethnicity and care status of pupil {arguments.get('pupil_id')} at " + school(
            str(arguments.get("urn"))
        )
    args = ", ".join(f"{k}={v}" for k, v in sorted(arguments.items()))
    return f"{TOOL_WORDS.get((server, tool), f'{server}.{tool}')} ({args})"
