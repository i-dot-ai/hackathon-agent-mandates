"""Deriving a tool grant from a verified mandate (OpenSpec add-scope-requests, capability tool-grants).

Everything in a grant comes from the verified claims and the scope entry that allowed the call, never from the
request arguments, so an argument can't widen what the server will return.
"""

from __future__ import annotations

from tool_grants import DEFAULT_MAX_ROWS, mint

from . import safe_counts
from .audience import audience_pupils
from .graded import claimless_level
from .interfaces import SERVER_LEVELS

# rows a per-pupil count breakdown may have (the census has 7,449 rows); it is folded at the gateway, never released
BREAKDOWN_MAX_ROWS = 20_000


def grant_fields(claims: dict, entry: dict, server: str, tool: str | None = None) -> dict:
    """The subject, level and limit part of a grant, from verified claims and the matched entry only."""
    level = SERVER_LEVELS.get(server, 4)
    clearance = claims.get("clearance")
    if type(clearance) is int:
        level = min(level, clearance)
    elif not safe_counts.applies(server, tool or ""):
        # no clearance claim: the claim-less level (add-graded-pupil-data), so the server strips what the gateway
        # strips. Not for counts: they are never stripped, and the per-pupil breakdown needs its group columns
        level = min(level, claimless_level())
    constraints = entry.get("constraints", {})
    urns = constraints.get("urn")
    pupils = audience_pupils(entry)
    max_rows = entry.get("max_rows", DEFAULT_MAX_ROWS)
    if type(max_rows) is not int or max_rows < 0:
        max_rows = DEFAULT_MAX_ROWS
    return {
        "level": level,
        "urns": [str(u) for u in urns] if urns is not None else None,
        "pupils": sorted(pupils) if pupils is not None else None,
        "constraints": constraints,
        "max_rows": max_rows,
    }


def grant_for(
    priv,
    claims: dict,
    entry: dict,
    *,
    server: str,
    tool: str,
    arguments: dict,
    decision_id: str,
    max_rows: int | None = None,
) -> str:
    """A signed, single-use grant for exactly this call; its jti is the call's audit decision_id.

    `max_rows` overrides the entry's cap only for output the gateway itself consumes (the safe-counts breakdown).
    """
    fields = grant_fields(claims, entry, server, tool)
    if max_rows is not None:
        fields["max_rows"] = max_rows
    return mint(
        priv,
        server=server,
        tool=tool,
        arguments=arguments,
        decision_id=decision_id,
        mandate_jti=claims["jti"],
        agent_id=claims.get("agent_id"),
        principal=(claims.get("delegator") or {}).get("principal"),
        **fields,
    )
