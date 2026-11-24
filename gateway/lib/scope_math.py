"""Comparing grants (OpenSpec add-scope-requests): is a requested grant well formed, already held, within a
person's ceiling, within a supervisor's mandate, or a subset of what was asked?

One implementation, used by the gateway and again by the issuer, so neither has to trust the other's answer.
"""

from __future__ import annotations

from .audience import audience_pupils
from .grant_words import TOOL_WORDS
from .interfaces import SERVER_LEVELS

# servers a scope request may ask for: the data servers, not the gateway's own
REQUESTABLE = {s for s in SERVER_LEVELS if s not in ("grants", "audit")}
KNOWN_TOOLS: dict[str, set[str]] = {}
for _server, _tool in TOOL_WORDS:
    KNOWN_TOOLS.setdefault(_server, set()).add(_tool)
MAX_ENTRIES = 10
MIN_TTL, MAX_TTL = 60, 86400
MAX_REASON = 500


class Invalid(ValueError):
    """A request that isn't a valid scope: reason REQUEST_INVALID."""


def validate_request(scope, clearance, ttl, reason) -> None:
    if not isinstance(scope, list) or not 1 <= len(scope) <= MAX_ENTRIES:
        raise Invalid(f"scope must list 1 to {MAX_ENTRIES} entries")
    for entry in scope:
        validate_entry(entry)
    if clearance is not None and (type(clearance) is not int or not 1 <= clearance <= 4):
        raise Invalid("clearance must be an integer from 1 to 4")
    if type(ttl) is not int or not MIN_TTL <= ttl <= MAX_TTL:
        raise Invalid(f"ttl must be {MIN_TTL} to {MAX_TTL} seconds")
    if not isinstance(reason, str) or not reason.strip():
        raise Invalid("a reason is required")
    if len(reason) > MAX_REASON:
        raise Invalid(f"reason is longer than {MAX_REASON} characters")


def validate_entry(entry) -> None:
    if not isinstance(entry, dict):
        raise Invalid("each scope entry must be an object")
    server = entry.get("server")
    if server not in REQUESTABLE:
        raise Invalid(f"unknown server {server!r}")
    tools = entry.get("tools")
    if not isinstance(tools, list) or not tools or not set(tools) <= KNOWN_TOOLS.get(server, set()):
        raise Invalid(f"tools must be a non-empty list of {server} tools")
    constraints = entry.get("constraints", {})
    if not isinstance(constraints, dict) or not all(isinstance(v, list) and v for v in constraints.values()):
        raise Invalid("constraints must map argument names to non-empty lists")
    try:
        audience_pupils(entry)
    except ValueError as e:
        raise Invalid(str(e)) from e
    extra = set(entry) - {"server", "tools", "constraints", "audience", "max_rows", "rate"}
    if extra:
        raise Invalid(f"unknown keys in a scope entry: {sorted(extra)}")


def entry_covers(held: dict, wanted: dict) -> bool:
    """Whether scope entry `held` allows everything entry `wanted` would allow."""
    if held.get("server") != wanted.get("server"):
        return False
    if not set(wanted.get("tools", [])) <= set(held.get("tools", [])):
        return False
    held_c, wanted_c = held.get("constraints", {}), wanted.get("constraints", {})
    for k, allowed in held_c.items():
        # held limits k; wanted must limit it at least as much
        if k not in wanted_c or not set(map(str, wanted_c[k])) <= set(map(str, allowed)):
            return False
    held_aud, wanted_aud = audience_pupils(held), audience_pupils(wanted)
    if held_aud is not None and (wanted_aud is None or not wanted_aud <= held_aud):
        return False
    held_rows = held.get("max_rows", 100)
    return wanted.get("max_rows", 100) <= held_rows


def scope_covers(held_scope: list[dict], wanted_scope: list[dict]) -> bool:
    return all(any(entry_covers(h, w) for h in held_scope) for w in wanted_scope)


def clearance_covers(held: int | None, wanted: int | None, wanted_scope: list[dict]) -> bool:
    """Whether clearance `held` suffices for `wanted` and for every server the wanted scope names."""
    needed = max([SERVER_LEVELS.get(e["server"], 4) for e in wanted_scope] + [wanted or 0])
    if held is None:
        # a mandate with no clearance reaches only pupil-data (the legacy rule)
        return all(e["server"] == "pupil-data" for e in wanted_scope) and wanted is None
    return held >= needed


def already_granted(claims: dict, scope: list[dict], clearance: int | None) -> bool:
    return scope_covers(claims.get("scope", []), scope) and clearance_covers(claims.get("clearance"), clearance, scope)


def within_ceiling(ceiling: dict | None, scope: list[dict], clearance: int | None) -> str | None:
    """None when the whole request fits the person's ceiling, else a description of the first part that doesn't.

    ceiling: {"servers": {server: [tools]}, "urns": [...] or "*", "max_clearance": n}
    """
    if not ceiling:
        return "this person has no grantable access"
    servers = ceiling.get("servers", {})
    urns = ceiling.get("urns", [])
    for entry in scope:
        server = entry["server"]
        if server not in servers or not set(entry["tools"]) <= set(servers[server]):
            return f"{server}.{','.join(entry['tools'])}"
        if urns != "*":
            asked = entry.get("constraints", {}).get("urn")
            if asked is None or not set(map(str, asked)) <= set(urns):
                return f"{server} at {asked or 'every school'}"
        if SERVER_LEVELS.get(server, 4) > ceiling.get("max_clearance", 0):
            return f"{server} needs clearance {SERVER_LEVELS.get(server, 4)}"
    if clearance is not None and clearance > ceiling.get("max_clearance", 0):
        return f"clearance {clearance}"
    return None


def narrower_or_equal(requested: dict, approved: dict) -> bool:
    """Whether an approved grant {scope, clearance, ttl} is a subset of the requested one."""
    if not scope_covers(requested["scope"], approved["scope"]):
        return False
    if approved.get("ttl", 0) > requested.get("ttl", 0):
        return False
    req_c, app_c = requested.get("clearance"), approved.get("clearance")
    return not (app_c is not None and (req_c is None or app_c > req_c))
