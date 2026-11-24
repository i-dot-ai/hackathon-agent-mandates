"""Whose data a scope entry may touch (OpenSpec add-scope-requests, capability mandate-audience).

A scope entry may carry `audience: {"pupils": ["P0011", ...]}`: a fixed list the issuer resolved when it signed the
mandate. Only that form is accepted. An audience keyed by anything else (care status, ethnicity, a year group)
would itself disclose who has the attribute, so such an entry refuses every call.
"""

from __future__ import annotations

import re

PUPIL_ID = re.compile(r"^P\d{4}$")
MAX_AUDIENCE = 500


def audience_pupils(entry: dict) -> frozenset[str] | None:
    """The entry's audience as a set of pupil IDs; None when the entry has no audience.

    Raises ValueError when the audience is present but not exactly {"pupils": [1..500 pupil IDs]}.
    """
    if "audience" not in entry:
        return None
    audience = entry["audience"]
    if not isinstance(audience, dict) or set(audience) != {"pupils"}:
        raise ValueError("audience must be {'pupils': [...]}")
    pupils = audience["pupils"]
    if not isinstance(pupils, list) or not 1 <= len(pupils) <= MAX_AUDIENCE:
        raise ValueError(f"audience.pupils must list 1 to {MAX_AUDIENCE} pupil IDs")
    if not all(isinstance(p, str) and PUPIL_ID.match(p) for p in pupils):
        raise ValueError("audience.pupils must be pupil IDs like P0011")
    return frozenset(pupils)


def named_pupils(arguments: dict) -> list[str]:
    """Pupil IDs a call names in its arguments (`pupil_id`, `pupil_ids`), in order."""
    named = []
    if "pupil_id" in arguments:
        named.append(str(arguments["pupil_id"]))
    ids = arguments.get("pupil_ids")
    if isinstance(ids, list):
        named.extend(str(p) for p in ids)
    elif ids is not None:
        named.append(str(ids))
    return named


def check_audience(entry: dict, arguments: dict) -> tuple[str, str, str] | None:
    """A DENY (decision, reason_code, detail) when the call falls outside the entry's audience, else None.

    Calls that name no pupil (search, roster) pass here; the tool grant carries the audience so the server
    returns only those pupils' rows.
    """
    try:
        pupils = audience_pupils(entry)
    except ValueError as e:
        return "DENY", "AUDIENCE_INVALID", str(e)
    if pupils is None:
        return None
    for pupil in named_pupils(arguments):
        if pupil not in pupils:
            return "DENY", "AUDIENCE_VIOLATED", pupil
    return None
