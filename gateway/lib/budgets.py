"""Run budgets, rates, ceilings and alerts (OpenSpec add-run-budgets, question 11).

Limits come from two places, never from request arguments:
    signed mandate claims   `budget: {distinct_pupils, calls}` and per scope entry `rate: {per_minute, max_calls}`
    gateway configuration   gateway/config/limits.yaml, overridable by GATEWAY_LIMIT_<SECTION>_<KEY>

Counting uses the audit store for anything that must survive a restart (pupils received, lifetime calls) and
in-memory sliding windows for per-minute rates. A mandate's family is its parent (`parent.jti`) or itself, so a
supplementary mandate draws on its parent's budget.
"""

from __future__ import annotations

import asyncio
import os
import posixpath
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, fields
from pathlib import Path

import yaml

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "limits.yaml"
CONFIG_ENV = "GATEWAY_LIMITS_CONFIG"
ENV_PREFIX = "GATEWAY_LIMIT_"
WINDOW_S = 60.0
ALERT_NAMESPACE = uuid.UUID("6f1c2d3e-4b5a-4c6d-8e7f-a0b1c2d3e4f5")


class LimitsConfigError(ValueError):
    """The limits file or an override is invalid: the gateway must not start with guessed limits."""


@dataclass(frozen=True)
class Limits:
    per_key_per_minute: int = 300
    unverified_per_source_per_minute: int = 120
    record_per_second: int = 1
    retry_after_seconds: int = 60
    default_distinct_pupils: int | None = None
    default_calls: int | None = None
    refusals_in_a_row: int = 5
    many_pupils: int = 200
    pupil_targeted_mandates: int = 3
    pupil_targeted_window_minutes: int = 60

    def public(self) -> dict:
        """What /describe shows: every limit, nothing secret in it."""
        return {f.name: getattr(self, f.name) for f in fields(self)}


SECTIONS = {
    "ceilings": ("per_key_per_minute", "unverified_per_source_per_minute", "record_per_second", "retry_after_seconds"),
    "budgets": ("default_distinct_pupils", "default_calls"),
    "alerts": ("refusals_in_a_row", "many_pupils", "pupil_targeted_mandates", "pupil_targeted_window_minutes"),
}
NULLABLE = {"default_distinct_pupils", "default_calls"}


def _check_value(name: str, value):
    if value is None and name in NULLABLE:
        return None
    if type(value) is not int or value < 0:
        allowed = "a non-negative integer or null" if name in NULLABLE else "a non-negative integer"
        msg = f"limits: {name} must be {allowed}, got {value!r}"
        raise LimitsConfigError(msg)
    return value


def load_limits(path: str | Path | None = None, env: dict | None = None) -> Limits:
    """Defaults, then the YAML file, then GATEWAY_LIMIT_* overrides. Raises LimitsConfigError on anything unknown."""
    env = os.environ if env is None else env
    path = Path(path or env.get(CONFIG_ENV) or DEFAULT_CONFIG)
    values: dict = {}
    if path.exists():
        doc = yaml.safe_load(path.read_text()) or {}
        if not isinstance(doc, dict):
            msg = f"limits: {path} must be a mapping of sections"
            raise LimitsConfigError(msg)
        for section, body in doc.items():
            if section not in SECTIONS or not isinstance(body, dict):
                msg = f"limits: unknown section {section!r} in {path}"
                raise LimitsConfigError(msg)
            for key, value in body.items():
                if key not in SECTIONS[section]:
                    msg = f"limits: unknown key {section}.{key} in {path}"
                    raise LimitsConfigError(msg)
                values[key] = _check_value(key, value)
    elif env.get(CONFIG_ENV):
        msg = f"limits: {CONFIG_ENV} points at {path}, which doesn't exist"
        raise LimitsConfigError(msg)
    for section, keys in SECTIONS.items():
        for key in keys:
            raw = env.get(f"{ENV_PREFIX}{section}_{key}".upper())
            if raw is None:
                continue
            parsed = None if raw.strip().lower() in ("", "null", "none") else _int_or_raise(key, raw)
            values[key] = _check_value(key, parsed)
    return Limits(**values)


def _int_or_raise(key: str, raw: str) -> int:
    try:
        return int(raw)
    except ValueError as e:
        msg = f"limits: {key} override must be an integer, got {raw!r}"
        raise LimitsConfigError(msg) from e


# ---------------------------------------------------------------- claims


class BudgetInvalid(Exception):
    pass


def _positive(value) -> bool:
    return type(value) is int and value > 0


def _parse(obj, keys: tuple[str, ...], where: str) -> dict:
    if not isinstance(obj, dict) or not obj or set(obj) - set(keys) or not all(_positive(v) for v in obj.values()):
        msg = f"{where} must be an object with positive integers for {', '.join(keys)}"
        raise BudgetInvalid(msg)
    return dict(obj)


@dataclass(frozen=True)
class Claimed:
    """The verified mandate's own limits. `has_claims` is False for mandates with neither budget nor rate."""

    budget: dict
    rates: dict[int, dict]

    @property
    def has_claims(self) -> bool:
        return bool(self.budget) or bool(self.rates)


def parse_claims(claims: dict) -> Claimed:
    """`budget` and per-entry `rate` from verified claims. Raises BudgetInvalid for anything malformed."""
    budget = _parse(claims["budget"], ("distinct_pupils", "calls"), "budget") if "budget" in claims else {}
    rates = {
        i: _parse(entry["rate"], ("per_minute", "max_calls"), f"scope[{i}].rate")
        for i, entry in enumerate(claims.get("scope", []))
        if isinstance(entry, dict) and "rate" in entry
    }
    return Claimed(budget, rates)


def family_of(claims: dict) -> str:
    parent = claims.get("parent")
    if isinstance(parent, dict) and isinstance(parent.get("jti"), str):
        return parent["jti"]
    return claims["jti"]


def matched_entry(server: str, tool: str, arguments: dict, scope: list[dict]) -> int | None:
    """Index of the first scope entry that accepts the call, with the same rules as check_request."""
    for i, entry in enumerate(scope):
        if entry.get("server") != server or tool not in entry.get("tools", []):
            continue
        ok = True
        for k, allowed in entry.get("constraints", {}).items():
            if k not in arguments:
                ok = False
                break
            value = arguments[k]
            if k == "path" and isinstance(value, str):
                value = posixpath.normpath(value)
            if str(value) not in set(map(str, allowed)):
                ok = False
                break
        if ok:
            return i
    return None


# ---------------------------------------------------------------- windows and locks


class Windows:
    """Per-key sliding 60 s windows of timestamps, in memory."""

    def __init__(self):
        self._w: dict[str, deque] = defaultdict(deque)

    def count(self, key: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        q = self._w[key]
        while q and q[0] <= now - WINDOW_S:
            q.popleft()
        return len(q)

    def add(self, key: str, now: float | None = None) -> None:
        self._w[key].append(time.monotonic() if now is None else now)

    def clear(self) -> None:
        self._w.clear()


class State:
    """Everything this module keeps between calls in one gateway process."""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.unverified = Windows()  # per source address: failed verifications
        self.per_key = Windows()  # per agent_id: verified calls
        self.per_entry = Windows()  # per (family, entry): allowed calls
        self.last_recorded: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def lock(self, family: str) -> asyncio.Lock:
        return self._locks[family]

    def should_record(self, caller: str) -> bool:
        """While a ceiling holds, at most `record_per_second` events per caller per second."""
        if self.limits.record_per_second == 0:
            return False
        now = time.monotonic()
        last = self.last_recorded.get(caller, 0.0)
        if now - last >= 1.0 / self.limits.record_per_second:
            self.last_recorded[caller] = now
            return True
        return False


def alert_id(*parts: str) -> str:
    """A deterministic event UUID, so the same alert is stored once."""
    return str(uuid.uuid5(ALERT_NAMESPACE, "|".join(parts)))


def hour_bucket(now: float | None = None) -> str:
    return str(int((time.time() if now is None else now) // 3600))


# ---------------------------------------------------------------- the request path (called from gateway/main.py)


@dataclass
class Plan:
    """What the budget layer knows about one verified call, between deciding and recording it."""

    family: str
    entry: int | None
    claimed: Claimed
    agent_id: str | None

    @property
    def claimless(self) -> bool:
        return not self.claimed.has_claims

    def entry_key(self) -> str:
        return f"{self.family}|{self.entry}"


def source_over_ceiling(st: State, source: str) -> bool:
    """Too many failed verifications from this address in the last minute (checked before deciding)."""
    limit = st.limits.unverified_per_source_per_minute
    return bool(limit) and st.unverified.count(source) >= limit


def plan_for(st: State, claims: dict, server: str, tool: str, arguments: dict) -> Plan:
    """Raises BudgetInvalid for a malformed budget or rate claim."""
    claimed = parse_claims(claims)
    entry = matched_entry(server, tool, arguments, claims.get("scope", []))
    return Plan(family_of(claims), entry, claimed, claims.get("agent_id"))


def key_over_ceiling(st: State, agent_id: str | None) -> bool:
    """Counts this call against the agent key's ceiling and says whether it's over."""
    limit = st.limits.per_key_per_minute
    if not agent_id or not limit:
        return False
    over = st.per_key.count(agent_id) >= limit
    st.per_key.add(agent_id)
    return over


def pupil_limit(st: State, plan: Plan) -> int | None:
    return plan.claimed.budget.get("distinct_pupils") or (st.limits.default_distinct_pupils if plan.claimless
                                                         else None)  # fmt: skip


def calls_limit(st: State, plan: Plan) -> int | None:
    return plan.claimed.budget.get("calls") or (st.limits.default_calls if plan.claimless else None)


async def before_forward(st: State, plan: Plan) -> tuple[str, str] | None:
    """(reason_code, detail) refusing the call before it reaches the data, or None. Hold st.lock(family)."""
    from . import audit  # noqa: PLC0415

    rate = plan.claimed.rates.get(plan.entry, {}) if plan.entry is not None else {}
    if "per_minute" in rate and st.per_entry.count(plan.entry_key()) >= rate["per_minute"]:
        return "RATE_LIMITED", f"per_minute {rate['per_minute']} on scope entry {plan.entry}"
    if "max_calls" in rate and await audit.family_allowed_calls(plan.family, plan.entry) >= rate["max_calls"]:
        return "BUDGET_EXHAUSTED", f"max_calls {rate['max_calls']} on scope entry {plan.entry}"
    limit = calls_limit(st, plan)
    if limit and await audit.family_allowed_calls(plan.family) >= limit:
        return "BUDGET_EXHAUSTED", f"calls {limit}"
    return None


async def over_pupil_budget(st: State, plan: Plan, pupils: list[str]) -> tuple[str, str] | None:
    """After forwarding, before release: would these pupils take the family past its budget?"""
    from . import audit  # noqa: PLC0415

    limit = pupil_limit(st, plan)
    if not limit or not pupils:
        return None
    seen = await audit.family_pupils(plan.family)
    if len(seen | set(pupils)) > limit:
        return "BUDGET_EXHAUSTED", f"distinct_pupils {limit}"
    return None


def after_allowed(st: State, plan: Plan) -> None:
    if plan.entry is not None and "per_minute" in plan.claimed.rates.get(plan.entry, {}):
        st.per_entry.add(plan.entry_key())


async def raise_alerts(st: State, plan: Plan, claims: dict, pupils: list[str]) -> list[str]:
    """Alerts for mandates without budget or rate claims. Never changes a decision; returns the reasons raised."""
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from . import audit  # noqa: PLC0415

    if not plan.claimless:
        return []
    jti, principal, lim, raised = claims["jti"], (claims.get("delegator") or {}).get("principal"), st.limits, []
    if lim.refusals_in_a_row and (await audit.history(jti)).refusals_in_a_row >= lim.refusals_in_a_row:
        raised.append(("ALERT_REFUSALS", alert_id(jti, "refusals"), None))
    if lim.many_pupils and len(await audit.family_pupils(plan.family)) > lim.many_pupils:
        raised.append(("ALERT_MANY_PUPILS", alert_id(plan.family, "many_pupils"), None))
    if lim.pupil_targeted_mandates and pupils:
        since = (datetime.now(UTC) - timedelta(minutes=lim.pupil_targeted_window_minutes)).isoformat()
        bucket = hour_bucket()
        for pupil in pupils:
            if len(await audit.mandates_for_pupil_since(pupil, since)) >= lim.pupil_targeted_mandates:
                raised.append(("ALERT_PUPIL_TARGETED", alert_id(pupil, "targeted", bucket), pupil))
    for reason, event_id, pupil in raised:
        await audit.record_alert(jti=jti, principal=principal, reason_code=reason, event_id=event_id,
                                 pupil_id=pupil, agent_id=plan.agent_id)  # fmt: skip
    return [r for r, _, _ in raised]
