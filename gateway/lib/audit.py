"""Audit trail: one signed, hash-chained event per gateway decision (OpenSpec add-audit-trail).

    record(...)          one event per POST /tools/call, refusals included
    record_external(...) events other layers add to the same chain (approvals)
    events(...) / saw()  what the `audit` server answers, filtered by the reader's scope
    history(jti)         a read-only summary other layers decide on (verified events only)
    verify_chain(...)    recompute hashes and signatures, check saved anchors

Data rule: events hold identifiers (pupil IDs, jti, agent_id), column names and PII *levels*, never data values.
Argument values are stored only for the scope keys in gateway_verify.AUDITED_SCOPE_KEYS.

Storage is a SQLite file when GATEWAY_AUDIT_DB is set (append-only by triggers, one writer at a time), otherwise in
memory, which is lost on restart. Either way the chain is the same: event_hash = sha256 over the canonical JSON of the event
(everything but seq, event_hash, sig) including prev_hash, and sig is the gateway key's Ed25519 signature over
event_hash.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt

from .common import canonical, generate_keypair, priv_from_pem, priv_to_pem, pub_to_pem, sha256_hex, sign_bytes, verify_bytes
from .interfaces import SERVER_LEVELS

log = logging.getLogger(__name__)

ZERO_HASH = "sha256:" + "0" * 64
MAX_EVENTS = 500  # per audit.events call
MAX_ARG_KEYS, MAX_KEY_LEN = 32, 64  # bounds what a forged request can make us store
PUPIL_KEYS = ("Psuedo ID", "pupil_id")
PUPIL_ID = re.compile(r"^P\d{4}$")
UNLISTED_LEVEL = 4
# Columns that tools derive rather than read from a table. Gateway policy; moves to the access config when it lands.
COLUMN_LEVEL_OVERRIDES = {"letter": 2, "total": 1, "count": 1, "suppressed_groups": 1}  # aggregates are not data
DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "mcp_server/data/synthetic/synthetic_manifest.json"
APPROVAL_EVENTS = ("approval_requested", "approval_granted", "approval_denied", "approval_expired")
# Servers the gateway answers itself. Their results are gateway metadata, not table rows, so they are scored at the
# server's own data level rather than by their keys (a flat dict of non-manifest keys would otherwise score 4).
GATEWAY_SERVERS = frozenset({"audit", "grants"})
EXTERNAL_EVENT_TYP = "audit-event+jwt"
EXTERNAL_EVENT_MAX_AGE_S = 24 * 3600  # an issuer outbox may retry for a day

# Every field an event carries, in no particular order (canonical JSON sorts them). seq, event_hash and sig are
# stored alongside but are not part of what is hashed.
FIELDS = (
    "decision_id", "ts", "event_type", "identity_verified",
    "jti", "agent_id", "iss", "issuer_kid", "status_idx", "principal", "parent_jti",
    "server", "tool", "arg_keys", "arg_hash", "scope_urn", "scope_pupil_id",
    "decision", "reason_code", "policy_version", "mandate_hash", "source_addr", "http_status",
    "rows_returned", "pupil_ids_returned", "columns_returned", "max_pii_level", "result_hash",
    "ref_decision_id", "prev_hash",
)  # fmt: skip
ARRAY_FIELDS = ("arg_keys", "pupil_ids_returned", "columns_returned")
# Fields added after events were already being chained. They are hashed only when set, so every event stored before
# a field existed still verifies unchanged.
OPTIONAL_FIELDS = (
    "minted_jti",  # approval_granted: the supplementary mandate the approval produced
    "family_jti",  # the mandate's parent jti, or its own: whose budget a call draws on (add-run-budgets)
    "scope_entry",  # index of the scope entry that allowed the call, for per-entry limits
)
ALERT_EVENT = "alert"
EVENT_TYPES = ("decision", *APPROVAL_EVENTS, ALERT_EVENT)


class AuditUnavailable(Exception):
    """The configured store could not write an event: the caller must withhold any result."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def norm_ts(value: Any) -> str:
    """One spelling for a timestamp, so an event hashes the same before and after a database round trip."""
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    return datetime.fromisoformat(str(value)).astimezone(UTC).isoformat(timespec="microseconds")


def content_of(event: dict) -> dict:
    """The hashed part of an event: every field, arrays sorted, the timestamp normalised."""
    out = {k: event.get(k) for k in FIELDS}
    for k in ARRAY_FIELDS:
        out[k] = sorted(out[k] or [])
    out["ts"] = norm_ts(out["ts"])
    for k in ("decision_id", "ref_decision_id"):
        out[k] = None if out[k] is None else str(out[k])
    for k in OPTIONAL_FIELDS:
        if event.get(k) is not None:
            out[k] = str(event[k])
    return out


def event_hash(content: dict) -> str:
    return sha256_hex(canonical(content))


# ---------------------------------------------------------------- what came back


@lru_cache
def _column_levels() -> dict[str, int]:
    """Column name -> the highest level any manifest table gives it."""
    path = Path(os.environ.get("GATEWAY_MANIFEST_PATH", DEFAULT_MANIFEST))
    try:
        columns = json.loads(path.read_text())["classification"]["columns"]
    except (OSError, KeyError, ValueError):
        log.warning("no data manifest at %s: every column counts as level %s", path, UNLISTED_LEVEL)
        return {}
    levels: dict[str, int] = {}
    for table in columns.values():
        for name, level in table.items():
            levels[name] = max(level, levels.get(name, 0))
    return levels


def column_level(name: str) -> int:
    if name in COLUMN_LEVEL_OVERRIDES:
        return COLUMN_LEVEL_OVERRIDES[name]
    return _column_levels().get(name, UNLISTED_LEVEL)


@dataclass(frozen=True)
class Summary:
    rows: int
    pupil_ids: list[str]
    columns: list[str]
    max_pii_level: int | None
    result_hash: str


SCALARS = (str, int, float, bool, type(None))


def _is_row(value: Any) -> bool:
    """A table row: a dict of scalar values. A dict holding lists or dicts is a document, not a row."""
    return isinstance(value, dict) and bool(value) and all(isinstance(v, SCALARS) for v in value.values())


def _rows_of(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [r for r in data if _is_row(r)]
    return [data] if _is_row(data) else []


def _pupils_in(data: Any, found: set[str]) -> None:
    if isinstance(data, dict):
        for k, v in data.items():
            if k in PUPIL_KEYS and isinstance(v, str) and PUPIL_ID.match(v):
                found.add(v)
            elif k == "pupil_ids" and isinstance(v, list):  # e.g. audit.saw, draft's arguments echoed back
                found.update(p for p in v if isinstance(p, str) and PUPIL_ID.match(p))
            else:
                _pupils_in(v, found)
    elif isinstance(data, list):
        for v in data:
            _pupils_in(v, found)


def summarise(data: Any, server: str | None = None, *, min_level: int | None = None) -> Summary:
    """What a result handed to the agent: row count, pupil IDs, column names, highest PII level, a hash.

    A result from a server the gateway answers itself (`audit`, `grants`) has no table columns and is scored at that
    server's data level, so reading the audit trail or a request's status doesn't count as seeing special category data.
    """
    pupils: set[str] = set()
    _pupils_in(data, pupils)
    if server in GATEWAY_SERVERS:
        count = len(data) if isinstance(data, list) else (1 if data not in (None, {}) else 0)
        level = SERVER_LEVELS.get(server, 1) if count else None
        return Summary(count, sorted(pupils), [], level, sha256_hex(canonical(data)))
    rows = _rows_of(data)
    columns = sorted({k for r in rows for k in r})
    level = max((column_level(c) for c in columns), default=None)
    if min_level is not None and data not in (None, [], {}):  # e.g. counts: the level of what was counted
        level = max(level or 0, min_level)
    if level is None and data not in (None, [], {}):
        # a document (a JSON file, classification(), an audit read): no table columns; pupil IDs make it level 2
        level = 2 if pupils else 1
    count = len(data) if isinstance(data, list) else (1 if data not in (None, {}) else 0)
    return Summary(count, sorted(pupils), columns, level, sha256_hex(canonical(data)))


# ---------------------------------------------------------------- signing


class Signer:
    """Signs event hashes with the gateway key (gateway/state/gateway_key.pem, made by `cli init`)."""

    def __init__(self, state_dir: Path | None):
        key_path = state_dir / "gateway_key.pem" if state_dir else None
        if key_path and key_path.exists():
            self.priv = priv_from_pem(key_path.read_bytes())
        else:
            log.warning("no gateway_key.pem: audit events are signed with a throwaway key and can't be verified")
            self.priv, _ = generate_keypair()

    def sign(self, digest: str) -> str:
        return sign_bytes(self.priv, digest.encode())


# ---------------------------------------------------------------- stores


def _matches(event: dict, principal: str | None, jti: str | None) -> bool:
    return (principal is None or event["principal"] == principal) and (jti is None or event["jti"] == jti)


def _in_family(event: dict, family: str) -> bool:
    """Events of a family: tagged with it, or (events from before family_jti existed) the mandate itself."""
    tagged = event.get("family_jti")
    return tagged == family if tagged is not None else event["jti"] == family


def _in_range(event: dict, since: str | None, until: str | None) -> bool:
    ts = norm_ts(event["ts"])
    return (since is None or ts >= norm_ts(since)) and (until is None or ts <= norm_ts(until))


class MemoryStore:
    """Events in a list. Lost on restart; used when no audit database is configured."""

    durable = False

    def __init__(self, signer: Signer):
        self.signer = signer
        self._events: list[dict] = []
        self._lock = asyncio.Lock()

    async def append(self, event: dict) -> dict:
        async with self._lock:
            prev = self._events[-1]["event_hash"] if self._events else ZERO_HASH
            content = content_of({**event, "prev_hash": prev})
            digest = event_hash(content)
            stored = {**content, "seq": len(self._events) + 1, "event_hash": digest, "sig": self.signer.sign(digest)}
            self._events.append(stored)
            return stored

    async def head(self) -> dict | None:
        return self._events[-1] if self._events else None

    async def all_events(self) -> list[dict]:
        return list(self._events)

    async def for_jtis(self, jtis: set[str]) -> list[dict]:
        return [e for e in self._events if e["jti"] in jtis]

    async def by_decision_id(self, decision_id: str) -> dict | None:
        return next((e for e in self._events if e["decision_id"] == decision_id), None)

    async def verified_matching(self, principal: str | None, jti: str | None) -> list[dict]:
        return [e for e in self._events if e["identity_verified"] and _matches(e, principal, jti)]

    async def family_events(self, family: str) -> list[dict]:
        return [e for e in self._events if e["identity_verified"] and _in_family(e, family)]

    async def pupil_events_since(self, pupil: str, since: str) -> list[dict]:
        return [e for e in self._events if e["identity_verified"] and pupil in e["pupil_ids_returned"]
                and norm_ts(e["ts"]) >= since]  # fmt: skip


SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, note TEXT NOT NULL);
INSERT OR IGNORE INTO schema_version (version, note) VALUES (1, 'audit trail (add-audit-trail)');

CREATE TABLE IF NOT EXISTS audit_events (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id        TEXT NOT NULL UNIQUE,
    ts                 TEXT NOT NULL,
    event_type         TEXT NOT NULL CHECK (event_type IN ('decision', 'approval_requested', 'approval_granted',
                                                           'approval_denied', 'approval_expired', 'alert')),
    identity_verified  INTEGER NOT NULL CHECK (identity_verified IN (0, 1)),
    jti TEXT, agent_id TEXT, iss TEXT, issuer_kid TEXT, status_idx INTEGER, principal TEXT, parent_jti TEXT,
    server             TEXT NOT NULL,
    tool               TEXT NOT NULL,
    arg_keys           TEXT NOT NULL,  -- JSON array
    arg_hash           TEXT NOT NULL,
    scope_urn TEXT, scope_pupil_id TEXT,
    decision           TEXT CHECK (decision IS NULL OR decision IN ('ALLOW', 'DENY', 'STEP_UP')),
    reason_code        TEXT NOT NULL,
    policy_version TEXT, mandate_hash TEXT, source_addr TEXT, http_status INTEGER,
    rows_returned      INTEGER,
    pupil_ids_returned TEXT NOT NULL,  -- JSON array
    columns_returned   TEXT NOT NULL,  -- JSON array
    max_pii_level      INTEGER CHECK (max_pii_level IS NULL OR max_pii_level BETWEEN 1 AND 4),
    result_hash TEXT, ref_decision_id TEXT, minted_jti TEXT, family_jti TEXT, scope_entry TEXT,
    prev_hash          TEXT NOT NULL UNIQUE,  -- each event can be extended once: the chain can't fork
    event_hash         TEXT NOT NULL UNIQUE,
    sig                TEXT NOT NULL,
    CHECK (event_type <> 'decision' OR decision IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS audit_events_jti ON audit_events (jti, seq);
CREATE INDEX IF NOT EXISTS audit_events_principal ON audit_events (principal, seq);
CREATE INDEX IF NOT EXISTS audit_events_family ON audit_events (family_jti, seq);
CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events (ts);

-- Append-only for every connection, short of dropping the trigger (which the anchors would then expose).
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
"""
COLUMNS = ("seq", *FIELDS, *OPTIONAL_FIELDS, "event_hash", "sig")


class SqliteStore:
    """gateway's audit trail in one SQLite file. One connection, one writer at a time, WAL so readers don't block.

    Writes run in a worker thread (sqlite3 is blocking) behind a lock, and each append is one BEGIN IMMEDIATE
    transaction that reads the last hash and inserts the next event, so the chain can't fork.
    """

    durable = True

    def __init__(self, signer: Signer | None, path: Path, *, read_only: bool = False):
        self.signer = signer
        self.path = Path(path)
        self._lock = threading.Lock()
        if read_only:
            self._conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")  # an acknowledged event survives a crash
            self._migrate()
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.row_factory = sqlite3.Row

    def _migrate(self) -> None:
        """Create the schema, or bring a file made by an earlier version up to it without changing any event.

        - Optional columns added later are added with ALTER TABLE.
        - The event-type check can't be altered in SQLite, so a file whose check predates `alert` is rebuilt:
          the table is copied row by row into the current schema, in one transaction. Hashes and signatures are
          unchanged, so the chain still verifies.
        """
        conn = self._conn
        table_sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_events'").fetchone()
        if table_sql and "'alert'" not in table_sql[0]:
            old_cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_events)")]
            conn.execute("BEGIN IMMEDIATE")
            try:
                for name in ("audit_events_no_update", "audit_events_no_delete"):
                    conn.execute(f"DROP TRIGGER IF EXISTS {name}")
                conn.execute("ALTER TABLE audit_events RENAME TO audit_events_before_alerts")
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name="
                                        "'audit_events_before_alerts' AND name LIKE 'audit_events_%'").fetchall():
                    conn.execute(f"DROP INDEX IF EXISTS {row[0]}")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.executescript(SQLITE_SCHEMA)
            cols = ", ".join(c for c in old_cols if c in COLUMNS)
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(f"INSERT INTO audit_events ({cols}) SELECT {cols} FROM audit_events_before_alerts")  # noqa: S608
                conn.execute("DROP TABLE audit_events_before_alerts")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        conn.executescript(SQLITE_SCHEMA.split("CREATE INDEX")[0])  # tables first, for a fresh file
        existing = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)")}
        for column in OPTIONAL_FIELDS:  # a file created before the field existed gains the column
            if column not in existing:
                conn.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
        conn.executescript(SQLITE_SCHEMA)  # indexes and triggers, now that every column exists

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _to_event(row: sqlite3.Row) -> dict:
        out = dict(row)
        out["identity_verified"] = bool(out["identity_verified"])
        for k in ARRAY_FIELDS:
            out[k] = json.loads(out[k])
        return out

    def _append_sync(self, event: dict) -> dict:
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                last = conn.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
                content = content_of({**event, "prev_hash": last[0] if last else ZERO_HASH})
                digest = event_hash(content)
                sig = self.signer.sign(digest)
                row = {**content, "event_hash": digest, "sig": sig}
                row["identity_verified"] = int(bool(row["identity_verified"]))
                for k in ARRAY_FIELDS:
                    row[k] = json.dumps(row[k])
                cols = [*FIELDS, *OPTIONAL_FIELDS, "event_hash", "sig"]
                row.update({k: content.get(k) for k in OPTIONAL_FIELDS})
                cur = conn.execute(
                    f"INSERT INTO audit_events ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",  # noqa: S608
                    [row[k] for k in cols],
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            return {**content, "seq": cur.lastrowid, "event_hash": digest, "sig": sig}

    async def append(self, event: dict) -> dict:
        try:
            return await asyncio.to_thread(self._append_sync, event)
        except Exception as e:
            raise AuditUnavailable(type(e).__name__) from e

    def _select_sync(self, where: str = "", params: tuple = ()) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {', '.join(COLUMNS)} FROM audit_events {where} ORDER BY seq", params  # noqa: S608
            ).fetchall()
        return [self._to_event(r) for r in rows]

    async def _select(self, where: str = "", params: tuple = ()) -> list[dict]:
        return await asyncio.to_thread(self._select_sync, where, params)

    async def head(self) -> dict | None:
        rows = await self._select("WHERE seq = (SELECT max(seq) FROM audit_events)")
        return rows[0] if rows else None

    async def all_events(self) -> list[dict]:
        return await self._select()

    async def by_decision_id(self, decision_id: str) -> dict | None:
        rows = await self._select("WHERE decision_id = ?", (decision_id,))
        return rows[0] if rows else None

    async def for_jtis(self, jtis: set[str]) -> list[dict]:
        if not jtis:
            return []
        marks = ", ".join("?" * len(jtis))
        return await self._select(f"WHERE jti IN ({marks})", tuple(sorted(jtis)))

    async def verified_matching(self, principal: str | None, jti: str | None) -> list[dict]:
        clauses, params = ["identity_verified = 1"], []
        if principal is not None:
            clauses.append("principal = ?")
            params.append(principal)
        if jti is not None:
            clauses.append("jti = ?")
            params.append(jti)
        return await self._select("WHERE " + " AND ".join(clauses), tuple(params))

    async def family_events(self, family: str) -> list[dict]:
        rows = await self._select("WHERE identity_verified = 1 AND (family_jti = ? OR jti = ?)", (family, family))
        return [e for e in rows if _in_family(e, family)]

    async def pupil_events_since(self, pupil: str, since: str) -> list[dict]:
        rows = await self._select(
            "WHERE identity_verified = 1 AND ts >= ? AND pupil_ids_returned LIKE ?", (since, f'%"{pupil}"%')
        )
        return [e for e in rows if pupil in e["pupil_ids_returned"]]


AUDIT_DB_ENV = "GATEWAY_AUDIT_DB"
_store: MemoryStore | SqliteStore | None = None


def init_store(state_dir: Path | None, db_path: str | Path | None = None) -> MemoryStore | SqliteStore:
    """SQLite at db_path or $GATEWAY_AUDIT_DB when either is set, otherwise memory. Fails loudly if unopenable."""
    global _store  # noqa: PLW0603
    signer = Signer(state_dir)
    path = db_path or os.environ.get(AUDIT_DB_ENV)
    _store = SqliteStore(signer, Path(path)) if path else MemoryStore(signer)
    log.info("audit store: %s", f"sqlite {path}" if path else "memory (lost on restart)")
    return _store


def get_store() -> MemoryStore | SqliteStore:
    if _store is None:
        return init_store(None)
    return _store


def store_status() -> dict:
    """For /healthcheck/audit: which store, and whether it's durable. No paths or event data."""
    store = get_store()
    return {"store": "sqlite" if isinstance(store, SqliteStore) else "memory", "durable": store.durable}


# ---------------------------------------------------------------- writing


def _arg_keys(arguments: dict) -> list[str]:
    return sorted(str(k)[:MAX_KEY_LEN] for k in list(arguments)[:MAX_ARG_KEYS])


def _arg_hash(arguments: dict) -> str:
    try:
        return sha256_hex(canonical(arguments))
    except (TypeError, ValueError):
        return sha256_hex(repr(arguments).encode())


def _parent_jti(claims: dict) -> str | None:
    """The parent mandate's jti: `parent.jti` (supplementary mandates), or a top-level `parent_jti`."""
    parent = claims.get("parent")
    if isinstance(parent, dict) and isinstance(parent.get("jti"), str):
        return parent["jti"]
    value = claims.get("parent_jti")
    return value if isinstance(value, str) else None


async def record(
    *,
    decision: dict,
    ctx,
    server: str,
    tool: str,
    arguments: dict,
    source_addr: str | None,
    http_status: int,
    summary: Summary | None = None,
    scope_entry: int | None = None,
) -> dict:
    """Write the one event for a tools/call. `decision` is Decision.to_dict() plus decision_id."""
    claims = ctx.claims if ctx.identity_verified else None
    status = (claims or {}).get("status", {}).get("status_list", {})
    event = {
        "decision_id": decision["decision_id"],
        "ts": now_iso(),
        "event_type": "decision",
        "identity_verified": bool(ctx.identity_verified),
        "jti": claims["jti"] if claims else ctx.claimed_jti,
        "agent_id": claims.get("agent_id") if claims else None,
        "iss": claims["iss"] if claims else ctx.claimed_iss,
        "issuer_kid": ctx.kid,
        "status_idx": status.get("idx") if claims else None,
        "principal": (claims.get("delegator") or {}).get("principal") if claims else None,
        "parent_jti": _parent_jti(claims) if claims else None,
        "server": str(server)[:MAX_KEY_LEN],
        "tool": str(tool)[:MAX_KEY_LEN],
        "arg_keys": _arg_keys(arguments),
        "arg_hash": _arg_hash(arguments),
        "scope_urn": ctx.scope_values.get("urn"),
        "scope_pupil_id": ctx.scope_values.get("pupil_id"),
        "decision": decision["decision"],
        "reason_code": decision["reason_code"],
        "policy_version": decision.get("policy_version"),
        "mandate_hash": decision.get("mandate_hash"),
        "source_addr": source_addr,
        "http_status": http_status,
        "rows_returned": summary.rows if summary else None,
        "pupil_ids_returned": summary.pupil_ids if summary else [],
        "columns_returned": summary.columns if summary else [],
        "max_pii_level": summary.max_pii_level if summary else None,
        "result_hash": summary.result_hash if summary else None,
        "ref_decision_id": None,
        "family_jti": (_parent_jti(claims) or claims["jti"]) if claims else None,
        "scope_entry": scope_entry,
    }
    try:
        return await get_store().append(event)
    except AuditUnavailable:
        raise
    except Exception as e:  # a store bug must also withhold results
        raise AuditUnavailable(type(e).__name__) from e


async def record_external(
    event_type: str,
    *,
    jti: str,
    server: str,
    tool: str,
    ref_decision_id: str,
    reason_code: str,
    principal: str | None = None,
    agent_id: str | None = None,
    event_id: str | None = None,
    minted_jti: str | None = None,
) -> dict:
    """Add an event another gateway layer produced (approvals) to the same chain. jti must be verified upstream.

    `event_id` becomes the event's decision_id. Passing the same one twice records it once: the second call returns
    the stored event, so a sender that retries after a lost acknowledgement doesn't duplicate history.
    """
    if event_type not in APPROVAL_EVENTS:
        msg = f"event_type must be one of {APPROVAL_EVENTS}"
        raise ValueError(msg)
    decision_id = str(uuid.UUID(event_id)) if event_id else str(uuid.uuid4())
    store = get_store()
    if event_id and (existing := await store.by_decision_id(decision_id)):
        return existing
    event = dict.fromkeys(FIELDS)
    event.update(
        decision_id=decision_id,
        ts=now_iso(),
        event_type=event_type,
        identity_verified=True,
        jti=jti,
        agent_id=agent_id,
        principal=principal,
        server=server,
        tool=tool,
        arg_keys=[],
        arg_hash=sha256_hex(b"{}"),
        reason_code=reason_code,
        ref_decision_id=ref_decision_id,
        policy_version=None,
        minted_jti=minted_jti,
    )
    return await store.append(event)


async def record_alert(*, jti: str, principal: str | None, reason_code: str, event_id: str,
                       pupil_id: str | None = None, agent_id: str | None = None) -> dict:
    """A gateway alert about a verified mandate, in the same chain. Recorded once per event_id."""
    store = get_store()
    decision_id = str(uuid.UUID(event_id))
    if existing := await store.by_decision_id(decision_id):
        return existing
    event = dict.fromkeys(FIELDS)
    event.update(
        decision_id=decision_id, ts=now_iso(), event_type=ALERT_EVENT, identity_verified=True, jti=jti,
        agent_id=agent_id, principal=principal, server="gateway", tool="alert", arg_keys=[],
        arg_hash=sha256_hex(b"{}"), reason_code=reason_code, scope_pupil_id=pupil_id,
    )  # fmt: skip
    return await store.append(event)


async def family_pupils(family: str) -> set[str]:
    """Distinct pupils the family's allowed calls received."""
    events = await get_store().family_events(family)
    return {p for e in events if e["event_type"] == "decision" for p in e["pupil_ids_returned"]}


async def family_allowed_calls(family: str, scope_entry: int | None = None) -> int:
    events = await get_store().family_events(family)
    return sum(
        e["event_type"] == "decision" and e["decision"] == "ALLOW"
        and (scope_entry is None or e.get("scope_entry") == str(scope_entry))
        for e in events
    )  # fmt: skip


async def mandates_for_pupil_since(pupil: str, since: str) -> set[str]:
    events = await get_store().pupil_events_since(pupil, norm_ts(since))
    return {e["jti"] for e in events if e["event_type"] == "decision"}


# ---------------------------------------------------------------- events signed by the issuer service


class ExternalEventRejected(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def sign_external_event(priv, *, iss: str, kid: str, event_type: str, mandate_jti: str, server: str, tool: str,
                        ref_decision_id: str, reason_code: str, principal: str | None = None,
                        agent_id: str | None = None, event_id: str | None = None, ttl: int = 3600,
                        minted_jti: str | None = None) -> str:
    """For the issuer service: an approval event, signed with the issuer key, that the gateway will record."""
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": iss, "jti": event_id or str(uuid.uuid4()), "iat": now, "exp": now + ttl,
        "event_type": event_type, "mandate_jti": mandate_jti, "server": server, "tool": tool,
        "ref_decision_id": ref_decision_id, "reason_code": reason_code,
        "principal": principal, "agent_id": agent_id, "minted_jti": minted_jti,
    }  # fmt: skip
    return jwt.encode(claims, priv_to_pem(priv), algorithm="EdDSA", headers={"typ": EXTERNAL_EVENT_TYP, "kid": kid})


def verify_external_event(token: str, registry) -> dict:
    """The claims of an issuer-signed approval event, or ExternalEventRejected with a stable reason code."""
    try:
        hdr = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:  # noqa: BLE001
        raise ExternalEventRejected("EVENT_INVALID", "not a JWT") from e
    if hdr.get("typ") != EXTERNAL_EVENT_TYP:
        raise ExternalEventRejected("EVENT_INVALID", f"typ must be {EXTERNAL_EVENT_TYP}")
    iss = unverified.get("iss")
    pub = registry.issuer_key(iss, hdr.get("kid", "")) if isinstance(iss, str) else None
    if pub is None:
        raise ExternalEventRejected("ISSUER_NOT_ACCREDITED", str(iss))
    try:
        claims = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                            options={"require": ["iss", "jti", "iat", "exp"]})  # fmt: skip
    except jwt.ExpiredSignatureError as e:
        raise ExternalEventRejected("EVENT_EXPIRED", claims_jti(unverified)) from e
    except jwt.PyJWTError as e:
        raise ExternalEventRejected("SIG_INVALID", type(e).__name__) from e
    now = datetime.now(UTC).timestamp()
    if not isinstance(claims["iat"], int) or claims["iat"] > now + 30 or claims["iat"] < now - EXTERNAL_EVENT_MAX_AGE_S:
        raise ExternalEventRejected("EVENT_EXPIRED", claims_jti(claims))
    if claims.get("event_type") not in APPROVAL_EVENTS:
        raise ExternalEventRejected("EVENT_REJECTED", f"event_type must be one of {APPROVAL_EVENTS}")
    for k in ("mandate_jti", "server", "tool", "ref_decision_id", "reason_code"):
        if not isinstance(claims.get(k), str) or not claims[k]:
            raise ExternalEventRejected("EVENT_REJECTED", f"{k} is required")
    if claims.get("minted_jti") is not None and not isinstance(claims["minted_jti"], str):
        raise ExternalEventRejected("EVENT_REJECTED", "minted_jti must be a string")
    try:
        uuid.UUID(claims["jti"])
    except (ValueError, TypeError) as e:
        raise ExternalEventRejected("EVENT_REJECTED", "jti must be a UUID") from e
    return claims


def claims_jti(claims: dict) -> str:
    return str(claims.get("jti", ""))


async def record_signed_external(token: str, registry) -> tuple[dict, bool]:
    """Verify an issuer-signed event and record it once. Returns (stored event, newly recorded)."""
    c = verify_external_event(token, registry)
    before = await get_store().by_decision_id(str(uuid.UUID(c["jti"])))
    stored = await record_external(
        c["event_type"], jti=c["mandate_jti"], server=c["server"], tool=c["tool"],
        ref_decision_id=c["ref_decision_id"], reason_code=c["reason_code"], principal=c.get("principal"),
        agent_id=c.get("agent_id"), event_id=c["jti"], minted_jti=c.get("minted_jti"),
    )  # fmt: skip
    return stored, before is None


# ---------------------------------------------------------------- reading


@dataclass(frozen=True)
class History:
    """A mandate's history from verified events only, so forged traffic can't change it."""

    jti: str
    calls_by_tool: dict[str, int] = field(default_factory=dict)
    allowed_by_tool: dict[str, int] = field(default_factory=dict)
    reasons: dict[str, int] = field(default_factory=dict)
    distinct_pupils: int = 0
    max_pii_level: int | None = None
    refusals_in_a_row: int = 0
    first_ts: str | None = None
    last_ts: str | None = None


def history_from(jti: str, events: list[dict]) -> History:
    decisions = [e for e in events if e["identity_verified"] and e["jti"] == jti and e["event_type"] == "decision"]
    calls, allowed, reasons, pupils = {}, {}, {}, set()
    level, streak = None, 0
    for e in decisions:
        key = f"{e['server']}.{e['tool']}"
        calls[key] = calls.get(key, 0) + 1
        reasons[e["reason_code"]] = reasons.get(e["reason_code"], 0) + 1
        if e["decision"] == "ALLOW":
            allowed[key] = allowed.get(key, 0) + 1
        pupils.update(e["pupil_ids_returned"])
        if e["max_pii_level"] is not None:
            level = max(level or 0, e["max_pii_level"])
        streak = streak + 1 if e["decision"] == "DENY" else 0
    return History(
        jti, calls, allowed, reasons, len(pupils), level, streak,
        decisions[0]["ts"] if decisions else None, decisions[-1]["ts"] if decisions else None,
    )  # fmt: skip


async def history(jti: str) -> History:
    return history_from(jti, await get_store().verified_matching(None, jti))


def _public(e: dict) -> dict:
    """An event as the request log shows it: who, when, from where, what, how it was decided. No result data."""
    return {
        "decision_id": e["decision_id"], "ts": e["ts"], "event_type": e["event_type"],
        "identity_verified": e["identity_verified"], "jti": e["jti"], "agent_id": e["agent_id"],
        "source_addr": e["source_addr"], "server": e["server"], "tool": e["tool"], "arg_keys": e["arg_keys"],
        "decision": e["decision"], "reason_code": e["reason_code"], "ref_decision_id": e["ref_decision_id"],
        "minted_jti": e.get("minted_jti"),
        **({"pupil_id": e["scope_pupil_id"]} if e["event_type"] == ALERT_EVENT else {}),
    }  # fmt: skip


def _filters(arguments: dict) -> tuple[str | None, str | None]:
    principal, jti = arguments.get("principal"), arguments.get("jti")
    if principal is None and jti is None:
        msg = "name a principal or a jti"
        raise ValueError(msg)
    for name, value in (("principal", principal), ("jti", jti)):
        if value is not None and not isinstance(value, str):
            msg = f"{name} must be a string"
            raise ValueError(msg)
    return principal, jti


async def events(arguments: dict) -> dict:
    """audit.events: the request log for a principal or a jti, verified events plus calls that only claim a jti."""
    principal, jti = _filters(arguments)
    since, until = arguments.get("since"), arguments.get("until")
    limit = arguments.get("limit", MAX_EVENTS)
    if type(limit) is not int or not 1 <= limit <= MAX_EVENTS:
        msg = f"limit must be an integer from 1 to {MAX_EVENTS}"
        raise ValueError(msg)
    store = get_store()
    verified = [e for e in await store.verified_matching(principal, jti) if _in_range(e, since, until)]
    jtis = {jti} if jti is not None else {e["jti"] for e in verified if e["jti"]}
    if principal is not None and jti is not None:
        jtis = {jti} if any(e["jti"] == jti for e in verified) else set()
    claimed = [e for e in await store.for_jtis(jtis) if not e["identity_verified"] and _in_range(e, since, until)]
    return {
        "verified": [_public(e) for e in verified[:limit]],
        "claimed": [_public(e) for e in claimed[:limit]],
        "truncated": len(verified) > limit or len(claimed) > limit,
    }


LEVEL_WORDS = {
    1: "public data only",
    2: "basic personal data such as names",
    3: "sensitive personal data",
    4: "records including special category data such as ethnicity or care status",
}


def _sentence(revoked: bool | None, n_events: int, n_pupils: int, schools: set[str], level: int | None) -> str:
    if n_events == 0:
        return "This access was never used."
    if level is None:
        return f"This access was used {n_events} time{'s' * (n_events != 1)} but returned no data."
    lead = "Before it was revoked, this access returned" if revoked else "This access has returned"
    who = f"{n_pupils} pupil{'s' * (n_pupils != 1)}" if n_pupils else "no individual pupils"
    where = f" at {len(schools)} school{'s' * (len(schools) != 1)}" if schools else ""
    return f"{lead} {LEVEL_WORDS[level]} for {who}{where}."


async def saw(arguments: dict, is_revoked=None) -> dict:
    """audit.saw: everything a mandate's allowed calls returned. is_revoked(event) -> bool | None."""
    principal, jti = _filters(arguments)
    if jti is None:
        msg = "audit.saw needs a jti"
        raise ValueError(msg)
    mine = [e for e in await get_store().verified_matching(principal, jti) if e["event_type"] == "decision"]
    allowed = [e for e in mine if e["decision"] == "ALLOW"]
    pupils = sorted({p for e in allowed for p in e["pupil_ids_returned"]})
    columns = sorted({c for e in allowed for c in e["columns_returned"]})
    levels = [e["max_pii_level"] for e in allowed if e["max_pii_level"] is not None]
    level = max(levels) if levels else None
    schools = {e["scope_urn"] for e in allowed if e["scope_urn"]}
    revoked = is_revoked(mine[-1]) if (mine and is_revoked) else None
    return {
        "jti": jti,
        "pupil_ids": pupils,
        "columns": columns,
        "max_pii_level": level,
        "schools": sorted(schools),
        "calls": {
            "allowed": len(allowed),
            "held": sum(e["decision"] == "STEP_UP" for e in mine),
            "refused": sum(e["decision"] == "DENY" for e in mine),
        },
        "first_ts": mine[0]["ts"] if mine else None,
        "last_ts": mine[-1]["ts"] if mine else None,
        "revoked": revoked,
        "summary": _sentence(revoked, len(mine), len(pupils), schools, level),
    }


async def handle(tool: str, arguments: dict, is_revoked=None) -> dict:
    """The `audit` server's tools. Access control already ran: scope constraints limit principal and jti."""
    if tool == "events":
        return await events(arguments)
    if tool == "saw":
        return await saw(arguments, is_revoked)
    msg = f"unknown audit tool {tool!r}"
    raise ValueError(msg)


async def head() -> dict:
    """The latest event's seq, hash and signature, and nothing else."""
    store = get_store()
    last = await store.head()
    if last is None:
        return {"seq": 0, "event_hash": ZERO_HASH, "sig": store.signer.sign(ZERO_HASH)}
    return {"seq": last["seq"], "event_hash": last["event_hash"], "sig": last["sig"]}


# ---------------------------------------------------------------- verifying


def verify_chain(chain: list[dict], gateway_pub, anchors: list[dict] = ()) -> list[str]:
    """Problems found, first one first; an empty list means the chain and every anchor check out."""
    problems: list[str] = []
    prev = ZERO_HASH
    by_seq = {}
    for e in sorted(chain, key=lambda e: e["seq"]):
        content = content_of(e)
        digest = event_hash(content)
        if e["prev_hash"] != prev:
            problems.append(f"seq {e['seq']}: prev_hash does not match the event before it")
        if digest != e["event_hash"]:
            problems.append(f"seq {e['seq']}: content does not match event_hash (edited)")
        if not verify_bytes(gateway_pub, e["event_hash"].encode(), e["sig"]):
            problems.append(f"seq {e['seq']}: bad signature")
        by_seq[e["seq"]] = e["event_hash"]
        prev = e["event_hash"]
    for a in anchors:
        seq = a["seq"]
        if seq == 0:
            continue
        if by_seq.get(seq) != a["event_hash"]:
            problems.append(f"anchor seq {seq}: chain no longer contains the saved head (rewritten at or before it)")
    return problems
