## Context

- `tools_call` in `gateway/main.py` builds a `Decision` (decision, reason, policy version, mandate and request hashes, `agent_id`, ts, detail) and returns it. Nothing is kept.
- `Gateway.decide` catches only `Reject`. A mandate that doesn't parse (`"garbage"`) or has no `iss` raises before the first check and returns a `500`, so today such a request couldn't be recorded at all.
- Postgres can't be used where the gateway is deployed, so the store must run inside the gateway container with no extra service. A Postgres dev scaffold exists (PR #2) but this change doesn't depend on it.
- `gateway_key.pem` and `gateway.pub` are created by `cli init` and used by nothing.
- The gateway image copies only `gateway/`. PII levels live in `mcp_server/data/synthetic/synthetic_manifest.json`, which the gateway container can't see today.
- Requirements: `specs/audit-trail/spec.md`, `specs/audit-access/spec.md`, and the `mandate-clearance` delta.

## Goals / Non-Goals

**Goals:**
- One module, `gateway/lib/audit.py`, that the other workstreams call without knowing the storage: `record`, `events`, `history`, plus `record_external` for approval events.
- Recording works the same with the SQLite file and in memory, so tests and the eval run on the base stack.
- Tampering is detectable by someone who doesn't trust the gateway's operator.

**Non-Goals:**
- Acting on history (budgets, suspensions, flow rules). Those read `history()` in their own changes.
- Exporting or redacting events for analysis.
- A UI. The demo frontend stays untouched; reads go through the CLI or `POST /tools/call`.

## Decisions

### 1. One event per call, written after the outcome is known, before the result is released
`tools_call` decides, forwards if allowed, summarises the result, writes the event, and only then returns. If the write fails on an allowed call, the result is dropped and the agent gets `503 AUDIT_UNAVAILABLE`.
- *Alternative:* write a "pending" event before forwarding and a "completed" one after. Rejected: it needs UPDATE (the table is append-only) or two linked rows, and a crash between them leaves a half record. The single write after the outcome is simpler and still fail closed, because nothing leaves before the commit.
- Refusals are returned even if their write fails. Withholding a refusal protects nothing, and a failed write is logged.

### 2. A store interface with two implementations
`AuditStore` with `append(event) -> StoredEvent`, `head()`, `query(filter)` and `history(jti)`.
- `SqliteStore` when `GATEWAY_AUDIT_DB` is set: Python's built-in `sqlite3`, no new dependency, one file on a named volume.
- *Alternative:* Postgres (the dev scaffold). Rejected: not available where we deploy, and a second service for one table is more to run.
- `MemoryStore` otherwise: a list behind an `asyncio.Lock`, lost on restart. `/healthcheck/db` already reports `disabled`, which makes the memory mode visible.
- *Alternative:* a JSONL file in `gateway/state/`. Rejected: no append-only guarantee, awkward concurrent appends, and the state folder is exactly what the Codex review said should stop being mounted.

### 3. Chain appends are serialised by SQLite's single writer
`SqliteStore.append` runs in a worker thread (`asyncio.to_thread`, since `sqlite3` blocks) behind a lock, as one `BEGIN IMMEDIATE` transaction: read the last `event_hash`, compute and sign the new event, insert, commit. `UNIQUE(prev_hash)` is the backstop. WAL mode lets `audit verify` read a copy while the gateway writes; `synchronous=FULL` so an acknowledged event survives a crash. Triggers make `UPDATE` and `DELETE` raise for every connection.
- Traffic is a hackathon's, so one lock is fine.
- *Alternative:* `SERIALIZABLE` isolation with retries. Rejected as more code for no benefit at this volume.

### 4. What is hashed
`event_hash = sha256(canonical(event without seq, event_hash, sig))`, using `common.canonical` (sorted keys, compact separators), the same encoding the request signatures use.
- The timestamp is taken by the gateway and stored as an ISO-8601 UTC string with microseconds, not the database default, so re-hashing after a round trip gives the same bytes.
- Arrays (`arg_keys`, `pupil_ids_returned`, `columns_returned`) are sorted before hashing and storing.
- `sig` is Ed25519 by `gateway_key.pem` over the `event_hash` string.

### 5. Anchoring outside the gateway
Whoever holds the gateway key can rewrite the whole chain and re-sign it. So:
- `GET /audit/head` returns `{seq, event_hash, sig}` only.
- `cli audit anchor --url <gateway>` fetches the head and appends it to a file on the caller's machine (default `audit_anchors.jsonl`), so the issuer's laptop or a teammate keeps heads the operator can't reach.
- `cli audit verify --db <url> --anchors <file>` recomputes every hash, checks every signature with `gateway.pub`, checks each `prev_hash`, and checks that every saved anchor's `seq` still has the saved hash. It reports the first mismatch.
- *Alternative:* sign with a key held only off the gateway. Rejected for now: the gateway must sign as it writes. Anchoring gives the same detection with no key management.

### 6. Identity of early refusals comes from a context object, not the response
`Gateway.decide` keeps returning the same `Decision`. A new `Gateway.decide_with_context(req) -> (Decision, AuditContext)` also returns:
- verified `claims` when they verified;
- otherwise the `jti` and `iss` read with signature verification off, if parsing works, flagged `identity_verified=false`;
- the scope values for `urn` and `pupil_id` when the matching scope entry constrains them.

`decide` becomes a thin wrapper, so existing tests and callers don't change.
- A non-`Reject` exception inside `decide_with_context` becomes `DENY` with reason `MANDATE_MALFORMED`. This replaces today's `500`, which is a crash, not a decision. Coordinate with the access-config workstream, which plans the same catch-all; one implementation lands, in `gateway_verify.py`.

### 7. Result summary
`summarise(server, tool, result) -> (rows, pupil_ids, columns, max_pii_level, result_hash)`:
- `rows`: list length, or 1 for a single dict, or 0 for empty.
- `pupil_ids`: every string value under the keys `Psuedo ID` or `pupil_id`, at any depth, that matches `P` followed by 4 digits.
- `columns`: the keys of the result's row dicts.
- `max_pii_level`: the highest level among those columns. Results of servers the gateway answers itself (`audit`, `grants`) are scored at the server's level from `SERVER_LEVELS` with no columns: they're metadata, and their keys would otherwise count as unlisted level-4 columns. Each column name takes the highest level any manifest table gives it; a name the manifest doesn't list counts as 4. Per-tool overrides for known derived columns (`letter` from `draft` is level 2) live in gateway config, which the access-config workstream owns.
- `result_hash`: sha256 of `canonical(result.data)`.
- The gateway reads the manifest from `GATEWAY_MANIFEST_PATH`, mounted read-only into the gateway container in `docker-compose.yaml`. If it's missing, every column counts as level 4, which over-reports but never under-reports.

### 8. The `audit` server is handled inside the gateway
- `SERVER_LEVELS["audit"] = 2`.
- The normal pipeline (mandate, signature, deny, clearance, scope, constraints) runs first. On ALLOW, `tools_call` dispatches `server == "audit"` to `audit.handle(tool, arguments)` instead of an MCP client.
- Scope constraints do the access control: `audit.events(principal=...)` must match the mandate's `principal` list, and `audit.events(jti=...)` its `jti` list. No new access logic.
- `audit.handle` filters on verified `principal` or `jti`. For a `jti` query it also returns events that only claim that `jti`, in a separate `claimed` list.
- The result of an audit read is summarised and recorded like any other.
- *Alternative:* a separate `GET /audit/...` endpoint with its own authentication. Rejected: it would need its own replay and signature handling, and a mandate per reader is exactly the kit's model.

### 9. Source address
`request.client.host` by default. `X-Forwarded-For`'s first hop is used only if `GATEWAY_TRUSTED_PROXY` names the immediate peer, so an agent can't fake its address.

### 10. History for other layers
`history(jti)` returns a frozen dataclass:
- calls per tool;
- counts per reason code;
- distinct pupils;
- highest PII level;
- refusals in a row;
- first and last time.

It's built from verified events only, so forged traffic can't change another mandate's history. `record_external(event_type, jti, ...)` lets the approval layer add `approval_requested`, `approval_granted`, `approval_denied` and `approval_expired` events, which carry a `ref_decision_id` and go into the same chain.

### 10a. Approval events from the issuer service
The scope-requests change puts the issuer key in its own service, so approvals happen off the gateway. The issuer signs each event as an `audit-event+jwt` with the issuer key (`audit.sign_external_event`, which the issuer can import). It posts the event to `POST /internal/audit-events`, and the gateway verifies it against `trusted_list.json` and calls `record_external`.
- **Idempotent:** the event's own UUID becomes its `decision_id`, which is `UNIQUE`, so an outbox that retries after a lost acknowledgement doesn't duplicate history.
- **Reachable publicly:** the signature is the gate, not the network. Without the issuer key nobody can write approval history.
- **Window:** events are accepted up to a day after `iat` and until `exp`, so retries survive an outage.
- **The minted mandate:** an `approval_granted` event may carry `minted_jti`, so the chain links an approval to the supplementary mandate it produced. Fields added later (`OPTIONAL_FIELDS`) are hashed only when set, so events stored before them still verify, and an older SQLite file gains the column when opened.
- *Alternative:* the issuer writes to the SQLite file directly. Rejected: two writers to one chain, and the file is the gateway's.

### 11. Schema
The schema is a `CREATE ... IF NOT EXISTS` script in `gateway/lib/audit.py`, run when the store opens, with a `schema_version` table for later changes. Arrays are stored as JSON text. Columns beyond the hashed fields:
- `event_type` (default `'decision'`);
- `identity_verified`, `columns_returned`, `result_hash`, `policy_version`, `mandate_hash`, `source_addr`, `http_status`, `ref_decision_id`.

`decision` is nullable, with a check that decision events carry one.

## Risks / Trade-offs

- **The log becomes an attack target on Day 2.** Reads need an issuer-signed audit mandate with clearance 2, and they're recorded. `GET /audit/head` exposes only a hash.
- **Event flooding.** Forged requests write events without any valid mandate, so an attacker can grow the table. At hackathon volume this is acceptable. The rate ceiling planned in the throttle layer bounds it; until then, pre-signature events are size-capped (argument names truncated to 32 keys of 64 characters).
- **The gateway key signs the chain and lives on the gateway.** Detection relies on external anchors, so the plan says to run `cli audit anchor` on a schedule (every minute during Day 2) from a teammate's laptop.
- **The memory store is lost on restart.** The Compose file always sets `GATEWAY_AUDIT_DB`; `/healthcheck/audit` shows `durable: false` if it's missing.
- **SQLite has one writer.** Fine for one gateway container; several replicas would each need their own chain.
- **Whoever has the file can drop the triggers or replace it.** The signed chain and external anchors detect that.
- **Pupil IDs in the log are pseudonymous level-2 data.** The audit server is level 2 and reads are mandated.
- **Summarising adds latency.** Results are at most hundreds of rows and the work is linear, under a millisecond.
- **The manifest mount reverses part of "mount less into the gateway".** It's one read-only public file with no keys, which is acceptable.
- **The catch-all overlaps another workstream.** Agree who lands it first; both need the same reason code.

## Migration Plan

1. Land this change. `docker-compose.yaml` sets `GATEWAY_AUDIT_DB`, so the stack keeps a durable log on the `gateway-audit` volume from the first start.
2. Without the variable (tests, bare `uvicorn`) it uses memory, so behaviour is the old behaviour plus `decision_id`.
3. To start a fresh log in dev: `docker compose down -v` drops the volume.
4. Rollback: revert the commit. The audit tables stay and are ignored.

## Open Questions

- Should the issuer CLI gain a shortcut, `cli issue-audit-reader --principal X`, so people needn't write the audit scope JSON? It's convenience only and can follow later.
- How long to keep events after Day 2? It doesn't matter for the hackathon.
