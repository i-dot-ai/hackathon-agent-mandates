## 1. Prerequisites

- [x] 1.1 Base `feature/audit-trail` on main with no dependency on the Postgres scaffold; verify `make test` passes on the rebased branch
- [ ] 1.2 Agree the `MANDATE_MALFORMED` catch-all and the `policy_version` field with the access-config workstream; verify by a note in this change's design (or their PR) naming who lands the catch-all _(Not done: needs the access-config workstream. `MANDATE_MALFORMED` is implemented here.)_

## 2. Decision context and catch-all

- [x] 2.1 Add `AuditContext` and `Gateway.decide_with_context` in `gateway/lib/gateway_verify.py` (verified claims, or claimed `jti`/`iss` read without verification, plus scope `urn`/`pupil_id`), with `decide` as a wrapper; verify existing gateway tests pass unchanged
- [x] 2.2 Turn any non-`Reject` exception in `decide_with_context` into `DENY MANDATE_MALFORMED`; verify with tests for `"garbage"` and a JWT payload with no `iss`, both returning 403 instead of 500
- [x] 2.3 Add `audit` at level 2 to `SERVER_LEVELS` in `gateway/lib/interfaces.py`; verify a test that a `clearance: 1` mandate gets `CLEARANCE_TOO_LOW` on `audit.events` and a mandate without clearance gets `CLEARANCE_MISSING`

## 3. Audit core

- [x] 3.1 Create `gateway/lib/audit.py` with the event model, canonical hashing (sorted arrays, ISO UTC timestamps) and Ed25519 signing with `gateway_key.pem`; verify unit tests that the same event hashes identically twice and that a changed field changes the hash
- [x] 3.2 Implement `summarise(server, tool, result)` (rows, pupil IDs under `Psuedo ID`/`pupil_id`, columns, max PII level from the manifest with level 4 for unlisted columns, result hash); verify unit tests on a census search result, the schools file (level 1, no pupils) and a `draft` result
- [x] 3.3 Implement `MemoryStore` (append under a lock, head, query by principal/jti/time with a 500 cap, history); verify unit tests for chain linkage, first-event zero hash and the query cap
- [x] 3.4 Write the SQLite schema (all event columns, nullable `decision` with a check for decision events, append-only triggers, `schema_version`), created on open; verify a test that `UPDATE` and `DELETE` are refused
- [x] 3.5 Implement `SqliteStore` (worker thread, lock, `BEGIN IMMEDIATE` append, WAL) with the same query and history methods; verify tests that 50 concurrent appends make one unbroken chain and that events survive reopening the file
- [x] 3.6 Implement `history(jti)` (calls per tool, reason counts, distinct pupils, max PII level, refusals in a row, first and last time; verified events only) and `record_external` for approval events; verify unit tests including a forged event that doesn't change another mandate's history

## 4. Gateway wiring

- [x] 4.1 In `gateway/main.py` `tools_call`, use `decide_with_context`, add `decision_id` to the `decision` object, record one event per call with source address (trusted-proxy rule) and HTTP status; verify tests that ALLOW, DENY, STEP_UP and a pre-signature refusal each produce exactly one event whose `decision_id` matches the response
- [x] 4.2 Withhold results and return `503 AUDIT_UNAVAILABLE` when an allowed call's event can't be written, and still return refusals; verify with a store that raises on append
- [x] 4.3 Dispatch `server == "audit"` to an in-process handler for `events` and `saw` after the normal checks, never to an MCP client; verify tests for an own-principal read (200), another principal (403 `CONSTRAINT_VIOLATED`), the default mandate (403), claimed events listed separately, and the read itself being recorded
- [x] 4.4 Implement `audit.saw` output with the plain-words sentence and revoked status from the status list; verify tests for a used-then-revoked mandate and a never-used one
- [x] 4.5 Add `GET /audit/head`; verify a test that it returns only `seq`, `event_hash` and `sig`
- [x] 4.6 Mount the manifest read-only into the gateway, set `GATEWAY_MANIFEST_PATH`, add the `gateway-audit` volume and `GATEWAY_AUDIT_DB` in `docker-compose.yaml`, and create `/app/gateway/audit` in the image; verify after `docker compose up -d --build gateway` that `/healthcheck/audit` reports sqlite and a live census search's event has `max_pii_level` 4

## 5. CLI

- [x] 5.1 Add `cli audit anchor --url` (append head to a local file) and `cli audit verify --db --anchors` (hashes, signatures, links, anchors); verify a test that an edited `reason_code` and a replaced chain are each reported
- [x] 5.2 Add `cli audit saw --jti` and `cli audit events --principal|--jti`, which sign an `audit` call with a reader mandate and key; verify against the live stack that they print the same data as the tool calls

## 6. Docs and check-in

- [ ] 6.1 Write `docs/audit-trail.md` laid out like `questions/02-worked-example.md`: an audit-reader mandate, a request it allows, one it denies, the `audit.saw` output after a revoke, and what's unresolved; verify each command in it runs on a fresh `make hack` _(Written from a live run against this branch's gateway with the main checkout's state; not re-run from a fresh `make hack`.)_
- [x] 6.2 Add `audit` events to `gateway/lib/mandate.schema.json` docs (reader scope form); verify the file still parses as JSON

## 7. Final checks

- [x] 7.1 `make eval_run` gives the same decisions and reason codes as before (question 0 at 12/12), with the memory store and with the SQLite store
- [x] 7.2 `make test` passes, including the new audit tests
- [x] 7.3 `make lint` passes
- [x] 7.4 `docker compose up -d --build gateway`, then one allowed, one refused and one forged call show up via `cli audit events`, and `cli audit verify` on a copy of the SQLite file reports the chain intact

## 8. For the scope-requests change

- [x] 8.1 Score results of `audit` and `grants` at their server's level with no columns; verify a unit test that a `grants.status`-shaped result scores 1 and an audit read's event records level 2
- [x] 8.2 Read the parent from `parent.jti` (falling back to `parent_jti`); verify a test that a mandate with a `parent` claim records it on its events
- [x] 8.3 Add `sign_external_event`, `verify_external_event` and `POST /internal/audit-events` (idempotent by event UUID); verify tests for a recorded and readable approval, a retried event recorded once, and refusals for garbage, the wrong `typ`, an untrusted issuer, a bad signature, an expired event, an unknown type and a non-UUID id
- [x] 8.4 Add an optional `minted_jti` to approval events (`sign_external_event`, `record_external`, the SQLite column added on open, `audit.events`), hashed only when set so existing chains still verify; verify tests for an old file gaining the column and verifying, and a signed approval carrying it
