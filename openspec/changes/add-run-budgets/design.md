## Context

- `tools_call` (`gateway/main.py`) decides with `decide_with_context`, forwards an allowed call through `_forward`, summarises the result (`audit.summarise`), writes one audit event, then returns. The summary already lists the pupil IDs in the result.
- `audit.history(jti)` gives, from verified events only: calls per tool, reasons, distinct pupils, refusals in a row, first and last time. It is keyed on one `jti`.
- The audit store is SQLite at `GATEWAY_AUDIT_DB` (or memory). `pupil_ids_returned` is stored as a JSON array.
- The question 3–5 fix caps `limit` at 100 rows per call, so one call can return at most 100 pupils.
- Codex review: a per-key ceiling, "5 refusals → suspend" and a model timeout would all fire on the eval's claim-less mandates and fail question 0. Hence alerts only for those.
- Requirements: `specs/run-budgets/spec.md`.

## Goals / Non-Goals

**Goals:**
- Nothing over a pupil budget leaves the gateway, even inside one call.
- Mandates without the new claims see no new refusals except a ceiling no legitimate run reaches.
- One module the decision model and flow rules can call later.

**Non-Goals:**
- Suspending mandates. The gateway-owned suspension list is a later change; alerts give the person the signal now.
- Smoothing or queueing over-limit calls: they're refused, and the agent retries.

## Decisions

### 1. Where each check runs
```
ceiling (per source, unverified)  ->  decide  ->  ceiling (per agent key)  ->  rate / call budget  ->  forward
  ->  summarise  ->  distinct-pupil budget  ->  record  ->  alerts  ->  respond
```
- **The unverified-source ceiling runs before `decide`**, so a flood of forged requests costs no signature work. It counts only requests that failed verification, so a legitimate agent behind a shared address isn't throttled by its own good calls.
- **The per-key ceiling runs after `decide`**, because the key is known only once the mandate verifies.
- **Rate and call budgets run before forwarding**, so an over-limit call never reaches the data.
- **The pupil budget runs after forwarding and before recording.** The result is in gateway memory, but only the summary is kept, and it never reaches the agent.
- *Alternative:* count pupils by asking the data server first. Rejected: the result itself is the only exact answer to "which pupils".

### 2. Family budget, counted from the audit store
- **Family key:** `parent.jti` if the mandate has one, otherwise its own `jti`. So a supplementary mandate and its parent share a family.
- **Pupils seen:** a new store query, `pupils_for_family(family_jti)`, returns the distinct pupil IDs in the family's verified decision events, from SQLite's `json_each` over `pupil_ids_returned` (or a scan in memory). A new column, `family_jti`, is added to events so the query is indexed. Events record it from the same claims.
- **Concurrency:** one `asyncio.Lock` per family key covers check, record and release, so two parallel calls can't both pass the last unit. The gateway runs as one process, so this is enough.
- **Lifetime call counts** come from the same store query: allowed decision events per family, and per scope entry, identified by an entry index recorded in the event context.
- *Alternative:* in-memory counters only. Rejected: a restart would reset a budget, and a Day 2 restart is likely.

### 3. Per-minute windows in memory
Sliding windows (a deque of timestamps) per `(family, entry)` for `rate.per_minute`, per `agent_id` for the key ceiling, and per source address for failed verifications. They're lost on restart, which only ever loosens them for one minute.

### 4. Limits come from a config file
`gateway/config/limits.yaml` holds `ceilings` (`per_key_per_minute` 300, `unverified_per_source_per_minute` 120, `record_per_second` 1, `retry_after_seconds` 60), `budgets` (`default_distinct_pupils` and `default_calls`, both `null`) and `alerts` (thresholds below). `GATEWAY_LIMITS_CONFIG` names another file, and `GATEWAY_LIMIT_<SECTION>_<KEY>` overrides one value. Unknown keys, wrong types or a missing named file stop the gateway at startup rather than run with guessed limits. `/describe` publishes the values, which carry nothing secret and help agents pace themselves.
- *Alternative:* plain environment variables only. Rejected: the access-config workstream is moving policy into YAML, and a file is reviewable in a PR.

Defaults:
- One eval run is about 32 calls in a few seconds. The Codex review measured that, and noted the ceiling must sit "well above" it.
- A hackathon agent loop rarely exceeds a few calls a second.
- Both settings are environment variables, so the deployment can set them.

### 5. Alerts are audit events
- `audit.py` gains an event type `alert`, added to the SQLite `event_type` check (with the migration in Risks) and to a new `record_alert(jti, principal, reason_code, event_id, pupil_id=None)`. Alerts join the hash chain, so they're tamper-evident, and `audit.events` shows them with no new read path.
- **Dedupe** uses a deterministic event UUID, `uuid5(jti + reason)`, or `uuid5(pupil + hour)` for targeting. That reuses the idempotent `decision_id` from the issuer-event change, so repeats cost nothing.
- **Pupil targeting** is a store query: distinct `jti` per pupil in the last hour, via `json_each`. It's only for pupils in the current result.
- *Alternative:* log lines only. Rejected: the person can't see logs (question 16), and the "Unseen" bonus needs the gateway's own records.

### 6. Responses
- The `429` body is `{"decision": {..., "decision": "DENY", "reason_code": "RATE_LIMITED" | "BUDGET_EXHAUSTED", "detail": ...}}`, with a `decision_id`.
- `Retry-After` is set for `RATE_LIMITED`.
- `detail` names the limit (for example `distinct_pupils 3`), never pupil IDs.

## Risks / Trade-offs

- **[A budget check that fails open would release data]** → Any error counting pupils or reading the store withholds the result with `503 AUDIT_UNAVAILABLE`, the same path as a failed audit write.
- **[Alert thresholds can be gamed by staying under them]** → They're signals, not controls. Mandates that need a hard limit carry `budget`. The thresholds are documented, so they're honest about what they catch.
- **[Poisoning `ALERT_PUPIL_TARGETED`]** → Attackers can make a pupil look targeted, but alerts never refuse, so question 0's P0004 stays allowed.
- **[The schema change on an existing audit file]** → Migrated on open. Optional columns are added. A file whose `event_type` check predates `alert` is rebuilt row by row in a transaction, keeping every hash and signature, so `audit verify` still passes.
- **[`json_each` scans grow with the audit log]** → They're indexed by `family_jti` and the hour. The volume is small for a hackathon.
- **[Child mandates from other issuers]** → The family key is trusted only from a verified mandate's `parent.jti`; no cross-issuer chains.

## Migration Plan

1. Land after `add-audit-trail` (on `ihor`).
2. Existing audit files migrate on open; nothing to recreate.
3. Rollback: set the ceilings to 0 (off) and revert. Mandates without `budget` were never refused, so nothing else changes.
