# Audit trail: questions 14 and 16

OpenSpec change `add-audit-trail`. The gateway writes one signed, hash-chained event for every `POST /tools/call`,
refusals included, and the person who granted a mandate can read what was done with it and what it received.

- **Every response** carries `decision.decision_id`, the ID of its audit event.
- **Events hold identifiers and levels, never values:** who (`jti`, `agent_id`, principal, source address), what
  (server, tool, argument *names*, plus the scope's `urn` / `pupil_id`), how it was decided, and for allowed calls
  what came back (row count, pupil IDs, column names, highest PII level, a hash of the result).
- **Refusals before the mandate verifies** (forged, expired, revoked, garbage) are recorded with the `jti` and `iss`
  the mandate *claims*, marked `identity_verified: false`.
- **Storage:** a SQLite file at `GATEWAY_AUDIT_DB`. `docker-compose.yaml` sets it to
  `/app/gateway/audit/audit.sqlite` on the named volume `gateway-audit`, so the log outlives the container and sits
  outside `gateway/state`. Without the variable (tests, a bare `uvicorn`) events are kept in memory and lost on restart.
  `GET /healthcheck/audit` says which: `{"store": "sqlite", "durable": true}`.
- **Append-only:** SQLite triggers refuse `UPDATE` and `DELETE` on `audit_events` for every connection. Someone with
  the file can still drop the triggers or replace the file; the hash chain and saved anchors are what catch that.
- **If an event can't be written**, an allowed call's result is withheld: `503` with reason `AUDIT_UNAVAILABLE`.
- **Decisions don't change.** `make eval_run` gives the same 27/32 with the SQLite store and the memory store.

## Reading it is a mandated call

The log is served by an `audit` server that the gateway answers itself, through the same `POST /tools/call`. Its data
level is 2, so a reader needs `clearance` of at least 2, and its scope constraints say whose events it may read. An
agent's operational mandate has neither, so it can't read the log, and nor can whoever steals its key.

## The mandate

An Ashfield job, issued after `make hack`:

```bash
uv run python -m gateway.cli keygen -o agent2.pem
uv run python -m gateway.cli issue --agent-key agent2.pem -o job.jwt \
  --principal officer:jsmith --purpose "Census lookups at Ashfield"
# wrote mandate (status idx 12) to job.jwt
```

And a reader for it, held by the person, with its own key:

```bash
uv run python -m gateway.cli keygen -o reader.pem
uv run python -m gateway.cli issue --agent-key reader.pem -o reader.jwt --principal officer:jsmith \
  --claims '{"clearance": 2}' --purpose "Audit reader for one job" \
  --scope '[{"server": "audit", "tools": ["events", "saw"], "constraints": {"jti": ["<the job jti>"]}}]'
```

To read every mandate one person granted, constrain `principal` instead:
`"constraints": {"principal": ["officer:jsmith"]}`.

## Using the job, then revoking it

```bash
call() { uv run python -m gateway.cli call --mandate job.jwt --agent-key agent2.pem "$@"; }
call --tool search --args '{"query": "P0004", "urn": "SCH01", "limit": 2}'   # 200 ALLOW IN_SCOPE
call --tool search --args '{"query": "P0022", "urn": "SCH01", "limit": 2}'   # 200 ALLOW IN_SCOPE
call --tool search --args '{"query": "SPR", "urn": "SCH02"}'                 # 403 DENY CONSTRAINT_VIOLATED
call --tool get --args '{"path": "synthetic/synthetic_manifest.json"}'       # 200 ALLOW IN_SCOPE
uv run python -m gateway.cli revoke --idx 12
call --tool search --args '{"query": "P0004", "urn": "SCH01"}'               # 403 DENY REVOKED
```

## What it saw (question 14)

```bash
uv run python -m gateway.cli audit saw --mandate reader.jwt --agent-key reader.pem --jti <the job jti>
```

```json
{
  "pupil_ids": ["P0004", "P0022"],
  "columns": ["AcademicYear", "AgeAtStartOfAcademicYear", "CensusTerm", "EnrolStatus", "Gender", "Psuedo ID", "URN"],
  "max_pii_level": 2,
  "schools": ["SCH01"],
  "calls": {"allowed": 3, "held": 0, "refused": 1},
  "revoked": true,
  "summary": "Before it was revoked, this access returned basic personal data such as names for 2 pupils at 1 school."
}
```

The manifest read added no columns and no pupils: a JSON document isn't a table, so it counts as level 1. The job
mandate has no `clearance`, so its census rows are stripped to the claim-less level (2 by default, see
`add-graded-pupil-data`) and came back without `Ethnicity`, `InCareAtCurrentSchool`, `FSMeligible` or `Language`.
With a higher `clearance` those columns would be in the list.

## Who used it (question 16)

```bash
uv run python -m gateway.cli audit events --mandate reader.jwt --agent-key reader.pem --jti <the job jti>
```

Each event has `decision_id`, time, source address, `agent_id`, tool, argument names, decision and reason. From the
run above, shortened:

```text
16:07:38  127.0.0.1  YZHwEIS7  search  ALLOW  IN_SCOPE
16:07:39  127.0.0.1  YZHwEIS7  search  ALLOW  IN_SCOPE
16:07:39  127.0.0.1  YZHwEIS7  search  DENY   CONSTRAINT_VIOLATED
16:07:39  127.0.0.1  YZHwEIS7  get     ALLOW  IN_SCOPE
claimed: 1   (the call after revocation)
```

A different `agent_id` or a new source address on a mandate is the sign someone else is using it.

## A request it denies

The same reader asking about a mandate it wasn't given:

```bash
uv run python -m gateway.cli audit saw --mandate reader.jwt --agent-key reader.pem --jti urn:uuid:someone-else
# 403 DENY CONSTRAINT_VIOLATED
```

The job's own mandate asking for its own log gets `403 DENY CLEARANCE_MISSING`.

## Checking nobody rewrote it

```bash
uv run python -m gateway.cli audit anchor --url http://localhost:8082          # run from a laptop the operator doesn't control
docker compose cp gateway:/app/gateway/audit/audit.sqlite ./audit.sqlite      # a copy of the log to check
docker compose cp gateway:/app/gateway/audit/audit.sqlite-wal ./audit.sqlite-wal  # recent writes, if present
uv run python -m gateway.cli audit verify --db audit.sqlite --anchors audit_anchors.jsonl
# chain intact: <n> events, 1 anchors checked
```

A quick check in place, without anchors:

```bash
docker compose exec gateway uv run --no-sync python -m gateway.cli audit verify \
  --db /app/gateway/audit/audit.sqlite --gateway-pub /app/gateway/state/gateway.pub
```

`audit verify` recomputes every event's hash, checks each signature against `gateway.pub` and each `prev_hash`
link, and checks that every saved head is still in the chain. An edited event is reported at its sequence number. A
chain rebuilt and re-signed with the gateway key still fails at the first saved anchor. During Day 2, run
`audit anchor` every minute.

## Still unresolved

- **A revoked mandate's later calls show up as claimed, not verified.** The revocation check runs before the
  gateway trusts the mandate, so `audit.saw` counts them under `claimed` rather than as refusals.
- **The gateway key signs the chain and lives on the gateway.** Tampering is only caught against heads saved
  elsewhere.
- **Forged requests still write events.** That gives an attacker a way to grow the file until the throttle layer
  caps it.
- **One gateway process per file.** SQLite allows one writer at a time, which suits one container. Several replicas
  would each need their own chain, or a shared database.
