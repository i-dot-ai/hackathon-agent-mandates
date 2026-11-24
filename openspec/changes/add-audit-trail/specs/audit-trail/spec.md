## Purpose

Makes every gateway decision leave a tamper-evident record of who asked for what, how it was decided and what came back, so access granted to an agent can be accounted for after the fact.

## ADDED Requirements

### Requirement: Every tool call produces exactly one audit event
The gateway SHALL write exactly one audit event for every `POST /tools/call` it answers, whatever the decision (`ALLOW`, `STEP_UP` or `DENY`) and whichever check decided it, including refusals at the mandate-type, issuer, signature, date, revocation and request-signature checks. An event SHALL record: `decision_id`, time, server, tool, the names of the request arguments, a hash of the request arguments, decision, reason code, policy version, the mandate hash, the source address, and the HTTP status returned.

#### Scenario: Allowed call is recorded
- **WHEN** the default Ashfield mandate calls `pupil-data.search(query="P0004", urn="SCH01", limit=1)` and the gateway returns `200 ALLOW`
- **THEN** exactly one audit event exists for that call, with decision `ALLOW`, reason `IN_SCOPE`, server `pupil-data`, tool `search` and argument names `limit, query, urn`

#### Scenario: Refusal is recorded
- **WHEN** the same mandate calls `pupil-data.search(query="SPR", urn="SCH02")` and the gateway returns `403 DENY`
- **THEN** exactly one audit event exists for that call, with decision `DENY` and reason `CONSTRAINT_VIOLATED`

#### Scenario: Held call is recorded
- **WHEN** a mandate that allows `pupil-data.write` calls it and the gateway returns `202 STEP_UP`
- **THEN** exactly one audit event exists for that call, with decision `STEP_UP` and reason `SENSITIVE_TOOL`

### Requirement: Argument values are not stored
An audit event MUST NOT contain the values of request arguments, the decision detail text, or any data value from a result. The only argument values it MAY store are the school URN and pupil ID values that the mandate's scope constrains, because they identify whose data the call concerned.

#### Scenario: Free text is not stored
- **WHEN** an agent calls `pupil-data.search(query="Zara Okafor", urn="SCH01")`
- **THEN** the audit event contains the argument names `query` and `urn`, the URN `SCH01` and an argument hash, and does not contain the text `Zara Okafor`

### Requirement: Identity on an event is marked verified or claimed
When the mandate and the request signature both verify, the event SHALL record the mandate's `jti`, `iss`, `agent_id`, delegator principal and parent `jti` (if any, read from the mandate's `parent.jti`, or a top-level `parent_jti`) as verified. When a refusal happens before that, the event SHALL record whatever `jti` and `iss` the mandate claims, if they can be parsed, and MUST mark them as claimed and not verified, with no `agent_id` or principal.

#### Scenario: Forged mandate refusal
- **WHEN** a request carries a mandate whose payload was edited after signing, claiming `jti` `urn:uuid:1111`, and the gateway returns `403 DENY` with reason `SIG_INVALID`
- **THEN** the audit event records `jti` `urn:uuid:1111` marked as claimed, not verified, and records no `agent_id` or principal

#### Scenario: Unparseable mandate
- **WHEN** a request carries `"mandate": "garbage"` and the gateway refuses it
- **THEN** an audit event is still written, with no `jti`, no `iss`, and the refusal's reason code

### Requirement: Every response carries a decision ID
Every `POST /tools/call` response SHALL include a `decision_id` field inside the existing `decision` object, equal to the `decision_id` of the call's audit event. The request body and every existing response field and status code SHALL be unchanged.

#### Scenario: Decision ID on a refusal
- **WHEN** any call is refused with `403`
- **THEN** the response body's `decision.decision_id` is a UUID, and an audit event with that `decision_id` exists

### Requirement: An allowed call records what came back
For an `ALLOW` decision whose result reached the agent, the event SHALL record: the number of rows returned, the distinct pupil IDs that appear in the result, the column names that appear in the result, the highest PII level among those columns according to the data manifest's classification (a column the manifest does not list counts as level 4), and a hash of the result exactly as returned. A result from a server the gateway answers itself (`audit`, `grants`) SHALL record no columns and SHALL be scored at that server's data level, because it is gateway metadata, not table rows.

#### Scenario: A census search
- **WHEN** the default Ashfield mandate calls `pupil-data.search(query="P0004", urn="SCH01")` and the result has N census rows, all for `P0004`
- **THEN** the event records N rows, pupil IDs `[P0004]`, the census column names, highest PII level 4, and a result hash

#### Scenario: A gateway server's result
- **WHEN** an allowed `grants.status` call returns `{"request_id": "sr_1", "status": "pending", "summary": "..."}`
- **THEN** the event records no columns and highest PII level 1, the `grants` server's level, not 4

#### Scenario: A supplementary mandate's parent
- **WHEN** a mandate carrying `"parent": {"jti": "urn:uuid:parent-1", ...}` makes an allowed call
- **THEN** the event records parent `jti` `urn:uuid:parent-1`

#### Scenario: A public file
- **WHEN** the default mandate calls `pupil-data.get(path="synthetic/synthetic_schools.csv")`
- **THEN** the event records 12 rows, no pupil IDs and highest PII level 1

### Requirement: Events form a signed hash chain
Each event SHALL carry the hash of the event before it and its own hash, computed over the event's canonical content including that previous hash, and the gateway's signature over its own hash. The first event SHALL use a previous hash of `sha256:` followed by 64 zeros. Recorded events MUST NOT be updated or deleted through the gateway, and the chain MUST NOT fork: each event can be followed by exactly one next event.

#### Scenario: Chain verifies
- **WHEN** a verifier recomputes every event's hash in order and checks each signature with the gateway's public key
- **THEN** every hash and signature matches and each event's previous hash equals the hash of the event before it

#### Scenario: Edited event is detected
- **WHEN** someone with access to the audit file changes the `reason_code` of one stored event, bypassing the gateway
- **THEN** the verifier reports the first event whose hash no longer matches

### Requirement: The chain head can be anchored outside the gateway
`GET /audit/head` SHALL return, without authentication, the sequence number and hash of the latest event and the gateway's signature over them, and nothing else. A verifier SHALL be able to check a stored chain against heads saved earlier outside the gateway, and SHALL report a chain that no longer contains a saved head as rewritten.

#### Scenario: Head is public and contains no data
- **WHEN** anyone calls `GET /audit/head`
- **THEN** the response contains only a sequence number, an event hash and a signature

#### Scenario: Rewritten chain is detected
- **WHEN** a head with sequence 40 was saved outside the gateway, and the stored chain is later replaced so that event 40 has a different hash
- **THEN** the verifier reports the chain as rewritten at or before event 40

### Requirement: Audit failure withholds results
When an audit store is configured and the gateway cannot write a call's event, the gateway MUST NOT return any tool result for that call. It SHALL return `503` with reason `AUDIT_UNAVAILABLE` and a `decision_id`. A call the checks refused SHALL still return its refusal.

#### Scenario: Store down on an allowed call
- **WHEN** the audit store can't be written (for example the file's volume is full or read-only) and the default mandate makes a call that would be `200 ALLOW`
- **THEN** the gateway returns `503` with reason `AUDIT_UNAVAILABLE` and no `result` field

#### Scenario: Store down on a refused call
- **WHEN** the audit store can't be written and a call is refused with `CONSTRAINT_VIOLATED`
- **THEN** the gateway returns `403` with reason `CONSTRAINT_VIOLATED`

### Requirement: Recording never changes a decision
Writing audit events SHALL NOT change any `ALLOW`, `STEP_UP` or `DENY` decision or its reason code, for mandates with or without new claims. With no audit store configured, the gateway SHALL keep events in memory, so the base stack and the eval behave as before apart from the added `decision_id`.

#### Scenario: Eval unchanged
- **WHEN** `make eval_run` runs against a gateway with this change, with the SQLite store or with no store configured
- **THEN** every case gets the same decision and reason code as before the change, and question 0 passes 12/12

### Requirement: The audit trail is kept in a file that outlives the gateway
When `GATEWAY_AUDIT_DB` names a file, the gateway SHALL store events in that SQLite file, creating it on first use, and SHALL refuse `UPDATE` and `DELETE` of stored events on every connection to it. `GET /healthcheck/audit` SHALL report which store is in use and whether it is durable, without paths or event data. The deployed stack SHALL set `GATEWAY_AUDIT_DB` to a file on a volume separate from the gateway's key folder.

#### Scenario: Events survive a restart
- **WHEN** the gateway records events with `GATEWAY_AUDIT_DB` set, then restarts with the same file
- **THEN** the earlier events are still there, and the next event's previous hash is the last stored event's hash

#### Scenario: Stored events can't be changed through SQL
- **WHEN** any connection to the file runs `UPDATE audit_events ...` or `DELETE FROM audit_events`
- **THEN** SQLite refuses it with an append-only error and the events are unchanged

#### Scenario: Health shows the store
- **WHEN** anyone calls `GET /healthcheck/audit` on a gateway with `GATEWAY_AUDIT_DB` set
- **THEN** the response is `{"store": "sqlite", "durable": true}`
