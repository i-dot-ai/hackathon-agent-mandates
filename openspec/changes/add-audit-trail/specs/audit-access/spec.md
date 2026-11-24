## Purpose

Lets the people who granted access see what was done with it, and only that, and gives other gateway layers a read-only view of a mandate's history, without opening the audit trail to the agents being audited.

## ADDED Requirements

### Requirement: Reading the audit trail is a mandated call
Audit reads SHALL go through `POST /tools/call` with `server` set to `audit`, using the same request shape, mandate verification and request-signature checks as any other call. The gateway SHALL answer `audit` calls itself and never forward them to an MCP server. The `audit` server SHALL have data level 2, so a reading mandate needs `clearance` of at least 2. Each audit read SHALL itself produce an audit event.

#### Scenario: Operational mandate can't read the log
- **WHEN** the default Ashfield mandate, which has no `audit` scope entry, calls `audit.events(jti="<its own jti>")`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_MISSING` or `OUT_OF_SCOPE`, and returns no events

#### Scenario: Read is itself recorded
- **WHEN** an audit-reader mandate calls `audit.events` and is allowed
- **THEN** an audit event for that read exists with server `audit`, tool `events` and decision `ALLOW`

### Requirement: A reader sees only events within their audit scope
An audit-reader mandate SHALL limit what it can read through its scope constraints, written in the same form as any other scope: `{"server": "audit", "tools": [...], "constraints": {"principal": [...]}}` or `{"constraints": {"jti": [...]}}`. A call SHALL name the `principal` or `jti` it reads, and the gateway's existing constraint check SHALL refuse a value outside the mandate's list. The result SHALL contain only events whose verified principal or verified `jti` matches, plus events that only claim a matching `jti`, each marked as claimed and not verified.

#### Scenario: Person reads their own log
- **WHEN** an issuer signs an audit-reader mandate with `clearance: 2` and scope `{"server": "audit", "tools": ["events"], "constraints": {"principal": ["officer:jsmith"]}}`, and its holder calls `audit.events(principal="officer:jsmith")`
- **THEN** the gateway returns `200 ALLOW` with the events of mandates delegated by `officer:jsmith`, and no others

#### Scenario: Person asks for someone else's log
- **WHEN** the same holder calls `audit.events(principal="officer:priya")`
- **THEN** the gateway returns `403 DENY` with reason `CONSTRAINT_VIOLATED` and returns no events

#### Scenario: Forged calls show up as claimed
- **WHEN** someone sent mandates with an edited payload claiming one of `officer:jsmith`'s `jti` values, and `officer:jsmith` reads that `jti`'s events
- **THEN** those refusals appear in the result marked as claimed, not verified, separate from the verified events

### Requirement: The request log shows who used the access
`audit.events` SHALL return, for each matching event in time order: `decision_id`, time, source address, agent key ID (`agent_id`), server, tool, argument names, decision, reason code and whether the identity was verified. It SHALL accept an optional time range and a maximum of 500 events per call.

#### Scenario: Key used from a new address
- **WHEN** a mandate's agent key was used from two source addresses during its lifetime
- **THEN** `audit.events` for that `jti` lists events from both addresses with the same `agent_id`

### Requirement: The person can see what a mandate received
`audit.saw` SHALL take a `jti` and return a summary of everything that mandate's allowed calls returned: the distinct pupil IDs, the column names, the highest PII level, the number of allowed, held and refused calls, the time of the first and last call, whether the mandate is currently revoked, and one sentence in plain words. It SHALL work for revoked and expired mandates.

#### Scenario: What a revoked mandate saw
- **WHEN** a mandate made 3 allowed searches at Ashfield returning pupils `P0004` and `P0007` with census columns, was then revoked, and its reader calls `audit.saw(jti=...)`
- **THEN** the result lists pupils `P0004` and `P0007`, highest PII level 4, 3 allowed calls, revoked `true`, and a sentence like "Before it was revoked, this access returned census records, including special category data, for 2 pupils at 1 school."

#### Scenario: Mandate never used
- **WHEN** the reader calls `audit.saw` for a `jti` with no events
- **THEN** the result has no pupils and zero calls, and says the access was never used

### Requirement: Other gateway layers can read a mandate's history
The gateway SHALL give its own layers (flow enforcement, budgets, approvals, the decision model) a read-only history of a mandate, built from verified events only: calls per tool, decisions per reason code, distinct pupils returned, highest PII level returned, refusals in a row, and the times of the first and last call. It SHALL also accept events that the gateway's own layers record outside tool calls, such as approval requested, granted, denied or expired, into the same chain.

#### Scenario: Flow rule asks what has run
- **WHEN** a mandate has made one allowed `directory.roster` call, and a flow rule reads its history before a `pupil-data.draft` call
- **THEN** the history shows one allowed `roster` call and no `draft` calls

#### Scenario: Approval event joins the chain
- **WHEN** the approval layer records that a person granted approval for a held call
- **THEN** that event is in the hash chain after the held call's event, and appears in `audit.events` for that mandate

### Requirement: The issuer service can add signed approval events
The gateway SHALL accept approval events from the issuer service at `POST /internal/audit-events`, as a JWT with `typ` `audit-event+jwt` signed by an issuer key on the gateway's trusted list, carrying the event's own UUID (`jti`), `iat`, `exp`, the event type (one of the four approval events), the mandate `jti`, server, tool, the held or requested call's `decision_id`, a reason code, and optionally the principal, the agent ID and, for `approval_granted`, the `jti` of the mandate the approval minted (`minted_jti`, a string). `audit.events` SHALL show `minted_jti` on events that carry it. The gateway SHALL record each accepted event in the same hash chain as decision events, with the event's UUID as its `decision_id`. The same event sent again SHALL be acknowledged without a second record. Any other input MUST be refused and recorded nowhere: not a JWT or the wrong `typ` with `400 EVENT_INVALID`, an issuer not on the trusted list with `403 ISSUER_NOT_ACCREDITED`, a bad signature with `403 SIG_INVALID`, expired or more than a day old with `403 EVENT_EXPIRED`, and an unknown event type or a missing field with `400 EVENT_REJECTED`.

#### Scenario: A person's approval reaches the chain
- **WHEN** the issuer posts an `approval_granted` event signed with its issuer key, for a mandate delegated by `officer:jsmith`
- **THEN** the gateway returns `201` with the event's `decision_id`, and `audit.events(principal="officer:jsmith")` lists the approval

#### Scenario: The approval names the mandate it minted
- **WHEN** the issuer posts an `approval_granted` event with `minted_jti` `urn:uuid:minted-1`
- **THEN** the stored event and its `audit.events` entry carry `minted_jti` `urn:uuid:minted-1`, and a non-string `minted_jti` is refused with `400 EVENT_REJECTED`

#### Scenario: The issuer retries
- **WHEN** the issuer posts the same signed event a second time
- **THEN** the gateway returns `200` with `duplicate: true` and the same `decision_id`, and the chain holds the event once

#### Scenario: Someone else writes approval history
- **WHEN** a caller posts an approval event signed with a key that isn't on the trusted list
- **THEN** the gateway returns `403 SIG_INVALID` or `403 ISSUER_NOT_ACCREDITED` and records nothing
