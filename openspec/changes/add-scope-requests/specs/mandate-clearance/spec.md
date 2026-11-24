## MODIFIED Requirements

### Requirement: Every server has a data level
The gateway SHALL hold a fixed data level for every server it routes to or handles itself: `grants` 1 (it returns the calling mandate's own grants and no pupil data), `schools` 1, `directory` 2, `audit` 2 (it returns pupil IDs but no other pupil data), `special` 4, and `pupil-data` 4 (it can return level 4 columns). The level SHALL come from gateway configuration only, never from the request or the mandate. A call naming a server that has no data level MUST be denied with `403` and reason `UNKNOWN_SERVER`.

#### Scenario: Server without a level
- **WHEN** a valid mandate lists `{"server": "census", "tools": ["record"]}` in scope and the agent calls `census.record`, and the gateway has no level for `census`
- **THEN** the gateway returns `403 DENY` with reason `UNKNOWN_SERVER` and detail `census`

#### Scenario: Audit needs clearance 2
- **WHEN** a mandate with `clearance: 1` and scope `{"server": "audit", "tools": ["events"], "constraints": {"principal": ["officer:jsmith"]}}` calls `audit.events(principal="officer:jsmith")`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW` and detail `audit is level 2, clearance is 1`

#### Scenario: Grants needs a clearance claim
- **WHEN** the default mandate from `make gateway_issue` (no `clearance`) calls `grants.self`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_MISSING`

### Requirement: Every special call is held for approval
Any call to the `special` server that passes every other check SHALL return `202` with decision `STEP_UP` and reason `SENSITIVE_TOOL`, and MUST NOT be forwarded to the server. The one exception is a call whose action hash is in the calling mandate's `preapproved` claim, with no earlier allowed call carrying the same action hash. That call SHALL be forwarded once, as the `scope-requests` capability defines.

#### Scenario: Special record held
- **WHEN** a mandate with `clearance: 4` and scope `[{"server": "special", "tools": ["record"], "constraints": {"urn": ["SCH04"]}}]` calls `special.record(pupil_id="P0011", urn="SCH04")`
- **THEN** the gateway returns `202 STEP_UP` with reason `SENSITIVE_TOOL`, and no data is returned

#### Scenario: Special refused below clearance 4
- **WHEN** a mandate with `clearance: 3` and the same scope makes the same call
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW`

#### Scenario: Pre-approved special record released once
- **WHEN** that held call's request was approved by the person, and the agent makes the same call with the minted mandate
- **THEN** the gateway returns `200 ALLOW` and the record, and the same call again with that mandate returns `202 STEP_UP`
