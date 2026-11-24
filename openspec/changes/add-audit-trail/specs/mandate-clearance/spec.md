## MODIFIED Requirements

### Requirement: Every server has a data level
The gateway SHALL hold a fixed data level for every server it routes to: `schools` 1, `directory` 2, `audit` 2 (it returns pupil IDs but no other pupil data), `special` 4, and `pupil-data` 4 (it can return level 4 columns). The level SHALL come from gateway configuration only, never from the request or the mandate. A call naming a server that has no data level MUST be denied with `403` and reason `UNKNOWN_SERVER`.

#### Scenario: Server without a level
- **WHEN** a valid mandate lists `{"server": "census", "tools": ["record"]}` in scope and the agent calls `census.record`, and the gateway has no level for `census`
- **THEN** the gateway returns `403 DENY` with reason `UNKNOWN_SERVER` and detail `census`

#### Scenario: Audit needs clearance 2
- **WHEN** a mandate with `clearance: 1` and scope `{"server": "audit", "tools": ["events"], "constraints": {"principal": ["officer:jsmith"]}}` calls `audit.events(principal="officer:jsmith")`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW` and detail `audit is level 2, clearance is 1`
