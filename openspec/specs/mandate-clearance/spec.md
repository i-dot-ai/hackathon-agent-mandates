# mandate-clearance Specification

## Purpose
Lets a mandate state the highest data level its agent is cleared for, and makes the gateway refuse any call to a server whose data level is above it, so sensitivity is checked by the gateway rather than left to scope choices.

## Requirements

### Requirement: Every server has a data level
The gateway SHALL hold a fixed data level for every server it routes to: `schools` 1, `directory` 2, `special` 4, and `pupil-data` 4 (it can return level 4 columns). The level SHALL come from gateway configuration only, never from the request or the mandate. A call naming a server that has no data level MUST be denied with `403` and reason `UNKNOWN_SERVER`.

#### Scenario: Server without a level
- **WHEN** a valid mandate lists `{"server": "census", "tools": ["record"]}` in scope and the agent calls `census.record`, and the gateway has no level for `census`
- **THEN** the gateway returns `403 DENY` with reason `UNKNOWN_SERVER` and detail `census`

### Requirement: The clearance claim is read only from the signed mandate
A mandate MAY carry a top-level claim `clearance` with an integer value from 1 to 4. The gateway SHALL read clearance only from the verified mandate claims. Any `clearance` key in the request arguments MUST be ignored for this decision. A `clearance` claim that is not an integer from 1 to 4 MUST be denied with `403` and reason `CLEARANCE_INVALID`.

#### Scenario: Clearance in the request arguments is ignored
- **WHEN** a mandate with `clearance: 1` calls `directory.roster` with an extra argument `"clearance": 4`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW`

#### Scenario: Malformed clearance
- **WHEN** a mandate with `clearance: "high"` calls `schools.list`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_INVALID`

### Requirement: A mandate may only call servers within its clearance
For a mandate that carries `clearance`, the gateway SHALL deny any call to a server whose data level is greater than the clearance, with `403` and reason `CLEARANCE_TOO_LOW`, and detail naming the server's level and the mandate's clearance. This check SHALL run after the mandate and request-signature checks and after `deny` rules, and before scope and constraint checks.

#### Scenario: Directory allowed at clearance 2
- **WHEN** a mandate with `clearance: 2` and scope `[{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}]` calls `directory.roster(urn="SCH04", year_group=11, academic_year="2023/24", term="SPR")`
- **THEN** the gateway returns `200 ALLOW` with reason `IN_SCOPE`

#### Scenario: Directory refused at clearance 1
- **WHEN** a newsletter mandate with `clearance: 1` and the same scope calls the same tool with the same arguments
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW` and detail `directory is level 2, clearance is 1`

#### Scenario: pupil-data refused below clearance 4
- **WHEN** a mandate with `clearance: 3` and scope `[{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH04"]}}]` calls `pupil-data.search(query="P0011", urn="SCH04")`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW`

#### Scenario: Clearance never widens scope
- **WHEN** a mandate with `clearance: 4` whose scope lists only `schools.list` calls `directory.roster`
- **THEN** the gateway returns `403 DENY` with reason `OUT_OF_SCOPE`

### Requirement: Mandates without clearance keep today's behaviour on pupil-data and are refused on interface servers
For a mandate with no `clearance` claim, the gateway SHALL apply no clearance check to `pupil-data`, so every existing decision there is unchanged. What such a call returns SHALL stop at level 3: the tool grant for it MUST carry level 3, so the server drops special category (level 4) columns such as `Ethnicity` and `InCareAtCurrentSchool` from every row. The same mandate calling `schools`, `directory` or `special` MUST be denied with `403` and reason `CLEARANCE_MISSING`.

#### Scenario: Default mandate unchanged
- **WHEN** the default mandate from `make gateway_issue` (no `clearance`) calls `pupil-data.search(query="P0004", urn="SCH01", limit=1)`
- **THEN** the gateway returns `200 ALLOW` with reason `IN_SCOPE`, as before this change

#### Scenario: Default mandate gets no special category data
- **WHEN** the same call is forwarded to `pupil-data` over HTTP
- **THEN** its tool grant carries level 3, and the rows returned have no `Ethnicity` or `InCareAtCurrentSchool` column
- **AND** the same call under a mandate with `clearance: 4` returns those columns

#### Scenario: Default mandate on a new server
- **WHEN** a mandate with no `clearance` whose scope lists `schools.list` calls `schools.list`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_MISSING`

### Requirement: Every special call is held for approval
Any call to the `special` server that passes every other check SHALL return `202` with decision `STEP_UP` and reason `SENSITIVE_TOOL`, and MUST NOT be forwarded to the server.

#### Scenario: Special record held
- **WHEN** a mandate with `clearance: 4` and scope `[{"server": "special", "tools": ["record"], "constraints": {"urn": ["SCH04"]}}]` calls `special.record(pupil_id="P0011", urn="SCH04")`
- **THEN** the gateway returns `202 STEP_UP` with reason `SENSITIVE_TOOL`, and no data is returned

#### Scenario: Special refused below clearance 4
- **WHEN** a mandate with `clearance: 3` and the same scope makes the same call
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW`

### Requirement: Discovery shows each server's data level
`GET /describe` SHALL include, for every server it lists, that server's data level.

#### Scenario: Levels in describe
- **WHEN** an agent calls `GET /describe`
- **THEN** the response includes `pupil-data` 4, `schools` 1, `directory` 2 and `special` 4
