## MODIFIED Requirements

### Requirement: A mandate may only call servers within its clearance
For a mandate that carries `clearance`, the gateway SHALL deny any call to a server whose data level is greater than the clearance, with `403` and reason `CLEARANCE_TOO_LOW`, and detail naming the server's level and the mandate's clearance, except for `pupil-data`, which is graded: any clearance from 1 to 4 may call it, and its results are stripped to the clearance (`graded-pupil-data`). This check SHALL run after the mandate and request-signature checks and after `deny` rules, and before scope and constraint checks.

#### Scenario: Directory allowed at clearance 2
- **WHEN** a mandate with `clearance: 2` and scope `[{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}]` calls `directory.roster(urn="SCH04", year_group=11, academic_year="2023/24", term="SPR")`
- **THEN** the gateway returns `200 ALLOW` with reason `IN_SCOPE`

#### Scenario: Directory refused at clearance 1
- **WHEN** a newsletter mandate with `clearance: 1` and the same scope calls the same tool with the same arguments
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_TOO_LOW` and detail `directory is level 2, clearance is 1`

#### Scenario: pupil-data refused below clearance 4
(Kept by name; since `add-graded-pupil-data` the call is no longer refused but graded.)
- **WHEN** a mandate with `clearance: 3` and scope `[{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH04"]}}]` calls `pupil-data.search(query="P0011", urn="SCH04")`
- **THEN** the gateway returns `200 ALLOW`, and no returned row has `Ethnicity` or `InCareAtCurrentSchool`

#### Scenario: Clearance never widens scope
- **WHEN** a mandate with `clearance: 4` whose scope lists only `schools.list` calls `directory.roster`
- **THEN** the gateway returns `403 DENY` with reason `OUT_OF_SCOPE`

### Requirement: Mandates without clearance keep today's behaviour on pupil-data and are refused on interface servers
For a mandate with no `clearance` claim, the gateway SHALL apply no clearance check to `pupil-data.search`, `pupil-data.get` and `pupil-data.aggregate`, so those decisions are unchanged. The same mandate calling `pupil-data.pupil`, `roster`, `draft` or `write`, or calling `schools`, `directory` or `special`, MUST be denied with `403` and reason `CLEARANCE_MISSING`.

#### Scenario: Default mandate unchanged
- **WHEN** the default mandate from `make gateway_issue` (no `clearance`) calls `pupil-data.search(query="P0004", urn="SCH01", limit=1)`
- **THEN** the gateway returns `200 ALLOW` with reason `IN_SCOPE`, as before this change

#### Scenario: Default mandate on a new server
- **WHEN** a mandate with no `clearance` whose scope lists `schools.list` calls `schools.list`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_MISSING`

#### Scenario: Person-level tool without clearance
- **WHEN** a mandate with no `clearance` whose scope lists `pupil-data.pupil` calls it
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_MISSING`
