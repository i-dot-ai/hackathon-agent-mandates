## Purpose

Makes a mandate's clearance decide which `pupil-data` columns an agent receives, and makes special category data something a person approves call by call, so default permissions get basic data only.

## ADDED Requirements

### Requirement: pupil-data results are stripped to the clearance
For a mandate with `clearance` from 1 to 3, a `pupil-data` call allowed by scope SHALL return no column whose data level, by the manifest's classification, is above the clearance. The tool grant SHALL carry the clearance as its level, so the MCP server removes those columns, and the gateway SHALL remove them again before releasing the result. A column the manifest doesn't list counts as level 4.

#### Scenario: Clearance 2 gets names, not sensitive fields
- **WHEN** a mandate with `clearance: 2` and scope `[{"server": "pupil-data", "tools": ["pupil"], "constraints": {"urn": ["SCH02"]}}]` calls `pupil-data.pupil(pupil_id="P0050", urn="SCH02")`
- **THEN** the gateway returns `200 ALLOW` with the record's `DisplayName`, `Gender` and deprivation fields, and without `Ethnicity`, `InCareAtCurrentSchool`, `FSMeligible` or `Language`

#### Scenario: Clearance 3 adds free school meals
- **WHEN** the same call is made with `clearance: 3`
- **THEN** the record includes `FSMeligible` and `Language`, and not `Ethnicity` or `InCareAtCurrentSchool`

### Requirement: Special category reads are held for approval
For a mandate with `clearance: 4`, a `pupil-data` call that returns level-4 columns (`search`, `pupil`, or `get` of the census file) SHALL be held with `202 STEP_UP` and reason `SPECIAL_CATEGORY`, unless the mandate pre-approves that exact call. A pre-approved call SHALL be allowed once with reason `PREAPPROVED`.

#### Scenario: Ethnicity needs a person
- **WHEN** a mandate with `clearance: 4` and the scope above calls `pupil-data.pupil(pupil_id="P0050", urn="SCH02")`
- **THEN** the gateway returns `202 STEP_UP` with reason `SPECIAL_CATEGORY` and no record

#### Scenario: Approved once
- **WHEN** a person approved that held call through `grants.request`, and the agent retries it with the minted mandate
- **THEN** the record is returned once with reason `PREAPPROVED`, and a second identical call is held again

### Requirement: Person-level tools need a clearance claim
A mandate with no `clearance` claim calling `pupil-data.pupil`, `pupil-data.roster`, `pupil-data.draft` or `pupil-data.write` MUST be refused with `403 CLEARANCE_MISSING`, after `deny` rules. Its `search`, `get` and `aggregate` calls SHALL be decided as before; what they release is set by the next requirement.

#### Scenario: The P0050 call without clearance
- **WHEN** a mandate with no `clearance` and scope allowing `pupil` at `SCH02` calls `pupil-data.pupil(pupil_id="P0050", urn="SCH02")`
- **THEN** the gateway returns `403 DENY` with reason `CLEARANCE_MISSING` and no record

#### Scenario: The eval is unchanged
- **WHEN** `make eval_run` runs
- **THEN** it passes 32/32 and question 0 12/12

### Requirement: No clearance means basic data
A `pupil-data` result for a mandate with no `clearance` claim SHALL be stripped at the gateway to the claim-less level: `GATEWAY_CLAIMLESS_LEVEL` when it is an integer from 1 to 4, else 2. A missing or invalid setting SHALL fall back to 2, never to 4. Safe counts SHALL NOT be stripped, because they release only rounded aggregates. The audit event SHALL record the stripped result.

#### Scenario: Claim-less search of one pupil
- **WHEN** a mandate with no `clearance` and scope allowing `search` at `SCH02` calls `pupil-data.search(query="P0050", urn="SCH02")`
- **THEN** the gateway returns `200 ALLOW` with P0050's rows, none containing `Ethnicity`, `InCareAtCurrentSchool`, `FSMeligible` or `Language`, and the audit event's `max_pii_level` is 2

#### Scenario: The server strips the same columns
- **WHEN** the same claim-less `search` is forwarded to `pupil-data` over HTTP
- **THEN** its tool grant carries the claim-less level, so the MCP server drops the same columns before the gateway sees the result
- **AND** a claim-less `aggregate` grant keeps the server's level, so the per-pupil breakdown behind safe counts keeps its group columns

#### Scenario: Claim-less free school meal counts
- **WHEN** the eval's counts mandate (no `clearance`) asks for free school meal numbers by school
- **THEN** the counts are released as before

### Requirement: A search can't select pupils by a stripped value
When a `pupil-data.search` result is stripped to a level below 4, a row SHALL be returned only if the search query matches, case-insensitively, one of the columns left after stripping. The gateway SHALL apply this before release, and the MCP server SHALL apply it again under the tool grant's level, so neither relies on the other. Otherwise the rows chosen by matching the whole row would reveal the stripped value.

#### Scenario: Searching for an ethnicity without the clearance for it
- **WHEN** a mandate with no clearance, or with clearance 2, calls `pupil-data.search(query="ASIA", urn="SCH02", limit=100)`
- **THEN** the gateway returns `200` with no rows, where before it returned exactly the 11 pupils of that ethnicity with the `Ethnicity` column removed

#### Scenario: Searching a column the mandate may see
- **WHEN** a mandate with clearance 3 searches `query="2_OTH"` at `SCH02`
- **THEN** the result has rows, each with `Language` `2_OTH`

#### Scenario: Question 0's searches are unaffected
- **WHEN** `make eval_run` runs
- **THEN** every search case (pupil IDs, terms, year codes) matches a visible column and the eval stays 32/32

