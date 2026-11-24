# data-interfaces Specification

## Purpose
Splits pupil data into separate data-interface servers, each able to express only one data class, so a mandate's tools decide not just what an agent may do but which class of data it can ever receive.

## Requirements

### Requirement: Each data interface serves one data class
The gateway SHALL route to three data-interface servers besides `pupil-data`, each with a fixed data level taken from the manifest's four-level classification: `schools` at level 1, `directory` at level 2 and `special` at level 4. A response from an interface server MUST NOT contain any column whose manifest level is above that server's level, except the identifying keys listed for that server below.

#### Scenario: schools returns only public data
- **WHEN** a mandate with `clearance: 1` and scope `[{"server": "schools", "tools": ["list"]}]` calls `schools.list` with no arguments
- **THEN** the gateway returns `200 ALLOW` with reason `IN_SCOPE`, and the result is the 12 schools with `URN`, `SchoolName` and `SchoolLA` only

#### Scenario: schools exposes the classification table
- **WHEN** the same mandate's scope also lists `classification` and the agent calls `schools.classification`
- **THEN** the result is the manifest's classification (levels, tables and columns) and nothing else from the manifest

### Requirement: directory returns pseudo IDs and names only
`directory.roster(urn, year_group, academic_year, term)` SHALL return, for every pupil in that cohort, exactly `Psuedo ID` and `DisplayName`. `directory.name(pupil_id, urn)` SHALL return exactly `Psuedo ID` and `DisplayName` for that pupil if their latest census row is at `urn`, and an empty result otherwise. Neither tool MAY return any census column other than `Psuedo ID`.

#### Scenario: Roster of a cohort
- **WHEN** a mandate with `clearance: 2` and scope `[{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}]` calls `directory.roster(urn="SCH04", year_group=11, academic_year="2023/24", term="SPR")`
- **THEN** the gateway returns `200 ALLOW`, and every row has exactly the keys `Psuedo ID` and `DisplayName`

#### Scenario: Name of a pupil at another school
- **WHEN** the same kind of mandate, constrained to `SCH04`, calls `directory.name(pupil_id="P0586", urn="SCH04")` and P0586's latest census row is at `SCH07`
- **THEN** the gateway returns `200 ALLOW` with an empty result

#### Scenario: No special category data from directory
- **WHEN** any `directory` tool is called with any arguments
- **THEN** the result contains no `Ethnicity`, `InCareAtCurrentSchool`, `FSMeligible`, `Language` or deprivation column

### Requirement: special returns level 4 fields for one pupil, without a name
`special.record(pupil_id, urn)` SHALL return exactly `Psuedo ID`, `URN`, `AcademicYear`, `CensusTerm`, `Ethnicity` and `InCareAtCurrentSchool` from the pupil's latest census row if that row is at `urn`, and an empty result otherwise. It MUST NOT return `DisplayName` or any deprivation field. It SHALL accept exactly one pupil per call.

#### Scenario: Level 4 record carries no name
- **WHEN** `special.record(pupil_id="P0011", urn="SCH04")` is forwarded to the server after approval
- **THEN** the result has the six listed keys and no `DisplayName`

#### Scenario: Pupil not at the named school
- **WHEN** `special.record(pupil_id="P0586", urn="SCH04")` is forwarded and P0586's latest row is at `SCH07`
- **THEN** the result is empty

### Requirement: An interface server limits itself even without the gateway
Each interface server SHALL apply its own column limit to every read, independently of the gateway, so a request that reaches the server directly receives no column above that server's level. The interface servers SHALL NOT be reachable from outside the deployment network.

#### Scenario: Direct call to directory
- **WHEN** a client inside the deployment network calls `directory.roster` directly, bypassing the gateway
- **THEN** the result still contains only `Psuedo ID` and `DisplayName`

#### Scenario: No published port
- **WHEN** the stack is started with `docker compose up`
- **THEN** the interface servers' port is not published on the host, while `pupil-data` on `:8080` and the gateway on `:8082` remain as they are

### Requirement: pupil-data is unchanged
The `pupil-data` server SHALL keep its existing tools, arguments and results, so that the eval and the Day 2 default mandate behave exactly as before this change.

#### Scenario: Eval unchanged
- **WHEN** `make eval_run` is run after this change
- **THEN** question 0 passes 12/12 and the overall tally is unchanged from before the change (27/32)
