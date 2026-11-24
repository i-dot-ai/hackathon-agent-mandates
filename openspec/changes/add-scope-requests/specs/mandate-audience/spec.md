## Purpose

Lets a mandate say whose data each grant may touch, as a fixed list of pupil IDs the issuer resolved at signing, so the person approves exact pupils and the gateway refuses calls about anyone else.

## ADDED Requirements

### Requirement: A scope entry may carry an audience of pupil IDs
A scope entry MAY carry `audience`, an object with one key, `pupils`: a list of 1 to 500 pupil IDs. The gateway SHALL read `audience` only from the verified mandate. An `audience` in any other form, including one keyed by a pupil attribute such as care status or ethnicity, MUST make the entry deny every call with `403` and reason `AUDIENCE_INVALID`. A scope entry without `audience` SHALL behave exactly as before.

#### Scenario: Entry without audience unchanged
- **WHEN** the default Ashfield mandate, whose entries have no `audience`, calls `pupil-data.search(query="P0004", urn="SCH01", limit=1)`
- **THEN** the gateway returns `200 ALLOW` with reason `IN_SCOPE`, as before this change

#### Scenario: Audience defined by an attribute
- **WHEN** a mandate's entry has `audience: {"InCareAtCurrentSchool": "1"}`, and the agent calls a tool that entry lists
- **THEN** the gateway returns `403 DENY` with reason `AUDIENCE_INVALID`

### Requirement: Calls naming pupils must stay inside the audience
For a call matched to an entry with an audience, the gateway SHALL refuse the call with `403` and reason `AUDIENCE_VIOLATED`, naming the first pupil outside the audience, when:
- a `pupil_id` argument is not in the audience; or
- any value of a `pupil_ids` argument is not in the audience.

#### Scenario: Pupil not on the list
- **WHEN** a mandate whose `pupil-data.pupil` entry has `audience: {"pupils": ["P0011", "P0042"]}` and `urn` constraint `SCH04` calls `pupil-data.pupil(pupil_id="P0099", urn="SCH04")`
- **THEN** the gateway returns `403 DENY` with reason `AUDIENCE_VIOLATED` and detail `P0099`

#### Scenario: One letter outside the list
- **WHEN** the same mandate's `draft` entry has the same audience and the agent calls `draft(urn="SCH04", pupil_ids=["P0011", "P0099"])`
- **THEN** the gateway returns `403 DENY` with reason `AUDIENCE_VIOLATED` and detail `P0099`

### Requirement: Calls returning many pupils are limited at the tool
For a call matched to an entry with an audience, where the tool's arguments don't name pupils (`search`, `roster`), the gateway SHALL allow the call on its other checks and put the audience in the tool grant, so the server returns only rows for those pupils.

#### Scenario: Roster limited to the audience
- **WHEN** a mandate whose `directory.roster` entry has `audience: {"pupils": ["P0011", "P0042"]}` calls `directory.roster(urn="SCH04", year_group=11)`
- **THEN** the gateway returns `200 ALLOW`, and the result contains only `P0011` and `P0042`
