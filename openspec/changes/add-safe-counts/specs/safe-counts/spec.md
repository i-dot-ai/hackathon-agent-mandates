## Purpose

Makes counts safe to release: the gateway refuses groupings that would single out a pupil, suppresses small groups, and rounds what it releases, so an answer made only of numbers can't name a child.

## ADDED Requirements

### Requirement: Counts can't group or filter by who a pupil is
For every `pupil-data.aggregate` call the gateway allows, it SHALL refuse with `403 COUNT_COLUMN_REFUSED`, before forwarding, any call that names a pupil identifier column (`Psuedo ID`, `DisplayName`) in `group_by`, `where` or `measure`. This SHALL apply to every mandate, with or without new claims.

#### Scenario: Filtering on one pupil
- **WHEN** a mandate allowing `aggregate` on the census table calls it with `group_by=["Ethnicity","URN"]` and `where={"Psuedo ID": "P0011"}`
- **THEN** the gateway returns `403 DENY` with reason `COUNT_COLUMN_REFUSED` and detail `Psuedo ID`

#### Scenario: Grouping by pupil
- **WHEN** the same mandate calls it with `group_by=["Psuedo ID","Ethnicity","URN"]`
- **THEN** the gateway returns `403 DENY` with reason `COUNT_COLUMN_REFUSED`

### Requirement: Special category columns need clearance 4
A level-4 column (by the data manifest's classification, currently `Ethnicity` and `InCareAtCurrentSchool`) in `group_by`, `where` or `measure` SHALL be allowed only for a mandate whose `clearance` claim is 4. Otherwise the gateway SHALL refuse with `403 COUNT_COLUMN_REFUSED` naming the column. A column the manifest doesn't list counts as level 4.

#### Scenario: Ethnicity without clearance
- **WHEN** a mandate with no `clearance` and an `aggregate` scope with no `measure` constraint calls it with `group_by=["URN","Ethnicity"]`
- **THEN** the gateway returns `403 DENY` with reason `COUNT_COLUMN_REFUSED` and detail `Ethnicity`

#### Scenario: Ethnicity with clearance 4
- **WHEN** a mandate with `clearance: 4` makes the same call
- **THEN** the call is allowed, subject to suppression

### Requirement: Counts are no finer than two columns
A call with more than 2 `group_by` columns, or a `where` filter on any column that isn't level 1 or 2, SHALL be refused with `403 COUNT_TOO_FINE`.

#### Scenario: Three-way breakdown
- **WHEN** a mandate with `clearance: 4` calls `aggregate` with `group_by=["URN","Gender","Ethnicity"]`
- **THEN** the gateway returns `403 DENY` with reason `COUNT_TOO_FINE`

### Requirement: Groups are counted on pupils and small ones are suppressed
For an allowed `aggregate` call, the gateway SHALL report `total` and `count` as numbers of distinct pupils, not census rows. It SHALL remove from the result every group with fewer than `k` distinct pupils, where `k` is 10, or the mandate's `counts.k` claim if that is a higher integer. In a released group, it SHALL replace `count` with `null` when either the count or `total − count` is between 1 and 4. When groups are removed, the result SHALL end with one row `{"suppressed_groups": N}` and SHALL NOT include any removed group's keys.

#### Scenario: Free school meals by school is released
- **WHEN** the eval's counts mandate calls `aggregate(table="personal_data_school_census", group_by=["URN"], measure="FSMeligible")`
- **THEN** the gateway returns `200 ALLOW` with one row per school, with `total` and `count` in pupils, and no suppressed groups

#### Scenario: One in-care pupil at a school
- **WHEN** a mandate with `clearance: 4` asks for `InCareAtCurrentSchool` grouped by `URN`, and Greystone (`SCH07`) has exactly one pupil in care
- **THEN** Greystone's row has `count: null`, so the one child isn't counted

#### Scenario: A mandate can raise k but not lower it
- **WHEN** a mandate with `counts: {"k": 3}` asks for a grouping with a 5-pupil group
- **THEN** the 5-pupil group is suppressed, because k stays 10

### Requirement: Released counts are rounded
Every `total` and `count` the gateway releases from `aggregate` SHALL be rounded to the nearest multiple of 5, with ties rounding up, except zero, which SHALL stay zero.

#### Scenario: Differencing two answers
- **WHEN** an agent asks for in-care counts at `SCH07` with and without a filter that excludes one pupil's census term
- **THEN** both answers are multiples of 5, and their difference doesn't identify the pupil

### Requirement: Counts are scored by what they group on
The audit trail SHALL score an `aggregate` result at the highest level among its `group_by` and `measure` columns, and SHALL NOT count `total`, `count` or `suppressed_groups` as unlisted level-4 columns.

#### Scenario: School counts aren't special category
- **WHEN** the eval's counts case is allowed
- **THEN** its audit event records highest PII level 3, the level of `FSMeligible`, rather than 4
