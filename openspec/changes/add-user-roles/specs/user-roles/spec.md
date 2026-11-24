# Spec Delta

## Purpose

Defines what a person holds and can pass down to an agent: access roles shaped like mandate grants, user roles that
bundle them, and the signed bearer token from a (stub) auth server that tells the issuer who the person is and which
roles they hold.

## ADDED Requirements

### Requirement: Access roles are grants a person holds
An access role SHALL be a named grant with the shape of a mandate scope entry (`server`, `tools`, optional
`constraints`, optional `max_rows`) plus a `clearance`. Access roles SHALL be defined in the issuer's roles file, and
nowhere else. A role name MUST NOT be read from request arguments as a grant.

#### Scenario: An access role in the roles file
- **WHEN** the roles file defines `pupil-data-editor@SCH04` as `{"server": "pupil-data", "tools": ["search", "pupil", "write"], "constraints": {"urn": ["SCH04"]}, "clearance": 4}`
- **THEN** a person holding it can delegate any grant inside that entry, and nothing outside it

### Requirement: User roles bundle access roles
A user role SHALL be a named list of access roles with a description in words, defined in the same roles file. A
person's held access roles SHALL be the union of the access roles in their user roles. A user role or access role name
that the roles file doesn't define SHALL grant nothing.

#### Scenario: Attendance officer
- **WHEN** a person holds user role `attendance-officer@SCH04` = `roster-reader@SCH04` + `pupil-data-editor@SCH04`
- **THEN** their held access roles are exactly those two

#### Scenario: Unknown role
- **WHEN** a token lists `head-of-everything`, which the roles file doesn't define
- **THEN** it adds no access, and the issuer's refusal detail names it as unknown

### Requirement: A grant fits only inside one whole access role
A requested or approved grant SHALL fit a person's roles only when every scope entry is covered by a single held access
role (same server, tools a subset, every constraint the role sets at least as narrow, rows no more), and the grant's
clearance and each entry's server level are no higher than that role's clearance. Entries MUST NOT combine parts of
different roles.

#### Scenario: Allowed: edit at the school you edit
- **GIVEN** a person holding `pupil-data-editor@SCH04` and `aggregate-reader@SCH01`
- **WHEN** their agent's request for `pupil-data.write` at `SCH04` with clearance 4 is checked
- **THEN** it fits, and the request is created

#### Scenario: Denied: edit at the school you only read
- **GIVEN** the same person
- **WHEN** their agent asks for `pupil-data.write` at `SCH01`
- **THEN** `grants.request` is refused with reason `EXCEEDS_PRINCIPAL`, naming `pupil-data.write at SCH01`

#### Scenario: Denied: clearance above the role
- **GIVEN** the same person, whose `roster-reader@SCH04` role has clearance 2
- **WHEN** their agent asks for `directory.roster` at `SCH04` with clearance 3
- **THEN** `grants.request` is refused with reason `EXCEEDS_PRINCIPAL`, naming clearance 3, even though the person holds clearance 4 through another role

### Requirement: The stub auth server signs bearer tokens
The team UI SHALL host a sign-in page acting as a stub auth server. A person chooses a principal and ticks user roles
from the issuer's published role list; the UI SHALL sign a bearer token with the stub-IdP key, typ `at+jwt`, claims
`iss`, `aud: "mandate-issuer"`, `sub`, `roles`, `iat`, `exp` (at most 15 minutes) and `jti`, and keep it in an HTTP-only
cookie. The private key SHALL be available only to the UI's server.

#### Scenario: Signing in as an attendance officer
- **WHEN** a person signs in as `officer:jsmith` with `attendance-officer@SCH04` ticked
- **THEN** the browser holds an HTTP-only cookie with a token whose `sub` is `officer:jsmith` and `roles` is `["attendance-officer@SCH04"]`, and page scripts can't read it

### Requirement: The issuer authenticates a person only from a valid bearer token
A person's decision SHALL be accepted only with a bearer token whose signature verifies against the trusted stub-IdP
public key, with typ `at+jwt`, `aud` `mandate-issuer`, and an unexpired `exp`. A missing token SHALL be refused with
`TOKEN_REQUIRED` (401); any other failure with `TOKEN_INVALID` (401). The request MUST stay pending after either.

#### Scenario: No token
- **WHEN** someone opens the `approval_url` without signing in and submits Approve
- **THEN** the issuer refuses with `TOKEN_REQUIRED`, and the request stays pending

#### Scenario: Token signed with another key
- **WHEN** a decision carries a token with the right claims, signed with a key the issuer doesn't trust
- **THEN** the issuer refuses with `TOKEN_INVALID`, and the request stays pending

#### Scenario: Expired token
- **WHEN** a decision carries a token 16 minutes after it was issued
- **THEN** the issuer refuses with `TOKEN_INVALID`

### Requirement: Only the mandate's principal approves, within their current roles
A person's decision SHALL be accepted only when the token's `sub` equals the requesting mandate's `delegator.principal`
(otherwise `NOT_THE_APPROVER`), and the approved grant fits the token's roles (otherwise `EXCEEDS_ROLES`). Both refusals
MUST leave the request pending.

#### Scenario: Allowed: the principal approves within their roles
- **GIVEN** a pending request from a mandate delegated by `officer:jsmith` for `directory.roster` at `SCH04`
- **WHEN** a token for `officer:jsmith` with `attendance-officer@SCH04` approves it
- **THEN** the issuer mints the supplementary mandate, and the audit chain records `approval_granted`

#### Scenario: Denied: someone else's token
- **WHEN** a token for `officer:priya` approves that request
- **THEN** the issuer refuses with `NOT_THE_APPROVER`, and the request stays pending

#### Scenario: Denied: the principal no longer holds the role
- **WHEN** a token for `officer:jsmith` with only `aggregate-reader@SCH01` approves that request
- **THEN** the issuer refuses with `EXCEEDS_ROLES`, and the request stays pending

### Requirement: A mandate records its delegator's roles
A mandate issued for a signed-in person SHALL record their user roles at issue time as `delegator.roles` and set
`delegator.principal` from the token's `sub`. Issuing SHALL be refused with `EXCEEDS_ROLES` when the mandate's scope
doesn't fit those roles.

#### Scenario: Issuing for a signed-in person
- **WHEN** `cli issue` runs with a token for `officer:jsmith` holding `attendance-officer@SCH04` and a scope of `directory.roster` at `SCH04`
- **THEN** the mandate's `delegator` is `{"principal": "officer:jsmith", "roles": ["attendance-officer@SCH04"], ...}`

#### Scenario: Denied: issuing beyond the person's roles
- **WHEN** the same token is used to issue a scope of `directory.roster` at `SCH02`
- **THEN** issuing is refused with `EXCEEDS_ROLES`, and no mandate is written

### Requirement: Scope requests are checked against the recorded roles
`grants.request` SHALL be checked against the requesting mandate's `delegator.roles`; only original mandates can make
requests. The issuer SHALL keep those roles with the request for later checks. A mandate without `delegator.roles`
SHALL have every scope request refused with `EXCEEDS_PRINCIPAL`, detail "no roles recorded".

#### Scenario: A mandate without roles keeps working
- **WHEN** the Day 2 default mandate, which has no `delegator.roles`, calls `schools.get`
- **THEN** the gateway's decision is the same as before this change

#### Scenario: A mandate without roles can't get more
- **WHEN** a mandate without `delegator.roles` calls `grants.request`
- **THEN** the gateway returns the issuer's refusal `EXCEEDS_PRINCIPAL` with detail "no roles recorded"

### Requirement: A supervisor's approval stays inside the person's roles
A supervising agent's decision SHALL be minted only when the approved grant fits the requesting mandate's recorded
`delegator.roles` as well as the supervisor's own mandate; otherwise it SHALL be refused with `EXCEEDS_PRINCIPAL`.

#### Scenario: Supervisor approves within the person's roles
- **WHEN** a supervisor with `can_delegate` approves a helper's request for `directory.roster` at `SCH04`, and the helper's mandate records `attendance-officer@SCH04`
- **THEN** the issuer mints the supplementary mandate

### Requirement: The role list is published in words
The issuer SHALL publish the defined user roles, each with its description and its access roles in plain words
generated from the structured grants, for the sign-in page. It SHALL publish no principals and no tokens.

#### Scenario: Sign-in page lists roles
- **WHEN** the sign-in page loads
- **THEN** it shows `attendance-officer@SCH04` with words such as "List Year 10 and 11 pupils' IDs and names at Dunmore Community College (SCH04)"
