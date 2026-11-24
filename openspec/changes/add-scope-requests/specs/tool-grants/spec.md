## Purpose

Applies zero trust to the hop between the gateway and the MCP servers. Each forwarded call carries a signed, single-use grant naming the data type, the arguments, and whose data the call may return. The servers enforce it themselves, so a gateway mistake or a caller that bypasses the gateway gets nothing beyond one grant.

## ADDED Requirements

### Requirement: Every forwarded call carries a tool grant
For every call the gateway forwards to an MCP server, the gateway SHALL send a tool grant with the call. The grant is a JWT of type `tool-grant+jwt`, signed with a key used only for tool grants (not the issuer key, not the audit key). It SHALL contain:
- `aud`: the target server name;
- `tool`;
- `args_hash`: the hash of the exact canonical arguments forwarded;
- `jti`: equal to the call's audit `decision_id`;
- `sub`: the mandate's `jti`;
- the agent's `agent_id`;
- the delegator principal;
- `level`: the highest data level the call may return;
- `subjects`: the schools and, if any, pupil IDs the call may concern;
- the matched scope entry's constraints;
- `max_rows`;
- `exp`: at most 30 seconds after issue.

The request body of `POST /tools/call` SHALL be unchanged.

#### Scenario: Grant joins the audit event
- **WHEN** the default Ashfield mandate's `pupil-data.search(query="P0004", urn="SCH01", limit=1)` is forwarded
- **THEN** the MCP server receives a tool grant with `aud` `pupil-data`, `tool` `search`, `subjects.urns` `["SCH01"]`, and a `jti` equal to the `decision_id` in the gateway's response

#### Scenario: No grant for refused or held calls
- **WHEN** a call is refused or held
- **THEN** no tool grant is issued

### Requirement: A grant is derived only from the verified mandate
The gateway SHALL derive every subject, level and limit in a tool grant from the verified mandate claims and the matched scope entry, never from the request arguments.
- `subjects.urns` SHALL be the values of the matched entry's `urn` constraint, if it has one.
- `subjects.pupils` SHALL be the entry's `audience`, if it has one.
- `level` SHALL be the lower of the server's data level and the mandate's clearance. For a mandate without clearance it SHALL be the server's data level.
- `max_rows` SHALL be the entry's `max_rows`, or 100 if it has none.

For a mandate without new claims, a grant SHALL allow exactly what the gateway's own checks allowed, so the result is unchanged.

#### Scenario: Default mandate result unchanged
- **WHEN** `make eval_run` runs with tool grants enforced
- **THEN** every case gets the same decision, reason code and result rows as without tool grants, and question 0 passes 12/12

### Requirement: Servers refuse calls without a valid grant
Every MCP server and interface slice that serves pupil data SHALL refuse an HTTP tool call unless it carries a valid tool grant. A valid grant:
- verifies with the gateway's tool-grant public key;
- has `aud` equal to that server's name and `tool` equal to the tool called;
- has an `args_hash` equal to the hash of the arguments received;
- is not expired;
- has a `jti` the server has not seen in an earlier call.

A refused call SHALL return an MCP error naming the reason (`GRANT_MISSING`, `GRANT_INVALID`, `GRANT_EXPIRED`, `GRANT_REPLAYED`, `GRANT_MISMATCH`) and no data.

#### Scenario: Direct call to the data server
- **WHEN** anyone calls `search` on `:8080/mcp/` without going through the gateway
- **THEN** the server returns an error with reason `GRANT_MISSING` and no rows

#### Scenario: Grant reused for another call
- **WHEN** a valid grant for `search(query="P0004", urn="SCH01")` is replayed with `search(query="", urn="SCH01")`
- **THEN** the server returns an error with reason `GRANT_MISMATCH` and no rows

#### Scenario: Grant replayed
- **WHEN** the same grant and arguments are sent a second time
- **THEN** the server returns an error with reason `GRANT_REPLAYED`

### Requirement: Servers re-check arguments against the grant
Before running a tool, a server holding a valid grant SHALL itself check the arguments against the grant:
- a `urn` argument MUST be in `subjects.urns`, when that list is present;
- a `pupil_id` argument, and every value of a `pupil_ids` argument, MUST be in `subjects.pupils`, when that list is present;
- every argument the grant's constraints name MUST have an allowed value.

A call failing any of these MUST return an error with reason `GRANT_SCOPE` and no data. This covers tools whose results don't carry the school or pupil, such as `roster` and `draft`.

#### Scenario: Roster for another school
- **WHEN** a grant has `subjects.urns` `["SCH04"]` and its arguments ask for `directory.roster(urn="SCH02", year_group=11)`, because of a gateway bug
- **THEN** the server returns an error with reason `GRANT_SCOPE` and no names

### Requirement: Servers return only what the grant allows
A server holding a valid grant SHALL itself apply the grant to the result before returning it:
- drop every row whose school is not in `subjects.urns`, when that list is present;
- drop every row whose pupil is not in `subjects.pupils`, when that list is present;
- drop every column whose data level is above `level`;
- return at most `max_rows` rows.

These checks SHALL be applied even when the gateway's own checks should already have refused the call. Pupil data in a result is the rows and column values under the pupil ID fields and every tool's documented output fields.

#### Scenario: Gateway bug does not leak another school
- **WHEN** a grant has `subjects.urns` `["SCH01"]`, and the arguments ask for `urn` `SCH02` because a gateway check was wrong
- **THEN** the server returns no `SCH02` rows

#### Scenario: Audience enforced at the tool
- **WHEN** a grant has `subjects.pupils` `["P0011", "P0042"]` and the call is `directory.roster(urn="SCH04", year_group=11)`
- **THEN** the result contains only rows for `P0011` and `P0042`

#### Scenario: Level enforced at the tool
- **WHEN** a grant has `level` 2 and the tool would return census columns
- **THEN** the result contains no column above level 2

### Requirement: Internal tool calls stay testable
Tool code called in process, without HTTP (unit tests and the gateway's in-process test servers), SHALL keep working without a grant. Grant verification SHALL apply at each server's HTTP entry point. Turning it off SHALL require an explicit environment setting that the deployed Compose file does not set.

#### Scenario: Unit tests unchanged
- **WHEN** `make test` runs
- **THEN** the existing MCP server and slice tests pass without minting grants
