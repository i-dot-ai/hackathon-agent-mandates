## Context

- `pupil-data.aggregate(table, group_by, measure, where)` (`mcp_server/api/routes_mcp.py`) groups the CSV's rows. It returns one row per group with `total` (rows) and `count` (rows where `measure` is `"1"`), and applies no suppression. Each pupil has up to 5 census rows (one per term), so row counts overstate pupils, and a group of one pupil's rows can pass any row threshold.
- The eval's counts mandate constrains only `table` (census) and `measure` (`FSMeligible`). Its allowed case is `group_by=["URN"]`. Its question 2 case, an in-care measure, is refused by the constraint before any new rule runs.
- Pupils per school are 112–141; free school meals counts are 15–44, with complements of 77 or more. So the eval's case releases every row unchanged in shape, and only its numbers change from rows to rounded pupils. Greystone has exactly 1 pupil in care, Brookmere 0.
- The manifest gives column levels: `URN`, `AcademicYear`, `CensusTerm` 1; `Psuedo ID`, `Gender`, `EnrolStatus`, `AgeAtStartOfAcademicYear` 2; `Language`, `FSMeligible` 3; `Ethnicity`, `InCareAtCurrentSchool` 4. The schools table has no pupil column.
- `audit.summarise` scores unlisted columns as 4, so `total` and `count` make every counts result level 4 today.
- Requirements: `specs/safe-counts/spec.md`.

## Goals / Non-Goals

**Goals:**
- No released number identifies a pupil, through grouping, filtering, a small group or a near-total complement.
- The eval's counts case stays allowed.
- The MCP server and the data stay untouched.

**Non-Goals:**
- Provable privacy (differential privacy). Rounding plus suppression is the standard statistical-release practice, and the residual risk is stated.
- Counts over tables without pupils: they're released as rows, but still rounded.

## Decisions

### 1. Check columns before forwarding, at the gateway
`safe_counts.check(arguments, claims)` runs in `tools_call` after `decide` allows a `pupil-data.aggregate` call and before `_forward`. It refuses:
- identifier columns anywhere;
- level-4 columns without `clearance: 4`;
- more than 2 `group_by` columns;
- `where` on a level-3 or level-4 column.

Levels come from the same manifest `audit.column_level` reads.
- *Why not in `check_request`?* It's tool-specific logic, and `check_request` is shared with the scope-requests change's `grants.check`. Keeping it in its own module avoids a three-way merge there, and `grants.check` can call `safe_counts.check` too.
- *Alternative:* constrain `group_by` in each mandate's scope. Rejected: every issuer would have to remember it, and the starter mandate's leak shows they don't.

### 2. Count pupils with one breakdown call, instead of the agent's call
The gateway doesn't forward the agent's call as written. It makes one call to the same tool, the per-pupil breakdown (decided while implementing, 23 Nov: forwarding both would be a second upstream call whose result is thrown away):

`aggregate(table, group_by + ["Psuedo ID"], measure, where)`

It returns one row per (group, pupil). The gateway folds it into:
- `n`: pupils in the group;
- `m`: pupils with `count > 0` in that group, meaning pupils whose matching rows have the flag at least once.

The gateway builds the released rows from `n` and `m`; the per-pupil rows never leave it.
- The internal call groups by `Psuedo ID`, which the rule refuses for agents. It never leaves the gateway, and it isn't recorded as an agent call.
- Tables with no `Psuedo ID` column (schools) skip the breakdown and release rounded row counts.
- *Alternative:* a new MCP tool for distinct pupil counts. Rejected for now: the scope-requests change is editing the MCP servers for tool grants, and one more tool there is a merge for little gain. When tool grants land, the gateway mints a grant for this internal call too (coordinate).

### 3. Suppression, then rounding
For each group:
- if `n < k`, drop it;
- else if `1 ≤ m ≤ 4` or `1 ≤ n − m ≤ 4`, set `count` to `null`.

Then round `total` and any remaining `count` to the nearest 5, with ties up and zero kept. Append `{"suppressed_groups": N}` if any group was dropped.
- `k` = max(10, `counts.k`), where `counts.k` must be a positive integer, or the claim is ignored.
- *Why suppress before rounding:* rounding a 1 to 0 or a 3 to 5 is still a signal.
- *Why a complement rule:* a school of 112 with 111 not in care says the same as "1 in care".

### 4. Audit scoring
`audit.summarise` learns that `total`, `count` and `suppressed_groups` are level 1 (they're aggregates). The released result's level is then the highest of its group columns, such as `URN` at 1. To include the measure's level (`FSMeligible` 3), `tools_call` passes a hint, `max_level`, from `safe_counts`, which knows the measure. The summary takes the maximum of the two.

### 5. Every mandate, not only those with new claims
These rules change answers for claim-less mandates, which goes against the team rule that they behave as before (D3). The exception is deliberate:
- the leak is in the starter, and any Day 2 feature mandate that grants `aggregate` would expose it;
- the eval's one counts case still passes.

Its result shape stays one row per school with `total` and `count`. Only the numbers change, to rounded pupils.

## Risks / Trade-offs

- **[Differencing across filters]** → `where` is limited to level-1 and level-2 columns, with at most 2 group columns. Rounding to 5 turns any difference into a range. A determined attacker with many queries can still narrow it; the query budget from `add-run-budgets` caps how many they get.
- **[Larger upstream result per `aggregate`]** → One call returning up to one row per pupil per group, still milliseconds over a 7,449-row CSV.
- **[The internal call needs a tool grant once grants are enforced]** → Noted as a dependency for the scope-requests change: the gateway mints a grant scoped to the same table, `where` and the pupil column.
- **[Results change from rows to pupils]** → Documented in the tool's gateway notes and the worked example. Nobody relied on row semantics; the eval doesn't check values.
- **[Manifest-driven levels]** → An unlisted column counts as 4, so a new column can't slip through as low-level.

## Migration Plan

1. Land after `add-audit-trail` (on `ihor`). It's independent of `add-run-budgets`.
2. No data or schema change. Rollback is a revert.
