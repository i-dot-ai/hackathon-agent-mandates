## Why

`aggregate` returns counts, but a count can name a child. Checked live on 23 Nov through the eval's counts mandate, which constrains only `table` and `measure`:
- `group_by=["Ethnicity","URN"], where={"Psuedo ID":"P0011"}` returns `ASIA, SCH04` for the Day 2 flag pupil: level-4 data, worth 40 points.
- `group_by=["Psuedo ID","Ethnicity","URN"]` lists all 1,500 pupils, P0586 included, which is a Bulk break.

The tool applies no suppression and says that is "the gateway's decision" (question 8). The audit trail also scores every counts result as level 4, because `total` and `count` aren't manifest columns.

## What Changes

- **A column allow-list for `group_by`, `where` and `measure`,** for every `aggregate` call, whatever the mandate:
  - pupil identifier columns (`Psuedo ID`, `DisplayName`) are never allowed in any of them;
  - level-4 columns (`Ethnicity`, `InCareAtCurrentSchool`) are allowed only for a mandate with `clearance: 4`;
  - at most 2 `group_by` columns;
  - `where` is limited to exact matches on level-1 or level-2 columns that aren't identifiers.

  Refusals: `403 COUNT_COLUMN_REFUSED` or `403 COUNT_TOO_FINE`.
- **Small groups are suppressed, counted on pupils.**
  - The gateway counts distinct pupils per group itself.
  - It drops any group with fewer than `k` pupils (default 10).
  - It hides `count` when it, or `total − count`, is between 1 and 4 pupils. That stops a near-total group revealing the few without the flag.
  - Suppressed groups come back as one marker row with how many groups were hidden, never their keys.
- **Counts are rounded to the nearest 5,** with `total` and `count` reported as pupils, not census rows. Subtracting two safe answers then gives a fuzzy number, not one child.
- **A mandate may tighten, never loosen.** An optional `counts` claim `{"k": N}` raises `k` above the default; a lower value is ignored.
- **The audit trail scores counts at the level of the grouped columns,** not as level 4.

## Capabilities

### New Capabilities
- `safe-counts`: the column rules for `aggregate`, distinct-pupil group sizes, suppression of small groups and complements, rounding, the `counts` claim, and how counts results are scored in the audit trail.

### Modified Capabilities
None. `pupil-data` itself is unchanged (`data-interfaces`' "pupil-data is unchanged"); the rules run at the gateway.

## Non-goals

- **No full differencing defence.** Rounding and a minimum group size make most subtraction attacks fuzzy, not impossible. A per-mandate query budget is `add-run-budgets`.
- **No new counting tool, and no change to the MCP server.** The gateway asks the existing tool for the per-pupil breakdown.
- **No suppression for `classification`, `roster` or other tools.**

## Impact

- **Changes claim-less mandates' answers for unsafe queries only.** This is a deliberate exception to "mandates without new claims behave as before" (D3): the leak is in the starter, and the Day 2 feature mandates are where it would land. The eval's counts case (`group_by=["URN"]`, `FSMeligible`) stays allowed. Its result changes from rows to rounded pupil counts, which the eval doesn't check.
- **New code:** `gateway/lib/safe_counts.py` (column rules, the pupil breakdown query, suppression, rounding).
- **Changed code:**
  - `gateway/main.py`: the column check before forwarding, and the rewrite after it.
  - `gateway/lib/audit.py`: scoring counts results by their group columns.
- **Upstream calls:** every allowed `aggregate` is sent upstream as its per-pupil breakdown instead of as written. Coordinate with the scope-requests change: its tool grant for this call must allow the extra `Psuedo ID` group column.
- **Questions:** 8, and part of 15. Day 2: closes the confirmed level-4 path through counts and the Bulk path through `group_by` on pupil IDs.
