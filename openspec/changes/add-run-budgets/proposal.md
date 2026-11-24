## Why

Every call is judged on its own, so an agent that walks Elmwood's Year 11s one pupil at a time ends up with the whole cohort, and every call was allowed (question 11). On Day 2 the same gap scores Bulk (10), and a flood of requests, forged or real, can crash the gateway (Crash, 5) or grow the audit file without limit. The audit trail now records which pupils each mandate received, so the gateway can finally judge the run, not just the call.

## What Changes

- **Per-mandate budgets, from signed claims only.**
  - A top-level `budget` claim: `{"distinct_pupils": N, "calls": N}`, both optional.
  - A per-scope-entry `rate`: `{"per_minute": N, "max_calls": N}`, both optional.
- **Distinct pupils are counted before release.** For an allowed call the gateway holds the result, counts the pupils in it that the mandate hasn't seen, and withholds the whole result with `429 BUDGET_EXHAUSTED` if the total would pass the budget. Nothing over budget leaves.
- **A budget covers a mandate and its children.** A supplementary mandate (`parent.jti`, from the scope-requests change) draws on its parent's budget, so asking for more access doesn't reset the count.
- **A gateway ceiling for every caller.** Calls per agent key per minute, and requests per source address per minute for requests that never verify. Over the ceiling: `429 RATE_LIMITED`. Defaults sit well above a full eval run.
- **Configurable.** Ceilings, alert thresholds and an optional default budget for mandates without claims live in `gateway/config/limits.yaml`, each overridable by a `GATEWAY_LIMIT_<SECTION>_<KEY>` environment variable, validated at startup and shown by `/describe`. The default budget ships as `null` (none), so the eval and Day 2 default mandate are unaffected.
- **Alerts for mandates without budget claims.** Those mandates are never refused by history (D3). Instead the gateway records an `alert` event in the audit trail when:
  - a mandate is refused 5 times in a row;
  - one mandate has received more than 200 distinct pupils;
  - one pupil has been returned to 3 or more mandates within an hour.
- **Readable by the person.** Alerts appear in `audit.events` next to the calls that caused them.

## Capabilities

### New Capabilities
- `run-budgets`: the `budget` and `rate` claims, distinct-pupil counting before release, budgets shared with child mandates, the gateway ceiling per agent key and per unverified source, the alert rules for mandates without budget claims, and the `429` responses.

### Modified Capabilities
None. Mandates without the new claims keep their decisions; the only new refusal they can meet is the gateway ceiling, set above any legitimate traffic.

## Non-goals

- **No change to any decision for mandates without `budget` or `rate`**, except the gateway ceiling. The eval and the Day 2 default mandate get the same answers.
- **No decision model** (the run-pattern label is a later change); the alert rules are fixed thresholds.
- **No cross-replica counters.** Per-minute windows are in memory, per process; lifetime counts come from the audit store.
- **No budget for counts results** (`aggregate`): they return no pupil IDs. Safe counts are `add-safe-counts`.

## Impact

- **Builds on** `add-audit-trail` on `ihor`: `history(jti)`, the result summary's pupil IDs, and the audit store.
- **New code:** `gateway/lib/budgets.py` (claim parsing, windows, the budget check, alert rules).
- **Changed code:**
  - `gateway/main.py`: the ceiling before deciding; the budget check between forwarding and recording.
  - `gateway/lib/audit.py`: an `alert` event type, distinct pupils per mandate family, and pupils returned per pupil across mandates.
- **Responses:** `429` with reasons `RATE_LIMITED` and `BUDGET_EXHAUSTED`, inside the existing `decision` object. The request shape is unchanged.
- **Storage:** the SQLite schema's `event_type` check gains `alert`, and events gain optional `family_jti` and `scope_entry`. An existing audit file is migrated on open: new columns are added, and a file whose check predates `alert` is rebuilt row by row, so its events and chain are unchanged.
- **Config:** `gateway/config/limits.yaml` (new), and `pyyaml` added to the gateway extra.
- **For the scope-requests change:** the issuer must copy the parent's `budget` claim into supplementary mandates.
- **Questions:** 11, and inputs for 16 (alerts show misuse). Day 2: Bulk, Crash, and the "Unseen" bonus.
