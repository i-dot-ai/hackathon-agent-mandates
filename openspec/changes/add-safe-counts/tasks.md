## 1. Column rules

- [x] 1.1 Create `gateway/lib/safe_counts.py` with `check(arguments, claims)`: identifiers refused anywhere, level-4 columns only with `clearance: 4`, at most 2 `group_by` columns, `where` only on level-1 or level-2 columns, giving `COUNT_COLUMN_REFUSED` or `COUNT_TOO_FINE`; verify unit tests for each rule and for the two leak calls from the proposal
- [x] 1.2 Call `check` in `tools_call` for allowed `pupil-data.aggregate` calls before forwarding, recording the refusal like any other; verify gateway tests that both leak calls get 403 and nothing is forwarded

## 2. Pupil counts, suppression and rounding

- [x] 2.1 Implement the internal breakdown call (`group_by + ["Psuedo ID"]`) and fold it into `n` and `m` per group, skipping it for tables without `Psuedo ID`; verify a unit test against an in-process MCP server that `SCH07`'s in-care `n` is 112 and `m` is 1 (checked through the gateway: total 110, count null)
- [x] 2.2 Implement suppression (`n < k` dropped, `count: null` for 1–4 either way, a `suppressed_groups` marker without keys) and rounding to 5 (ties up, zero kept), with `k` = max(10, `counts.k`); verify the one-in-care, raise-k-not-lower and differencing scenarios
- [x] 2.3 Return the rewritten result from `tools_call` in place of the tool's rows; verify the eval counts case returns 12 rows with rounded pupil counts and no suppression

## 3. Audit scoring

- [x] 3.1 Score `total`, `count` and `suppressed_groups` as level 1, and pass the measure's level as a `max_level` hint into `audit.summarise`; verify the eval counts case's audit event records level 3

## 4. Docs and check-in

- [x] 4.1 Document `counts` in `gateway/lib/mandate.schema.json` and write `docs/safe-counts.md` like `questions/02-worked-example.md` (a counts mandate, a count released, the P0011 leak call refused, Greystone's in-care count hidden, what's unresolved); verify each command runs against the branch gateway

## 5. Final checks

- [x] 5.1 `make eval_run` gives 32/32 and question 0 at 12/12
- [x] 5.2 `make test` and `make lint` pass
- [x] 5.3 Live: the two Codex leak calls from the proposal are refused through the gateway on `:8082`, _(24 Nov, on the rebuilt `:8082` container: both leak calls `403 COUNT_COLUMN_REFUSED Psuedo ID`, Ethnicity without clearance 4 refused, SCH07 in care `count: null`, SCH02 `count: 0`)_ and a `clearance: 4` in-care-by-school call returns Greystone with `count: null`
