## 1. Clearance

- [x] 1.1 Make `pupil-data` graded in `check_clearance` (any clearance 1 to 4 allowed) and refuse `pupil`, `roster`, `draft` and `write` without a clearance (`CLEARANCE_MISSING`); verify unit tests and the existing clearance tests
- [x] 1.2 Hold `pupil-data` `search`, `pupil` and census `get` at clearance 4 with `SPECIAL_CATEGORY`, released once by pre-approval; verify the ethnicity-needs-a-person and approved-once scenarios

## 2. Stripping

- [x] 2.1 Strip `pupil-data` results above the clearance at the gateway before release (the MCP server already does it via the tool grant); verify the clearance-2 and clearance-3 scenarios through the gateway

## 3. Final checks

- [x] 3.1 Update tests that relied on no-clearance person-level tools or clearance 4 reads; `make test`, `make lint`, `make eval_run` 32/32
- [x] 3.2 Live: the P0050 call without clearance is refused, at clearance 2 it returns no sensitive fields

## 4. No clearance means basic data

- [x] 4.1 `graded.level_for` returns the claim-less level (`GATEWAY_CLAIMLESS_LEVEL`, default 2) for mandates without `clearance`; counts are not stripped
- [x] 4.2 Tests: claim-less `search` and census `get` stripped, counts unchanged, the setting's fallbacks; audit expectations now record level 2
- [x] 4.3 `make eval_run` 32/32 live; live claim-less `search`/`get` return no level 3-4 columns

## 5. Search can't select by a stripped value

- [x] 5.1 Keep a search row only if the query matches a column left after stripping, in `graded.strip` (gateway, before release) and in `tool_grants.enforce` (MCP server, under the grant's level); verify tests that `ASIA`, `2_OTH` and `WHIT` return no rows with no clearance and at clearance 2, that a visible-column search still returns rows, and the server-side grant at level 2 versus 4
- [x] 5.2 `make eval_run` 32/32 live with the change, and the 23 Nov `ASIA` check (11/11 inferred) rerun with no rows returned. Done 24 Nov against this branch's gateway beside the running data servers: ASIA 0 rows with no clearance and at clearance 2 and 3, 2_OTH 0 rows below clearance 3 and 100 at 3, ID searches unchanged

