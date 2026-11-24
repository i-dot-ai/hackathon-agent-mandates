## Why

The team's model is: an agent's default permissions get basic data, and anything sensitive is asked for, call by call. On `pupil-data` that isn't true today. A mandate below clearance 4 is refused outright, and one at clearance 4 or with no clearance at all gets every column, special category included. Checked live on 23 Nov: a no-clearance mandate allowed `pupil` at Brookmere returned P0050's name together with ethnicity, care status, free school meals and language. The tool grant already carries a level and the MCP server already strips columns above it, but because the clearance check refuses anything below the server's level, that stripping never removes anything.

## What Changes

- **`pupil-data` works at any clearance and returns only what the clearance covers.** At clearance 1 to 3 a call is allowed, and every column above the clearance is removed from the result, both by the MCP server (through the tool grant's level) and again by the gateway before release. Clearance 2: names and basic fields. Clearance 3: also free school meals and language.
- **Special category is asked for, call by call.** At clearance 4, a `pupil-data` call that would return level-4 columns (`search`, `pupil`, or `get` of the census file) is held with `202 STEP_UP` and reason `SPECIAL_CATEGORY`, and needs a person's approval of that exact call, like `special.*`. Counts (`aggregate`) stay under safe counts' rules instead.
- **Person-level tools need a clearance claim.** `pupil-data.pupil`, `roster`, `draft` and `write` are refused for a mandate without `clearance` (`CLEARANCE_MISSING`). The no-clearance exception stays only for `search`, `get` and `aggregate`, which the eval and the Day 2 default mandate use.
- **No clearance means basic data.** Those claim-less `search` and `get` results are stripped to level 2 (configurable with `GATEWAY_CLAIMLESS_LEVEL`, never above 4 by fallback). Safe counts are unchanged.

## Capabilities

### New Capabilities
- `graded-pupil-data`: stripping `pupil-data` results to the mandate's clearance, holding level-4 reads, and the person-level tools that need a clearance.

### Modified Capabilities
- `mandate-clearance`: `pupil-data` is no longer refused below clearance 4 (it is graded instead); the no-clearance exception on `pupil-data` no longer covers person-level tools.

## Non-goals

- No change to the eval's decisions or the Day 2 default mandate's allowed calls: their claim-less `search`, `get` and `aggregate` calls are still allowed; `search` and `get` now return basic data only.
- No change to the slices (`schools`, `directory`, `special`), which already serve one level each.
- No change to safe counts.

## Impact

- **Changed code:** `gateway/lib/interfaces.py` (graded server, person-level tools), `gateway/lib/gateway_verify.py` (the level-4 hold), `gateway/main.py` (strip before release).
- **Behaviour change:** a clearance-4 mandate's `search` and `pupil` calls are now held; to get non-special data without asking, issue clearance 3.
- **Questions:** 6 and 15 (clearance), 9 (approval). Day 2: closes the no-clearance `pupil` path to a named pupil's special category data.
