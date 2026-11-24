## Why

Today one MCP server (`pupil-data`) can read every data file, and a single tool can return a pupil's name next to their ethnicity and care status. A mandate can narrow tools and argument values, but nothing in it or in the gateway says how sensitive the data behind a tool is, so every mandate is one scope mistake away from special category data. We want permission sliced thin on every layer; the first and cheapest slice is the interface itself: each data server can only express one data class, and a mandate states the highest class it is cleared for.

Addresses questions **6** (classification) and **15** (PII clearance) directly, and lays the ground for **12** (purpose) and **11** (many small calls). Layer: **0, interface segregation** (Gateway Security Layers design).

## What Changes

- Add three data-interface servers, each limited to one data class, reachable only through the gateway:
  - `schools` (level 1): the schools list and the classification table.
  - `directory` (level 2): pseudo IDs and display names, for one cohort or one pupil.
  - `special` (level 4): ethnicity and care status for one pupil per call, with no name.
- Each interface server can read only the columns at or below its level (plus the keys it needs), enforced inside the server, so a call that bypasses the gateway still gets one slice.
- The gateway assigns every server a data level and adds a top-level mandate claim, `clearance` (1 to 4). A mandate may only call servers whose level is within its clearance.
- Every call to `special` is held for approval (`202 STEP_UP`).
- New stable reason codes: `CLEARANCE_MISSING`, `CLEARANCE_TOO_LOW`, `CLEARANCE_INVALID`, `UNKNOWN_SERVER`.
- `GET /describe` lists each server's data level.
- `pupil-data` is unchanged and keeps its tools. It counts as level 4.

**Mandates without `clearance`** keep today's behaviour on `pupil-data`: no clearance check, so question 0, the eval and the Day 2 default mandate are unaffected. The same mandates are refused on the new servers with `CLEARANCE_MISSING`. New servers fail closed.

## Non-goals

- The other planned interfaces (`census`, `stats`, `letters`, `corrections`). They follow once this slice works.
- Pseudonyms per mandate. Pupil IDs stay the same across servers in this change, so two slices can still be joined by an agent that holds both.
- One OS process per interface. All three run in one new container; splitting them is Day 2 hardening.
- Changing `pupil-data`, the data files, or the frontend.
- Fixing questions 3 to 5. They go on a separate branch.
- Issuer-side checks that a person may grant a given clearance (question 13).
- An approval flow for `STEP_UP` (question 9).

## Capabilities

### New Capabilities
- `data-interfaces`: the segregated data servers, what each one returns through the gateway, and the column limits each one enforces.
- `mandate-clearance`: the `clearance` claim, the server-to-level map, and the gateway decisions and reason codes that follow from them.

### Modified Capabilities
None. There are no existing specs in `openspec/specs/`.

## Impact

- **New code:** a `data_slices/` package with the three FastMCP servers and a level-aware data reader; a gateway module for server levels and the clearance check.
- **Changed code:** `gateway/lib/gateway_verify.py` (clearance check and `special.*` step-up), `gateway/main.py` (`/describe` levels), `gateway/lib/mandate.schema.json` (documents `clearance`).
- **Infrastructure:** a new `slices` container in `docker-compose.yaml` with the data folder mounted read-only and no published port; the gateway's `MCP_SERVERS` gains three entries.
- **Untouched:** `mcp_server/` and its data, `frontend/`, the `POST /tools/call` request shape.
- **Day 2:** gives us a feature mandate that refuses special category data by clearance; adds three servers to the attack surface.
