## Context

See proposal.md for why. The relevant current state:

- `gateway/main.py` already routes by server name: `MCP_SERVERS` is parsed from `name=url,…`, and `tools_call` forwards to `MCP_SERVERS[body.server]` after an ALLOW. Scope entries already carry `server`. So routing to more servers needs configuration, not new mechanism.
- `check_request` in `gateway/lib/gateway_verify.py` runs deny globs, then scope and constraints, then step-up globs (`*.write`, `*.draft`). `Gateway.decide` passes it `claims["scope"]` and `claims["deny"]` after `verify_mandate` and the proof-of-possession check.
- `mcp_server/` reads data with helpers over the CSVs and has no access control. `pyproject.toml` describes it as a frozen hackathon fixture and excludes it from ruff, and other teams attack its `pupil-data` tools on Day 2.
- The manifest (`mcp_server/data/synthetic/synthetic_manifest.json`) assigns a level to every table and every column. It is the only source of levels we use.

## Goals / Non-Goals

**Goals:**
- Interface servers that cannot return a column above their level, even when called directly.
- A clearance check that is one lookup per call, placed so it can't be skipped by any scope shape.
- Zero change in behaviour for mandates without `clearance` on `pupil-data`.

**Non-Goals:** beyond the proposal's list, no new request fields, no changes to how mandates are issued (`cli issue --claims '{"clearance": 2}'` already works), and no result filtering of `pupil-data` responses.

## Decisions

### 1. A new `data_slices/` package, not changes inside `mcp_server/`
The three servers live in a new top-level package with one module per interface (`schools.py`, `directory.py`, `special.py`) and a shared `reader.py`.

- *Why:* `mcp_server/` is treated as a shared fixture. Leaving it untouched keeps our results comparable with other teams' and keeps `pupil-data` exactly as attackers expect it.
- *Alternative:* add the servers inside `mcp_server/api/` and mount them in `mcp_server/main.py`. Less Docker work, but it edits the fixture and puts the slices in the same process as the unrestricted server, which defeats the point.

### 2. Column limits enforced by a level-aware reader inside each server
`reader.py` loads the manifest once and exposes `rows(table, max_level, keep=())`. It drops every column whose manifest level is above `max_level` unless the column is named in `keep`. Each interface module calls it with its own constants and has no other way to open a file:

| Server | Reads | `max_level` | `keep` |
| --- | --- | --- | --- |
| `schools` | `schools`, manifest classification | 1 | – |
| `directory` | `display_names`, `personal_data_school_census` | 2 | – (cohort membership uses `URN`, `AcademicYear`, `CensusTerm`, `AgeAtStartOfAcademicYear`, `Psuedo ID`, all ≤ 2) |
| `special` | `personal_data_school_census` | 4, then projected | `Psuedo ID`, `URN`, `AcademicYear`, `CensusTerm`, `Ethnicity`, `InCareAtCurrentSchool` (explicit allow-list) |

Each tool also projects its output to the exact keys in the spec, so a future column added to the data can't leak through by default.

- *Why:* the limit lives with the data access, not in the gateway, so bypassing the gateway still yields one slice. Reading levels from the manifest means there's one source of truth.
- *Alternative:* hand-written column lists per tool only. Simpler, but a new sensitive column would be returned until someone noticed. We do both: the reader drops by level, and each tool projects to an allow-list.

### 3. One `slices` container, three mounted apps
`data_slices/main.py` builds one Starlette/FastAPI app that mounts each FastMCP `http_app` at `/schools/mcp/`, `/directory/mcp/` and `/special/mcp/`. A new `slices` service in `docker-compose.yaml` runs it on port 8090 with `./mcp_server/data` mounted **read-only**, on the internal network, with **no `ports:` mapping**. The gateway's `MCP_SERVERS` becomes `pupil-data=http://backend:8080/mcp/,schools=http://slices:8090/schools/mcp/,directory=http://slices:8090/directory/mcp/,special=http://slices:8090/special/mcp/`.

- *Why:* a separate process from `pupil-data` with read-only data and no host port. One container keeps the build small for Day 1.
- *Alternative:* one container per interface. That's the real end state (a compromise of one interface server can't read another's columns). It's a compose-only change later, listed as Day 2 hardening.

### 4. Levels are gateway policy in a new `gateway/lib/interfaces.py`
`SERVER_LEVELS = {"pupil-data": 4, "schools": 1, "directory": 2, "special": 4}` and a function `check_clearance(server, claims) -> (decision, code, detail) | None`.

- *Why:* the gateway, not the server, decides who may call what; the server's own limit is the second line. A constant is reviewable and can't be changed by a request.
- *Alternative:* ask each server for its level at startup or in `/describe`. That makes the server the authority for its own permission, which a compromised server could lie about.

### 5. Check order: deny → clearance → scope → step-up
`check_request` gains the claims and calls `check_clearance` after deny globs and before the scope loop.

- *Why:* clearance is cheaper than scope and doesn't depend on scope shape, so no combination of scope entries can route around it. Deny still wins first, as today.
- *Trade-off:* a call that is both out of scope and above clearance reports `CLEARANCE_TOO_LOW`, not `OUT_OF_SCOPE`. Both deny; the clearance reason tells the issuer more.

### 6. Rules for a missing or bad claim
| Mandate | Server | Result |
| --- | --- | --- |
| No `clearance` | `pupil-data` | No check: today's behaviour |
| No `clearance` | interface server | `CLEARANCE_MISSING` |
| `clearance` not an int 1–4 (booleans rejected) | any | `CLEARANCE_INVALID` |
| Any | server not in `SERVER_LEVELS` | `UNKNOWN_SERVER` |

`UNKNOWN_SERVER` replaces today's late `404` in `tools_call` for unrouted servers with a decided `403` and a reason code.

### 7. Step-up for `special` by glob
The gateway's default step-up patterns become `["*.write", "*.draft", "special.*"]`.

- *Why:* reuses the existing step-up path, so no new code path; until question 9's approval flow exists, `special` returns nothing, which is the safe default.

### 8. Failure mode
Fail closed throughout: an unknown server, a bad claim or a missing claim on a new server all deny. If the `slices` container is down, an ALLOWed call returns the existing `502` from `tools_call` and no data. `/describe` lists servers by connecting to each; if `slices` is down it fails as it does today for `pupil-data`. That's acceptable for discovery but noted.

## Risks / Trade-offs

- [Pupil IDs are the same across servers, so an agent holding `directory` and `special` can join name and care status] → `special` always steps up in this change; pseudonyms per mandate are the follow-up.
- [`pupil-data` stays level 4 and unrestricted for mandates without `clearance`] → by design for the eval and Day 2; our feature mandate carries `clearance` and so loses `pupil-data` below 4.
- [Mounting three apps in one process shares memory and the data mount] → read-only mount and per-module reader constants; separate containers on Day 2.
- [FastMCP http apps each need their lifespan run] → combine lifespans with `fastmcp.utilities.lifespan.combine_lifespans`, as `mcp_server/main.py` already does.
- [`/describe` now depends on the `slices` container] → gateway health check is unaffected; describe failing when a server is down is existing behaviour.

**Day 2:** closes attacks on our feature mandate that reach level 3 or 4 data through a broad scope (Sensitive PII 20, Special category 40 points), because the clearance check refuses the server outright. Opens three new servers to probing; they have no host port, take no path argument, and project to fixed keys. The "4, named" flag (name plus care status, 60 points) stays blocked only because `special` steps up.

## Migration Plan

Additive. Deploy order: build and start `slices`, then rebuild the gateway with the new `MCP_SERVERS`. Rollback: remove the three entries from `MCP_SERVERS`; mandates using them then get `UNKNOWN_SERVER`, and `pupil-data` is unaffected.
