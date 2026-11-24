## 1. Data interface servers

- [x] 1.1 Create `data_slices/reader.py` with a manifest-driven `rows(table, max_level, keep=())`; verify with a unit test that census rows read at level 2 have no `Ethnicity`, `InCareAtCurrentSchool`, `FSMeligible` or `Language`
- [x] 1.2 Create `data_slices/schools.py` (`list`, `classification`); verify an in-process FastMCP test returns 12 schools with exactly `URN`, `SchoolName`, `SchoolLA`
- [x] 1.3 Create `data_slices/directory.py` (`roster`, `name`); verify tests that the SCH04 Y11 2023/24 SPR roster rows have exactly `Psuedo ID` and `DisplayName`, and that `name("P0586", "SCH04")` is empty
- [x] 1.4 Create `data_slices/special.py` (`record`); verify tests that `record("P0011", "SCH04")` has exactly the six spec keys and no `DisplayName`, and that `record("P0586", "SCH04")` is empty
- [x] 1.5 Create `data_slices/main.py` mounting the three apps at `/schools/mcp/`, `/directory/mcp/`, `/special/mcp/` with combined lifespans and a `/healthcheck`; verify `uv run uvicorn data_slices.main:app --port 8090` starts and `curl localhost:8090/healthcheck` returns ok

## 2. Container and routing

- [x] 2.1 Add `data_slices/Dockerfile` and a `slices` service to `docker-compose.yaml` (data mounted read-only, internal network, no `ports:`, health check); verify `docker compose up -d --wait slices` is healthy and `curl localhost:8090` from the host fails
- [x] 2.2 Extend the gateway's `MCP_SERVERS` in `docker-compose.yaml` with `schools`, `directory` and `special`, and make the gateway depend on `slices` being healthy; verify `docker compose up -d --build gateway` and `curl localhost:8082/describe` lists all four servers

## 3. Gateway clearance check

- [x] 3.1 Create `gateway/lib/interfaces.py` with `SERVER_LEVELS` and `check_clearance`; verify unit tests for each row of design decision 6 (missing on pupil-data, missing on an interface, invalid values including `true` and `"high"`, unknown server)
- [x] 3.2 Call `check_clearance` from `check_request` after deny globs and before scope, passing the verified claims; verify gateway tests for `CLEARANCE_TOO_LOW` (clearance 1 → directory, clearance 3 → pupil-data and special) and `IN_SCOPE` (clearance 2 → directory)
- [x] 3.3 Add `special.*` to the default step-up patterns; verify a gateway test that a clearance 4 `special.record` call returns `202 STEP_UP` with `SENSITIVE_TOOL` and is not forwarded
- [x] 3.4 Verify a gateway test that a `clearance` key in request arguments does not change the decision (clearance 1 mandate, argument `clearance: 4` → `CLEARANCE_TOO_LOW`)
- [x] 3.5 Add each server's level to `GET /describe`; verify a gateway test that the response includes the four levels
- [x] 3.6 Document `clearance` in `gateway/lib/mandate.schema.json`; verify the JSON still parses

## 4. Worked example for the check-in

- [x] 4.1 Write `docs/interface-slices.md` in the layout of `questions/02-worked-example.md`: a clearance 2 directory mandate, a clearance 1 newsletter mandate, one request each allows and denies with the real `cli issue` and `cli call` commands and outputs, and what is still unresolved; verify every command in it runs against the local stack and prints the shown decision

## 5. Final checks

- [x] 5.1 Run `make eval_run` and verify question 0 is 12/12 and the tally is unchanged at 27/32
- [x] 5.2 Run `make test` and verify the new and existing tests pass
- [x] 5.3 Run `make lint` and verify it passes
- [x] 5.4 Rebuild with `docker compose up -d --build gateway slices` and verify the spec scenarios against `:8082` with `cli call`
