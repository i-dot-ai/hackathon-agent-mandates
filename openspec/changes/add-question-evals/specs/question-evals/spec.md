## Purpose

A per-question eval of a running gateway. For every hackathon question, 0 to 16, it gives a PASS, a FAIL or a known GAP, and it checks what came back as well as the decision.

## ADDED Requirements

### Requirement: The eval runs against a live gateway with its own mandates
`make eval_questions` SHALL run `gateway/eval_questions.py` against `GATEWAY_URL` (default `http://localhost:8082`). Every mandate it uses SHALL be minted from the issuer state in `GATEWAY_STATE_DIR`, live at most 15 minutes, and use an agent key generated for the run. One key SHALL be used per question, so the per-key ceiling and `SELF_APPROVAL` see distinct agents. Every mandate it minted SHALL be revoked when the run ends, including when the run fails part way.

Before the cases run, a preflight call SHALL check that the gateway trusts the issuer state. If the gateway answers `ISSUER_NOT_ACCREDITED`, or doesn't answer at all, the run SHALL stop with one message naming `GATEWAY_STATE_DIR` and `GATEWAY_URL`, and exit non-zero.

#### Scenario: Wrong issuer state
- **WHEN** `GATEWAY_STATE_DIR` points at a state folder the gateway doesn't trust
- **THEN** the preflight's `search P0004` returns `403 ISSUER_NOT_ACCREDITED`, the eval prints "set GATEWAY_STATE_DIR to the gateway's issuer state" and exits 2 without running any case

#### Scenario: Mandates are cleaned up
- **WHEN** a run mints 60 mandates and a case raises an exception
- **THEN** all 60 status-list indices are revoked before the process exits

### Requirement: A case checks the decision and the result
Each case SHALL check the HTTP status and `decision.reason_code`. Where it names them, it SHALL also check:
- the number of rows;
- the columns returned;
- the pupils returned;
- the highest PII level of the columns, from the manifest.

For every case, whatever else it states:
- a response with status 500, or with no `decision.decision_id`, SHALL fail;
- a response whose `result` or `error` contains one of the Day 2 flag values (`Zara Okafor`, `0.2505`, `Mason Owusu`, `P0586`) SHALL fail, unless the case lists that flag as one it is entitled to.

The flag scan SHALL cover `result` and `error`, not the decision record, whose `detail` echoes arguments.

#### Scenario: Allowed search returns basic data only
- **WHEN** the default mandate (search at `SCH01`, no clearance) asks `pupil-data.search` with `query: "P0004"`, `urn: "SCH01"`
- **THEN** the result is `200 ALLOW IN_SCOPE`, every row's `Psuedo ID` is `P0004`, no column is level 3 or 4, and the case PASSES

#### Scenario: A flag in a refused-scope response fails the case
- **WHEN** a case not entitled to any flag gets a 200 whose result contains `Zara Okafor`
- **THEN** the case is FAIL, whatever its decision

### Requirement: Outcomes are PASS, FAIL and GAP, totalled per question
Every case SHALL end as PASS or FAIL. A case marked GAP SHALL be a probe of the behaviour we want:
- while it fails, it is reported as `GAP` and doesn't affect the exit code;
- when it passes, it is reported as `GAP-FIXED`, so the marker can be removed.

The eval SHALL print one line per case, then a total per question (`Question N: P pass, F fail, G gap`), like `gateway/eval.py`. It SHALL exit 1 if any case FAILED and 0 otherwise. Findings that are neither pass nor fail SHALL be printed as `NOTE` lines.

#### Scenario: Only GAPs fail
- **WHEN** every case passes except two GAP cases, which still fail
- **THEN** the eval prints `GAP` for both and exits 0

#### Scenario: A gap is closed
- **WHEN** a GAP case's probe starts passing
- **THEN** the eval prints `GAP-FIXED` for it and still exits 0

### Requirement: The flood case is opt-in and runs alone
The case for the unverified-source ceiling SHALL run only when `--flood` (or `EVAL_FLOOD=1`) is given, and then SHALL run alone, after the preflight, with no other case. Without the flag it is reported as a `NOTE`. When it runs, it SHALL send forged requests until the ceiling answers, and expect `429 RATE_LIMITED` with a `Retry-After` header. It is meant for a gateway started with a low `GATEWAY_LIMIT_CEILINGS_UNVERIFIED_PER_SOURCE_PER_MINUTE`.

#### Scenario: Default run
- **WHEN** `make eval_questions` runs without `--flood`
- **THEN** no forged flood is sent, and a NOTE says the ceiling case was skipped

### Requirement: Approval cases drive the real loop
Cases that need an approval SHALL go through the real loop:
- the held or refused call;
- `grants.request` through the gateway;
- a decision signed with an approver key and posted to the issuer, as `cli approve` does (or `grants.decide` for a supervising agent);
- `grants.status`;
- the retry with the minted mandate.

Cases that need limits wider than `officer:jsmith`'s SHALL use eval-only principals. These are added to `principals.json` and `approvers.json` at the start and removed at the end. Requests a case leaves pending SHALL be rejected at the end.

#### Scenario: A held write released once
- **WHEN** a mandate allowing `pupil-data.write` at `SCH01` calls `write`, gets `202 STEP_UP SENSITIVE_TOOL`, asks with `held`, and the eval approver approves with the right user code and key
- **THEN** the exact call with the minted mandate is `200 ALLOW PREAPPROVED` once, and the same call again is `202 SENSITIVE_TOOL`

### Requirement: Questions 0 to 5 match the organisers' eval and check results
The eval SHALL import `VALID`, `INVALID`, `BUILD` and the scopes from `gateway.eval`, and SHALL add result checks and edge cases:
- **0:** the 12 VALID calls are ALLOW. `search P0004` at `SCH01` returns only P0004's rows, with no level-3 or level-4 columns. A NOTE records that `query: "1_ENG"` returns 0 rows, because Language is level 3 and hidden without clearance.
- **1:**
  - `EXPIRED` for a mandate 2 minutes past `exp`, and for one 1 second past it (no grace period);
  - `NOT_YET_VALID` for an `nbf` an hour ahead;
  - `REVOKED`;
  - `PARENT_REVOKED` for a supplementary mandate whose parent is revoked.
- **2:** the INVALID cases, plus `directory.roster` at clearance 1, which is `CLEARANCE_TOO_LOW`. A GAP: a lone surrogate (`\ud800`) in an argument is refused (400, 403 or 422), not answered with a 500.
- **3:** an empty query, a whitespace query, limit `1000`, `"1000"` and `1000.0` are all `TOO_MUCH`. `query: ","` returns at most 100 rows.
- **4:** `./` and `//` spellings of the allowed file are ALLOW. `..`, a percent-encoded `..`, backslashes and an absolute path to the names file are refused.
- **5:**
  - a two-school mandate allows `SCH01` and `SCH02` and refuses `SCH03`;
  - with two entries constraining different arguments (urn on one, path on the other), a call can't take its urn from one entry and its path from the other.

#### Scenario: One second past expiry
- **WHEN** a mandate whose `exp` was 1 second ago is used for `search P0004` at `SCH01`
- **THEN** the result is `403 DENY EXPIRED`

#### Scenario: Mixed entries
- **WHEN** a mandate has `{search, urn: [SCH01]}` and `{get, path: [schools.csv]}`, and a `get` names `urn: SCH01` with the names file as `path`
- **THEN** the result is `403 CONSTRAINT_VIOLATED`

### Requirement: Questions 6 to 10 cover clearance, delegation, counts, held calls and plain words
The eval SHALL check:
- **6 (Castleton, SCH03):**
  - clearance 2 `pupil` returns a name with no level-3 or level-4 column;
  - clearance 4 `pupil` is `202 SPECIAL_CATEGORY` with no result;
  - `special.record` is held (`202 SENSITIVE_TOOL`) and released once after approval: `200 PREAPPROVED`, then held again.
- **7 (Dunmore, SCH04):**
  - a `can_delegate` supervisor approves a helper's `directory.roster` at SCH04 with `grants.decide`, and the minted mandate allows exactly that and refuses SCH02;
  - asking for `special.record` gets `EXCEEDS_SUPERVISOR`;
  - the helper approving its own request gets `SELF_APPROVAL`;
  - the supervisor revoked gets `APPROVER_REVOKED`;
  - the parent revoked gets `PARENT_REVOKED`;
  - the child shares the parent's `budget.distinct_pupils`.
  - GAP: a helper with a brand-new key can't get a first mandate without the person.
- **8:**
  - free school meals by URN: 12 rows, each a multiple of 5, none suppressed;
  - `where: {"Psuedo ID": "P0011"}`, or grouping by pupil: `COUNT_COLUMN_REFUSED`;
  - Ethnicity without clearance 4: refused;
  - three `group_by` columns: `COUNT_TOO_FINE`;
  - in care by URN at clearance 4: SCH07 has `count: null`;
  - with and without a `CensusTerm` filter, every count is a multiple of 5.
- **9:**
  - `write` is `202 SENSITIVE_TOOL`;
  - approved with the approver key, the exact call goes through once, and the same call again is held;
  - different arguments are held;
  - a decision posted with the URL and code but no key, or signed with a key that isn't the approver's, is refused, and the request stays `pending`.
- **10:**
  - `grants.self`'s summary names the school by name and says when the access ends ("Valid until …");
  - `grants.request`'s text has the approval URL and user code and says a chat reply doesn't approve it.
  - GAP: there is no way to draft a mandate from the person's sentence.

#### Scenario: Supervisor passes down part of its access
- **WHEN** the supervisor (`can_delegate`, `directory.roster` at SCH04, clearance 2) decides "approve" on the helper's request for `directory.roster` at SCH04
- **THEN** the helper's retry with the minted mandate is `200 ALLOW` with only `Psuedo ID` and `DisplayName` columns, and `directory.roster` at SCH02 with that mandate is `403 CONSTRAINT_VIOLATED`

#### Scenario: Approval without the key
- **WHEN** a decision is posted to the issuer for a pending request with the right user code but no signed decision
- **THEN** the issuer answers 401 `APPROVER_REQUIRED`, and `grants.status` still says `pending`

### Requirement: Questions 11 to 16 cover run limits, purpose, people, revocation, clearance and the log
The eval SHALL check:
- **11 (Elmwood, SCH05):**
  - with `budget.distinct_pupils: 3`, three `pupil` calls are ALLOW and the fourth is `429 BUDGET_EXHAUSTED` with no result;
  - a search that would cross the budget is withheld whole;
  - the same pupil again is ALLOW;
  - with `rate.per_minute: 2`, the third call is `429 RATE_LIMITED` with a `Retry-After` header;
  - for a mandate with no budget or rate claim, six refusals raise one `ALERT_REFUSALS` and leave the decisions unchanged;
  - three mandates receiving the same pupil raise `ALERT_PUPIL_TARGETED`, visible through `audit.events`. The pupil is a random quiet one, not P0004, whose hourly alert is already used up.
- **12:**
  - a letters mandate (`roster` and `draft` only) asking for in-care counts is `OUT_OF_SCOPE`.
  - GAP: two mandates for one school with different `purpose` should get different decisions for a purpose-unrelated call.
- **13:**
  - a request beyond the person's limits is `EXCEEDS_PRINCIPAL` (for the eval person `eval:shrink`, limited to SCH05).
  - GAP: a mandate should stop working after its person's limits shrink.
- **14:**
  - after three allowed searches and a revoke, `audit.saw` lists exactly those pupils, with `max_pii_level` and `revoked: true`;
  - the next call is `REVOKED` and is listed under `claimed`;
  - `cli audit anchor`, then `cli audit verify` on a snapshot of the audit store, reports the chain intact. If no snapshot can be taken, a NOTE says why.
- **15:**
  - a newsletter mandate at clearance 1: `schools.list` is 200, `directory.roster` is `CLEARANCE_TOO_LOW`, `pupil-data.search` returns level-1 columns only, and a pupil-ID search returns 0 rows;
  - counts at clearance 3: free school meals is 200, in care is `COUNT_COLUMN_REFUSED`;
  - `ASIA` and `2_OTH` searches return 0 rows below the clearance that shows them.
- **16:**
  - the person's own `audit.events` include `agent_id`, a source address and a `decision_id` matching the response;
  - another person's log is `CONSTRAINT_VIOLATED` (the person is `eval:questions`; the other person is `officer:jsmith`);
  - an operational mandate (no clearance) reading the log is `CLEARANCE_MISSING`;
  - forged calls carrying the person's `jti` appear under `claimed`.

#### Scenario: Pupil budget
- **WHEN** a mandate with `budget.distinct_pupils: 3` has received three pupils, and asks `pupil` for a fourth
- **THEN** the result is `429 DENY BUDGET_EXHAUSTED` and carries no `result`

#### Scenario: What a revoked mandate saw
- **WHEN** a mandate made three allowed searches for three pupils, was revoked, and then made one more call
- **THEN** that call is `403 REVOKED`, and `audit.saw` for its `jti` lists exactly the three pupils with `revoked: true`
