## Why

The organisers' `make eval_run` checks decisions only, and only for questions 0 to 5. Today it is 32/32. Most of what we built since then decides what comes *back*: graded columns, safe counts, budgets, approvals, the audit trail. None of that is checked against the live gateway. On Day 2 other teams attack the deployed gateway and score on data that leaves it, so before then every question (0 to 16) needs evidence: PASS, FAIL, or a GAP we know about.

## What Changes

- New `gateway/eval_questions.py` and `make eval_questions`. One run fires cases for questions 0 to 16 at `GATEWAY_URL` (default `http://localhost:8082`). It mints its own short-lived mandates from the local issuer state (`GATEWAY_STATE_DIR`) and revokes them afterwards.
- Each case checks the decision and `reason_code`, and also the result: row count, columns, pupils, the highest PII level, and that no Day 2 flag value (`Zara Okafor`, `0.2505`, `Mason Owusu`, `P0586`) reaches a response not entitled to it. Every response must carry `decision.decision_id`, and no case may get a 500.
- Three outcomes:
  - **PASS**.
  - **FAIL**: the run exits non-zero.
  - **GAP**: a known gap, written as a probe of the behaviour we want. It is printed but doesn't fail the run, and it is reported as *fixed* when it starts passing.
  - Findings that are neither, such as `query="1_ENG"` returning 0 rows, are printed as notes.
- Approval cases drive the real loop: `grants.request`, then `cli approve` with an approver key, then a retry. The supervisor path uses `grants.decide`.
- The forged-flood case (the unverified-source ceiling) runs only with an opt-in flag, so a normal run never blocks the machine's address for a minute.
- `day_2_attack/self_attack.py` becomes import-safe. Its helpers (`mint`, `signed`, `post`) take a key, ttl, principal and org, and `post` also returns headers. Its behaviour as a script is unchanged.
- `gateway/eval.py` and `make eval_run` are **not** changed. The new eval imports their `VALID`, `INVALID` and `BUILD` cases.

**Question 0 and mandates without the new claims.** Nothing changes in the gateway. Mandates without a clearance, budget or rate claim behave exactly as before, and the eval checks that question 0's twelve calls stay ALLOW.

## Capabilities

### New Capabilities
- `question-evals`: a per-question eval of the live gateway. It checks decisions and results for questions 0 to 16 with PASS/FAIL/GAP outcomes, using its own mandates and the real approval loop. Layer: verification and evidence, across all layers.

### Modified Capabilities
(none)

## Non-goals

- Changing any gateway decision. Where the eval shows a gap, it records it as GAP and the fix is separate work.
- Replacing or editing `gateway/eval.py` and `make eval_run`, which other teams compare against.
- Attacking other teams' gateways. The eval needs this laptop's issuer key, so it works only against a gateway that trusts it.
- Long waits. Expiry is tested with mandates that are already expired or not yet valid, not by sleeping.
- Rebuilding or stopping the shared containers.

## Impact

- New: `gateway/eval_questions.py`, `gateway/tests/test_eval_questions.py`, a `make eval_questions` target.
- Changed: `day_2_attack/self_attack.py` (refactor only).
- Shared state touched at run time:
  - Eval-only principals and approver keys are added to `gateway/state/principals.json` and `approvers.json`, and removed again when the run ends. `officer:jsmith` is never edited.
  - Mandates are minted into `status_list.json` and revoked.
  - The approved question 9 write appends one tagged line to `mcp_server/data/writes/corrections.jsonl` (outside `synthetic/`).
  - Audit events are added to the gateway's chain.
