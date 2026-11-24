## 1. Helpers

- [x] 1.1 Make `day_2_attack/self_attack.py` import-safe: build `agent`, `M` and `CASES` inside `run()`; give `mint` `key`/`ttl`/`principal`/`org`/`purpose` and `signed` a `key`; add `post_full` returning headers. Verify `python -m day_2_attack.self_attack` still runs and prints the same groups

## 2. Eval harness

- [x] 2.1 Write `gateway/eval_questions.py`:
  - the case model (PASS/FAIL/GAP/GAP-FIXED, NOTE);
  - the generic checks (no 500, `decision_id`, flags in `result`/`error` only);
  - the `expect()` helper;
  - the per-question totals and exit code;
  - the preflight;
  - cleanup in `finally`.
- [x] 2.2 Add the eval principals and approver keys (add at start, remove at end), the approval-loop helpers (`grants.request`, the signed decision as `cli approve` does it, `grants.status`), and the audit snapshot and verify helper
- [x] 2.3 Add `make eval_questions` (passes `GATEWAY_URL`, `GATEWAY_STATE_DIR`, and `EVAL_ARGS` such as `--flood`)

## 3. Cases

- [x] 3.1 Questions 0 to 5: import `VALID`, `INVALID` and `BUILD` from `gateway.eval`, then add the result checks, the 1-second, `nbf` and parent-revoked cases, the bulk spellings, the paths, and the mixed entries
- [x] 3.2 Questions 6 to 10: clearance and special category with approval, supervisor delegation, safe counts, held writes and approval refusals, plain words; the Q7 and Q10 GAPs
- [x] 3.3 Questions 11 to 16: budgets, rates and alerts, purpose (GAP), principals and the shrink (GAP), revoke with `audit.saw` and anchor/verify, newsletter and counts clearance, the request log; the opt-in flood

## 4. Tests

- [x] 4.1 `gateway/tests/test_eval_questions.py`: importing mints nothing and makes no network call; PASS, FAIL, GAP and GAP-FIXED map to the right exit code and totals; the flag scan ignores the decision record

## 5. Run and check

- [x] 5.1 Run `make eval_questions` against :8082 with no FAIL. Fix any expectation the code contradicts, and record each change in the run notes
- [x] 5.2 `make eval_run` is unchanged at 32/32; `make test`, `make format` and `make lint` pass
- [x] 5.3 Gateway container rebuild: not applicable. This change edits no gateway code, and the shared stack on :8082 must not be rebuilt by this session
