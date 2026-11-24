## 1. Hint

- [x] 1.1 Say "put every pupil in one call" in the `draft` tool description, and that held calls can be passed as one list in `grants.request`'s description and `grants.check`'s hint; verify a test reads them through `/describe` and `grants.check`

## 2. Batch release

- [x] 2.1 Accept `held` as one object or a list of 1 to 50 in `grants.request` (gateway) and the issuer, refusing empty, over-long, duplicate or foreign entries with `REQUEST_INVALID`; verify the refusal scenarios
- [x] 2.2 Summarise, store and mint a batch: one entry per distinct held-call shape, one pre-approved action hash per call, old single-object rows read as a list of one; verify the three-drafts-one-prompt and released-once-each scenarios
- [x] 2.3 List every held call on the approval page (`held_actions`), keeping `held_action` for a single call; verify the 25-pupil scenario and `npm run build`

## 3. Final checks

- [x] 3.1 `make test`, `make lint`, and `make eval_run` 32/32
