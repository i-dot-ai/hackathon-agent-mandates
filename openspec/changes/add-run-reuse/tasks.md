## 1. Issuer

- [x] 1.1 Add `approved_for(requester_jti)` to `issuer/store.py` (approved, not held, minted, newest first); verify a unit test
- [x] 1.2 In `create_request`, before the ceiling and throttles, return an earlier approval's minted mandate when it verifies and covers the ask (`already_granted` with `mandate`, `mandate_jti`, `reused_request_id`); verify the restart, narrower, wider, revoked, held-call and new-run scenarios

## 2. Gateway

- [x] 2.1 Pass `mandate`, `mandate_jti` and `reused_request_id` through `grants._request`'s `already_granted`; verify a gateway test that the agent receives the earlier mandate

## 3. Run wallet

- [x] 3.1 Write `examples/mandate_wallet.py` (load and save, drop expired, pick the narrowest covering mandate, add from results); verify the restart scenario in a test

## 4. Final checks

- [x] 4.1 `make test`, `make lint`, and `make eval_run` 32/32
