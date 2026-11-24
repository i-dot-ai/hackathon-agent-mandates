## Why

Within one job, an agent may need the same extra access several times: after a restart, in a second step, or because it lost the mandate an approval produced. Today each time is a new scope request, and the person is asked again for something they already approved minutes ago. That trains them to approve without reading (approval fatigue), which an attacker can exploit. Intent classification is out of scope: other teams and products already do it. What's missing is memory within a run.

## What Changes

- **A run is the base mandate and everything minted under it.** No new run ID: supplementary mandates already point at the base (`parent.jti`), die with it, and share its budget.
- **The issuer reuses an approval from the same run.** Before creating a pending request, it looks for an earlier approved request from the same base mandate whose minted mandate is still valid (signature, expiry, not revoked) and covers the new request's scope and clearance. If one does, it returns that mandate with `status: "already_granted"` and the reused `request_id`. The person isn't asked, nothing new is minted, and throttles don't count it.
- **The gateway passes the reused mandate to the agent.** `grants.request`'s `already_granted` result now carries `mandate`, `mandate_jti` and `reused_request_id` when an earlier approval was reused.
- **Never reused:** approvals that release one held call (single-use by design), anything wider than what was approved, and anything after the base mandate or the minted one is revoked or expired.
- **An agent-side run wallet** (`examples/mandate_wallet.py`): holds the base mandate and every supplementary one minted in the run, picks the narrowest mandate that covers each call, adds newly approved mandates, drops expired ones, and persists to a file so a restarted agent keeps its approvals.

## Capabilities

### New Capabilities
- `run-reuse`: what a run is, when the issuer reuses an earlier approval instead of asking, what is never reused, what the agent receives, and the wallet contract.

### Modified Capabilities
None in main specs. The `scope-requests` capability is still a pending change; this builds on its `grants.request` and issuer store.

## Non-goals

- No intent classification or labels, and no reuse across runs (a new base mandate asks again).
- No change to what an approval may grant, or to who may approve.
- No change to the `POST /tools/call` request shape.

## Impact

- **Changed code:** `issuer/app.py` (reuse lookup in `create_request`), `issuer/store.py` (approved requests per requester), `gateway/lib/grants.py` (pass the reused mandate through).
- **New code:** `examples/mandate_wallet.py` and its tests.
- **Questions:** 9 and 10 (fewer, clearer prompts), Day 2: removes the approval-fatigue path to "a mandate the target mints for you".
