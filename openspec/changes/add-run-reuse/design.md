## Context

- `issuer/app.py` `create_request` verifies the agent's signed `grants.request`, refuses requests from supplementary mandates, returns `already_granted` when the requesting mandate itself covers the ask, checks the principal ceiling and throttles, then creates a pending request.
- The request store keeps, per request: `requester_jti`, `status`, `approved`, `held`, `minted_jti` and the minted token (`minted`).
- `gateway/lib/grants.py` `_request` turns the issuer's `already_granted` into `{"status": "already_granted", "next_action": "retry"}` and drops anything else.
- `scope_math.already_granted(claims, scope, clearance)` answers "does this mandate cover this ask".
- Requirements: `specs/run-reuse/spec.md`.

## Decisions

### 1. Reuse lives on the issuer, before throttles and ceiling
The lookup runs right after the existing "the requesting mandate already covers it" check, and before the principal ceiling and throttles. Reusing something the person approved is not a new ask, so it shouldn't count against "3 pending, 10 an hour".
- **Candidates:** approved requests with the same `requester_jti`, no `held`, a `minted` token, newest first.
- **Validity:** each candidate's token is re-verified with `verify_mandate` against the trusted list and the current status list. That catches expiry, the minted mandate's own revocation bit, and the parent's revocation (the parent check from the scope-requests change).
- **Coverage:** `already_granted(minted_claims, scope, clearance)`.
- The first match is returned.
- *Alternative:* reuse on the gateway, from the agent's presented mandates. Rejected: the gateway sees only the mandate on the call; the issuer has the run's history.

### 2. What the agent gets back
`{"status": "already_granted", "next_action": "retry", "mandate": ..., "mandate_jti": ..., "reused_request_id": ...}`. The gateway passes these through unchanged.
- The `grants.request` call itself is a normal audited call, so the person's log shows it.
- No `approval_*` event is sent, because nothing new was approved.

### 3. The run wallet is a client helper, not a server feature
`examples/mandate_wallet.py`:
- **State:** a small JSON file holding the base mandate path plus the minted tokens.
- **Choosing a mandate:** it decodes the mandates without verifying (the gateway verifies) and runs `check_request` on each to find one that allows the call, preferring supplementary mandates (narrower) over the base. If none allows it, it uses the base mandate, so the gateway's refusal and the `grants.check` missing grant come back as usual.
- **Adding:** a result containing a `mandate` adds it; expired tokens are dropped on load.
- *Alternative:* the gateway tries every mandate the agent holds. Rejected: the request shape carries one mandate.

## Risks / Trade-offs

- [Reuse widens nothing but extends exposure: an approved mandate lives until its TTL] → Unchanged from today: the person chose that TTL, and revocation stops reuse at once.
- [The status list read per candidate] → A run has a handful of approvals at most.
- [A stale wallet file holds expired mandates] → Dropped on load and at use; the gateway refuses them anyway.
