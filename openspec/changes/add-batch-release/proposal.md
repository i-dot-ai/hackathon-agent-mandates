## Why

A job like "write letters for these 25 absent pupils" should cost the person one approval. `draft` is always held, and a held call is released only by approving that exact call, so it costs one approval only if the agent happens to put all 25 pupils in one call. An agent that drafts one pupil at a time produces 25 held calls, 25 requests and 25 prompts, and the request throttle stops it after 3. That is approval fatigue by accident, and it makes the safe path (asking) the annoying one.

## What Changes

- **A hint to batch.** The `draft` tool says to put every pupil in one call. `grants.check`'s hint for a held call and `grants.request`'s description say several held calls can be released together.
- **Several held calls, one approval.** `grants.request` accepts `held` as one held call (as before) or a list of 1 to 50. Each must be a call this mandate made and had held, with its exact arguments, named once.
- **One approval page for the batch.** It lists every held call in plain words, and the person approves or rejects them together.
- **Each released call still goes through once.** The minted mandate pre-approves one action hash per held call. Each call is allowed once; repeating one, or making a call that wasn't in the batch, is held again.

## Capabilities

### New Capabilities
- `batch-release`: the batching hint, `held` as a list, the approval page for a batch, and the once-each rule for released calls.

### Modified Capabilities
None in main specs (`scope-requests` is still a pending change; this extends its `held` argument).

## Non-goals

- No change to which tools are held. Whether `draft` should be held at all, or only sending, is a separate team decision.
- No approving a class of calls ("any draft for these pupils"): only the exact calls named.
- Release approvals are still never reused within a run (`add-run-reuse`).

## Impact

- **Changed code:** `gateway/lib/grants.py` (validate a list), `issuer/app.py` (store, summarise, view and mint a list), `mcp_server/api/routes_mcp.py` (the `draft` description), `frontend/src/components/ApprovalRequest.svelte` (list the held calls).
- **Compatible:** a single `held` object works as before; requests stored with the old shape are read as a list of one.
- **Questions:** 9 and 10. Day 2: removes the many-prompt path that invites approving without reading.
