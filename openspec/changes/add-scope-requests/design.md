## Context

- `POST /tools/call` runs `Gateway.decide`, then forwards an allowed call with `fastmcp.Client(target)`. `target` is a URL string from `MCP_SERVERS`, or an in-process `FastMCP` instance in tests. Nothing is sent to the server except the tool call.
- The MCP server on `:8080` is published to the host and has no access control. The slices container has no published port but trusts every caller on the Compose network.
- `gateway/state/` holds the issuer private key. It is mounted into the gateway, and `/demo/mandate` and `/demo/revoke` use it with no login.
- STEP_UP is final today. `special.*` and `*.write` or `*.draft` calls are held and can never be released.
- **The audit trail is implemented on `ihor`** (`gateway/lib/audit.py`, as of 23 Nov). It provides:
  - **Storage:** a SQLite store at `GATEWAY_AUDIT_DB` on the `gateway-audit` volume, or memory without it. Postgres isn't available where we deploy.
  - **`decision_id`:** `tools_call` assigns it right after `decide_with_context` and before `_forward`.
  - **`_forward(body)`:** dispatches `server == "audit"` in process, and everything else to `Client(target)`.
  - **`record_external(event_type, jti, server, tool, ref_decision_id, reason_code, principal, agent_id)`:** accepts only the four `APPROVAL_EVENTS`.
  - **`history(jti)`:** built from verified decision events.
  - **`MANDATE_MALFORMED`:** the catch-all.
  - **`summarise(data)`:** scores a flat dict whose keys aren't manifest columns as level 4. A document (nested values) scores level 1, or 2 with pupil IDs.
- **The question 3–5 fixes are in `check_request`:** any matching entry is tried; `path` is compared after `normpath`; `limit` must be an integer from 0 to `MAX_ROWS = 100`; a blank `search` query is refused. The reason code for the last two is `TOO_MUCH`.
- **`frontend/`** (Astro 7, Svelte 5, Node adapter, GOV.UK styles) has a demo page and a server-side proxy, `src/pages/api/demo/[...path].ts`, so the browser never calls the gateway. Its middleware uses the i.AI Auth API, from the `x-amzn-oidc-data` header, outside local. Organisers approved changes to `frontend/` on 23 Nov.
- fastmcp 4.2.3's `StreamableHttpTransport(url, headers=...)` sends extra HTTP headers, so the grant can travel without changing the tool arguments.
- Requirements: `specs/scope-requests`, `specs/tool-grants`, `specs/mandate-audience`, and the `mandate-clearance` delta.

## Goals / Non-Goals

**Goals:**
- Two scoped hops: the agent to the gateway by the mandate (as now, plus audience), and the gateway to the tool by a tool grant. Each side checks its own hop and doesn't trust the other.
- One approval path for both kinds of escalation: wider scope, and releasing a held call.
- The issuer key leaves the gateway.
- Audit stays one system. This change only calls into it.

**Non-Goals:**
- Changing how the audit trail stores, chains or exposes events.
- Making approvals survive a gateway or issuer restart, beyond what the audit store and the issuer's own file give.
- Any rendering in specific MCP hosts.

## Decisions

### 1. `grants` is a gateway-handled server, like `audit`
Tools: `self`, `check`, `request`, `status`, `decide`.
- The normal pipeline runs first: mandate, signature, deny, clearance at level 1. Then a fixed implicit rule allows every `grants` tool for the calling mandate, instead of requiring a scope entry.
- `tools_call` dispatches `server == "grants"` to `grants.handle(tool, arguments, claims, audit_ctx)`, next to the `audit` dispatch.
- *Why:* replay protection, request signatures and audit recording come free, and the request shape stays fixed.
- *Alternative:* REST endpoints (`POST /scope-requests`). Rejected: they'd need their own signature and replay checks, and the audit change would have to learn a second entry point.

### 2. `grants.check` reuses `check_request` without side effects
It verifies the mandate claims the agent presented, then runs the same `check_request`, clearance and audience functions on the hypothetical call. It never forwards, never mints a grant, and doesn't consume a nonce for the hypothetical call. Only the `grants.check` call's own nonce is used.
- The missing grant is computed by entry type:
  - `OUT_OF_SCOPE`: a new entry for the server and tool, with the call's constrained-argument values.
  - `CONSTRAINT_*`: the closest entry with the offending value added.
  - `CLEARANCE_TOO_LOW`: the server's level.
  - `AUDIENCE_VIOLATED`: the closest entry with the pupil added.
  - `STEP_UP`: the action hash.
- `grants.check` is itself recorded by audit. Its result lists only grants, never pupil data.

### 3. A separate issuer service owns the issuer key
New container `issuer` (FastAPI), mounting `issuer_key.pem`, `status_list.json` and the principals and approvers files. It serves:
- `POST /requests` and `POST /requests/{id}/supervisor-decision`: internal only. The gateway forwards the agent's or supervisor's signed call bodies unchanged.
- `GET /requests/{id}`: status, and the minted mandate once approved.
- `GET /requests/{id}/view`, `POST /approver/login` and `POST /requests/{id}/decision`: JSON endpoints for the approval page in `frontend/`. No HTML is served by the issuer (decision 5a).
- `POST /revoke`.
- The status list, `status_list.jwt`, which it writes to a shared read-only volume the gateway reads as today.

The gateway's mount shrinks to `trusted_list.json`, `status_list.jwt`, `tool_grant_key.pem` and the audit key.
- *Why:* minting is what approval produces. Keeping it on the internet-facing gateway would put the issuer key back where the Codex review said it must not be.
- *Alternative:* the gateway mints with a delegated sub-issuer key in `trusted_list.json`. Rejected: any gateway bug becomes a forged-mandate bug.
- **Zero trust on this hop too.** The issuer never acts on the gateway's word.
  - To create a request, the gateway forwards the agent's signed `POST /tools/call` body for `grants.request` unchanged. The issuer re-verifies it: its own signature on the mandate, dates, revocation, the agent's request signature, and the nonce in its own seen set.
  - To mint, the issuer needs a decision it verified itself. A person's decision arrives directly on the issuer, from the page or CLI, with the approver key. A supervisor's `grants.decide` body and mandate are forwarded unchanged and re-verified the same way.
  - A compromised gateway can therefore relay and delay, but not create, approve or widen a request.
- The CLI's `issue` and `revoke` keep working locally. They write the same files the issuer service reads.

### 4. Where requests live
Scope requests are a small table in the issuer service: `id`, `requester_jti`, `requester_agent_id`, `principal`, the requested grant (canonical JSON), the reason, `match_number` and `match_options` (the number the person must choose and the three shown, in a fixed shuffled order), `end_reason` (`NUMBER_MISMATCH` when a wrong number ended it), `created`, `expires`, `status`, `decided_by`, `minted_jti`. It lives in SQLite at `issuer/state/requests.db`, because the issuer must survive alone, and SQLite gives one-decision-only through a `status='pending'` conditional update. The gateway calls the issuer over the Compose network for create, status and decide. Request throttling (pending count, requests per hour, identical recent rejection) reads this table, not `history(jti)`, which has no such counts.
- *Alternative:* Postgres. Not available where we deploy (the same reason the audit trail uses SQLite).

### 4a. Issuer events reach the audit chain
`record_external` runs inside the gateway, but a person's decision happens on the issuer. So the issuer signs each event (`approval_requested`, `approval_granted`, `approval_denied`, `approval_expired`, the four types `record_external` accepts) with its issuer key. A person's refused decision isn't one of these, so it stays in the issuer's request log. A supervisor's refused `grants.decide` is audited as that call's own event. It posts them to an internal gateway endpoint, `POST /internal/audit-events`, reachable only on the Compose network. The gateway verifies the issuer signature against `trusted_list.json` and calls `record_external`.
- The issuer keeps an outbox in SQLite and retries until the gateway acknowledges the event. Events reach the chain even if the agent never polls.
- An unsigned or wrongly signed post is refused, so nobody else can write approval history.
- *Alternative:* the issuer writes to the audit store directly. Rejected: two writers to one hash chain, and the audit change owns the store.

### 5. Approver identity: a key per person, used two ways
`cli approver keygen --principal officer:jsmith` makes an Ed25519 approver key and registers its public half in the issuer's `approvers.json`. The person approves in one of two ways:
- **CLI:** `cli approve <request_id> --approver-key ...`. It signs `{request_id, decision, approved_grant_hash}`.
- **Page:** `cli approver-login --principal ... --approver-key ...` prints a one-time login link. It is a token signed by the approver key, valid for 5 minutes and single use. Opening it sets an HTTP-only session cookie on the issuer page.

The agent never holds an approver key. URL and number are only identifiers: the number lets the person match the page to what the agent said, and a wrong one ends the request.
- *Alternative:* WebAuthn passkeys. They're the right production answer, but too much for Day 1. The flow stays the same when they replace the key.
- *Alternative:* trust the network or a shared password. Rejected: it reproduces `/demo/mandate`.

### 5a. The approval page lives in `frontend/`, with no authority
- **Pages:**
  - `src/pages/approve/[id].astro`, with a Svelte component `ApprovalRequest.svelte`;
  - `src/pages/approve/login.astro`, which takes the one-time login token from the CLI link.
- **Proxy:** `src/pages/api/approve/[...path].ts` forwards to the issuer, mirroring `api/demo/[...path].ts`. It relays the issuer's approver-session cookie as an HTTP-only, `SameSite=Strict` cookie on the UI origin, scoped to `/approve`. The browser never calls the issuer.
- **`approval_url`** is `${FRONTEND_URL}/approve/{id}`.
- **Reason text** is rendered with Svelte text interpolation only (escaped), never `{@html}`. The summary and argument wording come from the issuer's view JSON.
- **The UI decides nothing.** Its Approve, Reject and Narrow buttons post to the issuer, which checks the approver session and the ceiling.
  - Where the UI's own i.AI sign-in is active, it's an extra gate on the page, not approver authentication.
  - Approval pages are excluded from the UI's public paths, so its sign-in still applies when configured.
- *Why the frontend:* it already has the proxy pattern, GOV.UK styling and a sign-in layer, and organisers allowed changing it. The issuer stays an API with a small attack surface.
- *Alternative:* HTML served by the issuer. Rejected now that the UI can change: two web surfaces to secure instead of one.

### 6. The principal ceiling
`issuer/state/principals.json` maps principal → {servers, tools, urns, max clearance}. It is checked at request time, so the agent sees `EXCEEDS_PRINCIPAL` immediately, and again at mint time, in case the file changed. A principal with no entry has no ceiling to grant from, and every request is refused. This is the hackathon stand-in for a real entitlement source (question 13).

### 7. The supplementary mandate shape
```json
{
  "cnf": {"jwk": "<same as parent>"},
  "delegator": "<same as parent>",
  "scope": ["<approved entries>"],
  "deny": "<parent deny>",
  "clearance": "<approved, or parent's>",
  "exp": "min(parent.exp, now + approved_ttl)",
  "parent": {"jti": "...", "status": {"uri": "...", "idx": 7}},
  "approved_by": {"kind": "person", "id": "officer:jsmith", "request_id": "sr_..."},
  "preapproved": ["sha256:<action hash>"],
  "purpose": "<gateway-generated summary>"
}
```
- `verify_mandate` gains one step after the revocation check: if `parent` is present, check its bit on its status list, giving `PARENT_REVOKED` or `STATUS_UNAVAILABLE`. One level only (non-goal: deeper chains).
- The agent keeps both mandates and chooses per call. The MCP shim tries the base mandate first, and any unexpired supplementary one on refusal.
- *Alternative:* re-issue the parent, wider. Rejected: it widens standing access, and the old mandate must be revoked in step.

### 8. Action hash for held calls
`action_hash = sha256(canonical({server, tool, arguments, mandate_hash: parent_mandate_hash}))`. Unlike `request_hash`, it leaves out the nonce and `ts`. That is the Codex finding that approval couldn't replay the held request.
- **The audit trail never stores argument values, so the request carries them again.** `grants.request` for a held call sends the `decision_id` plus server, tool and full arguments. The gateway checks them against the held event: same mandate, decision `STEP_UP`, same server and tool, and the same argument hash. The approval page shows the arguments in plain words, and the issuer computes the `action_hash` from them.
- **Single use is the gateway's own record, not audit history.** `history(jti)` has no lookup by action hash. A small `preapproval_uses(jti, action_hash, decision_id)` table lives in a gateway SQLite file next to the audit database, on the same `gateway-audit` volume (`GATEWAY_STATE_DB`), otherwise in memory. It is written, under a unique key, before the call is forwarded.
- A pre-approved mandate also expires 5 minutes after approval, which bounds the damage if the memory store loses a use on restart.

### 9. Tool grant mint and verify live in one shared module
`gateway/lib/tool_grant.py` has `mint(claims, entry, req, decision_id, level)` and `verify(token, server, tool, args)`. The MCP server image and the slices image both copy this file, the way `reader.py` is shared.
- **Transport:** the gateway builds `Client(StreamableHttpTransport(url, headers={"X-Tool-Grant": token}))` for URL targets. In-process `FastMCP` targets (tests) get no header.
- **Server side:** a Starlette middleware on each MCP HTTP app reads the JSON-RPC body:
  - for a `tools/call`, it verifies the grant against the tool name and arguments, and puts the verified grant in a context variable;
  - for `initialize` and `tools/list`, it passes them through, so `/describe` keeps working.

  Tool functions read the grant from the context variable. Before running, `check_args(grant, arguments)` re-checks `urn`, `pupil_id`, `pupil_ids` and constrained arguments, giving `GRANT_SCOPE`. This is the only school check for `roster` and `draft`, whose output has no URN. After running, one helper applies subjects, level and `max_rows`: `enforce(rows, grant, table)` for row lists, and `enforce_one` for single records.
- **Seen `jti`s:** an in-memory set per server, kept for 60 s, twice the grant lifetime.
- **Test bypass:** `TOOL_GRANTS=off` disables the middleware for local debugging. Unset means `enforce`, and any other value stops the app from starting, so turning grants off always takes an explicit setting. Compose sets `TOOL_GRANTS=enforce`. Unit tests call tool functions in process, so they need neither.
- **Key distribution:** `cli init` and `cli grant-key` (run by `make hack`, `make run` and `make grant_key`) create `tool_grant_key.pem` and `tool_grant.pub` in `gateway/state`. Compose mounts only the `.pub` into the servers. The gateway also creates the pair on startup if it's missing.
- *Alternative:* put the grant inside the tool arguments. Rejected: the agent's arguments are then partly gateway-written, and the `args_hash` must exclude it.
- *Alternative:* mTLS between gateway and servers. It proves who is calling but carries no scope. Complementary, and out of scope here.

### 10. Separate keys by purpose
- `issuer_key.pem`: issuer service only. It signs mandates, the status list and approval events.
- `tool_grant_key.pem`: the gateway signs grants; servers hold the public half.
- The audit chain key: owned by `add-audit-trail`.

No separate key authenticates the gateway to the issuer. The issuer re-verifies the signed bodies it receives (decision 3), so a channel key would add nothing.

Different keys and different JWT `typ` values mean one leaked key doesn't mint another kind of token.

### 11. Audience check and tool enforcement are the same data
The gateway's `AUDIENCE_VIOLATED` check covers argument-named pupils. Pupils that appear only in results (`search`, `roster`) are left to the tool, through `subjects.pupils` in the grant. The gateway then summarises the filtered result for audit, as `add-audit-trail` already does. So the audit event records what really left, not what the server would have sent.

### 12. Fitting `add-audit-trail`
The audit change is now on `ihor`. This change uses:
- `decision_id`, as the tool grant's `jti`. It's already assigned before forwarding; `_forward` only needs it passed in;
- `record_external` for `approval_*` events, fed by the issuer through decision 4a;
- the held call's audit event (server, tool, argument hash, decision), to validate a request about a held call;
- `decide_with_context` for verified claims;
- the `MANDATE_MALFORMED` catch-all, unchanged.

Two asks remain for the audit workstream (task 1.2). The third, `decision_id` before forwarding, is already done.
- **Score results by server level.** `summarise` counts a flat dict with non-manifest keys as level 4. A `grants.status` result `{request_id, status, summary}` therefore scores 4 (checked 23 Nov) and would raise the mandate's highest PII level seen. `grants` and `audit` results should be scored at their server's level.
- **Accept the issuer's events.** They reach `record_external` from the gateway's internal endpoint, after the gateway has checked the issuer signature.

Throttling and single use don't use `history(jti)`; it lacks the counts they need. Nothing here writes its own audit log.

## Risks / Trade-offs

- [The approval page is a new mint path, and a gap there is a "Forged mandate" (30) on Day 2] → Approval only by the principal's approver key. The issuer mints only on decisions it verified itself. Tests for URL-only, wrong-key, double-approve and a gateway-only mint attempt.
- [Social engineering through the agent's reason] → The summary is gateway-generated; the reason is escaped and labelled; level-4 data is marked; requests are throttled and repeats after a rejection are refused.
- [Grants add latency and a failure mode: a clock skew between containers breaks calls] → Grants live 30 s; all containers share the host clock; verification allows 5 s of skew; failures name the reason.
- [The server-side filter changes results for claim-less mandates] → The grant derives from the same entry the gateway matched. A parity test runs the full eval with grants enforced and compares rows. The `max_rows` default of 100 matches the server's own default.
- [This change edits `check_request` after the question 3–5 fixes] → Rebased onto `ihor` on 23 Nov. Audience slots in after the "any one entry accepts every argument" loop, and `TOO_MUCH` stays the bulk reason.
- [The approval page adds a web surface (cookies, cross-site requests)] → The session cookie is HTTP-only, `SameSite=Strict` and path-scoped. Decisions are POST-only, and an approval carries the number the person chose; a wrong one ends the request. The issuer re-verifies everything.
- [The audit table's argument-hash slot is needed for `action_hash`] → Agree it in task 1.2, or add one optional field in the audit change.
- [`grants` sits at level 1, so mandates without `clearance` (the eval, the Day 2 default, `make gateway_issue`) can't introspect or ask for more] → Intended: legacy mandates behave as before. Agents that should escalate get a mandate with `clearance`. The docs and the shim's setup issue one.
- [The `mandate-clearance` delta copies a requirement that `add-audit-trail` also modifies] → Re-copy it from main after the rebase (task 1.4), keeping both changes' entries and scenarios.
- [Supplementary mandates multiply] → They're short-lived (at most the approved TTL), die with the parent, and the shim drops expired ones.
- [An in-memory seen-`jti` set at the server resets on restart] → Grants live 30 s and bind to exact arguments and `decision_id`, so a replay after a restart repeats only the same allowed call. Accepted.

## Migration Plan

1. Done 23 Nov: rebased onto `ihor`, which has the audit trail and the question 3–5 fixes.
2. Add the issuer container and move the issuer key out of the gateway mount. `make hack` initialises both state folders. The CLI keeps writing the shared files, so `make gateway_issue` and `make attack_mandates` are unchanged.
3. Turn on tool grants in Compose (`TOOL_GRANTS=enforce`) after the parity test passes.
4. Rollback: set `TOOL_GRANTS=off` and remove the `issuer` service from Compose. Existing mandates keep working. Supplementary mandates stop being minted, and the ones already issued expire within their TTL.

## Open Questions

- Should `grants.self` also list supplementary mandates minted from this mandate? It's convenient for the shim, and can follow.
- Should the issuer notify the principal out of band (email or chat) when a request is created? It's the right production answer; the approver CLI's `approvals list` is enough for the hackathon.
