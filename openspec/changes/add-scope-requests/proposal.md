## Why

An agent that finds its mandate too narrow has no way to ask for more. A held call (`202 STEP_UP`) can never go through, and nothing can approve it (question 9). The person can't see in plain words what they're granting (question 10). A helper agent gets all of its parent's access or none (question 7). And once the gateway allows a call, the MCP server behind it trusts whoever reaches it: the hop from gateway to tool carries no scope at all, so one gateway bug, or any caller that reaches the server directly, gets everything that server holds.

## What Changes

- **Agents can see their own access.** A new gateway-handled server, `grants`, is reached through the existing `POST /tools/call` request shape. Its tools:
  - `grants.self`: the effective grants, in structured form and plain words.
  - `grants.check`: the decision a call would get, without forwarding it, plus the missing grant when it would be refused.
  - `grants.request`: ask for more access.
  - `grants.status`: poll a request.
- **Scope requests.** An agent asks for a structured grant with a reason and a lifetime. The gateway:
  - refuses the request if the mandate already covers it;
  - refuses it if it goes beyond what the person behind the mandate may hold;
  - otherwise creates a pending request with an ID, an approval URL, a two-digit number for the person to choose on the approval page (one of three shown), a challenge for a supervising agent, and an expiry.
- **Approval by a person or a supervising agent.**
  - **A person** approves on an approval page in the team's UI (`frontend/`, which organisers approved us changing on 23 Nov). The page shows a description the gateway generates from the structured request, and the agent's reason labelled as the agent's own words. The page holds no authority: the approval must be authenticated by the person's approver key, and the issuer verifies it. Holding the URL is not enough.
  - **A supervising agent** can approve only what its own mandate covers, and only if that mandate allows delegation. Anything wider goes to the person.
  - Either approver can reject, or approve something narrower than was asked. Pending requests expire.
- **An issuer service mints the result.** A separate issuer service, which alone holds the issuer key, mints a **supplementary mandate** for the same agent key. It contains exactly the approved grant, points to its parent, expires no later than the parent, and stops working when the parent is revoked.
- **Held calls can be approved.** A request made for a held call produces a mandate that pre-approves that exact action, so the retried call is allowed once instead of being held again. **BREAKING** for the `mandate-clearance` rule "every `special` call is held for approval": a call pre-approved this way is forwarded.
- **Zero-trust tool grants.** For every allowed call, the gateway signs a short-lived, single-use tool grant and sends it to the MCP server with the call. The grant is bound to:
  - the server and tool (the data type);
  - the exact arguments;
  - the subjects the mandate allows (schools, pupils);
  - the clearance level;
  - a row cap.

  The MCP servers and slices refuse any call without a valid grant, and return only rows and columns inside it. Every hop is scoped: agent to gateway by the mandate, gateway to tool by the grant.
- **Scope by whom.** A scope entry may carry an `audience`, a list of pupil IDs. It is checked at the gateway and enforced again at the tool through the grant.
- **Built on the audit trail, not alongside it.**
  - Every `grants.*` call is a normal `POST /tools/call`, so `add-audit-trail` records it.
  - Approval steps go into the same hash chain through `record_external`, including those that happen on the issuer service, which sends them signed.
  - A tool grant's ID is the call's `decision_id`, so the second hop joins the audit event with no new audit field.
  - A request about a held call is checked against that call's audit event.
- **Zero trust between gateway and issuer as well.** The issuer re-verifies the agent's and the supervisor's signed calls itself, and mints only on decisions it verified. The gateway's word alone never creates, approves or widens a request.

## Capabilities

### New Capabilities
- `scope-requests`: the `grants` server, self-introspection and dry-run checks, scope requests and their limits, approval by a person or a supervising agent, the approval page contract, issuer-minted supplementary mandates, pre-approved held calls, and the audit events these produce.
- `tool-grants`: the gateway-to-tool hop. Covers what a tool grant contains, how it is derived from the mandate, how MCP servers verify it, how they enforce subjects, columns and row caps, and behaviour without a grant.
- `mandate-audience`: an optional per-scope-entry `audience` (pupil IDs) that limits whose data a call may concern, checked at the gateway.

### Modified Capabilities
- `mandate-clearance`: the server data-level list gains `grants` at level 1. The "every `special` call is held for approval" requirement gains an exception for calls a mandate pre-approves.

## Non-goals

- **No change to any decision for mandates without the new claims** (`audience`, `parent`, `preapproved`, `can_delegate`), apart from servers that didn't exist before. The eval and the Day 2 default mandate get the same answers.
- **No production sign-in for people.** Approver identity is a per-person approver key held by the issuer and the person. SSO or passkeys can replace it later without changing the flow.
- **No host-specific rendering** (MCP elicitation, MCP app cards). The plain-text and structured result of `grants.request` is the contract; any richer rendering must link to the same approval page.
- **No delegation chains deeper than one supervisor in this change.**
- **No budgets, rate limits or decision model.** Only scope-request throttling, which reads audit history.
- **No database-backed data API** (row-level security in Postgres). Tool grants are enforced in the MCP server code that reads the CSVs.

## Impact

- **Built on** (all on `ihor` as of 23 Nov):
  - `add-audit-trail` (implemented with a SQLite store): `decision_id` assigned before forwarding, `record_external`, the held call's audit event, the `MANDATE_MALFORMED` catch-all, and the gateway-handled server pattern;
  - `add-interface-slices`;
  - the question 3–5 fixes in `check_request` (`TOO_MUCH`, `MAX_ROWS = 100`, path normalisation, any matching entry), which `grants.check` reuses.
- **New code:**
  - `gateway/lib/grants.py`: the `grants` server, request store, approval logic.
  - `gateway/lib/tool_grant.py`: mint and verify, shared by the gateway and the servers.
  - `issuer/`: a new service and container that holds `issuer_key.pem`, mints supplementary mandates and publishes the status list.
  - `frontend/`: an approval page (`/approve/[id]`), an approver login page, and a server-side proxy to the issuer, like the existing demo proxy. The browser never talks to the issuer directly.
- **Changed code:**
  - `gateway/lib/gateway_verify.py`: audience, parent revocation, pre-approved actions.
  - `gateway/lib/interfaces.py`: `grants` level.
  - `gateway/main.py`: `grants` dispatch, tool grant on forward.
  - `mcp_server/api/routes_mcp.py` and `data_slices/`: grant verification middleware and enforcement. The CSV data is not touched.
  - `gateway/cli.py`: `approver keygen`, `approve`, `approver-login`.
  - `docker-compose.yaml`: issuer container; the gateway stops mounting the issuer private key.
- **Keys:**
  - A new `tool_grant_key.pem` on the gateway, used for tool grants only. No key authenticates the gateway to the issuer; the issuer re-verifies the signed bodies instead.
  - Approver public keys registered with the issuer.
  - The gateway no longer holds `issuer_key.pem`.
- **API:** `POST /tools/call`'s request shape is unchanged. New issuer endpoints: JSON endpoints for viewing a request, approver login and decisions (called through the frontend's proxy), plus internal request endpoints. New frontend pages: `/approve/[id]` and `/approve/login`. New gateway endpoint: an internal endpoint for signed issuer audit events. The MCP servers now require a grant header on HTTP tool calls.
- **Mandates without clearance can't use `grants`** (level 1). This includes the eval, the Day 2 default mandate and `make gateway_issue`'s mandate. An agent that should be able to ask for more needs a mandate with `clearance`.
- **Demo router:** `/demo/mandate` and `/demo/revoke` need the issuer key, so they move behind the issuer service and an env flag. Coordinate this with the access-config workstream, which plans to disable them.
- **Questions:** 7, 9, 10, 12 (through narrow, purpose-bound grants), 13 (person ceiling), 14 and 16 (approval events). Day 2: closes "a mandate the target mints for you" if approval stays authenticated, and the issuer key leaves the gateway.
