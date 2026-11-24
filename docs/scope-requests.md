# Scope requests: an agent asks for more, a person decides

**Questions 7, 9 and 10**, from OpenSpec change `add-scope-requests`. An agent that finds its mandate too narrow asks
for exactly what it's missing. The person behind the mandate, or a supervising agent within its own mandate, decides
on a page that shows the request in words generated from the structured grant. The issuer then mints a new,
short-lived mandate for the same agent key, holding exactly what was approved. Every hop is scoped: agent to gateway
by the mandate, gateway to tool by a signed tool grant per call.

Everything below runs after `make hack` (which now also starts the `issuer` service).

## Setup: a person who can approve

The issuer only lets a person grant what they hold. For the hackathon that's a file, `gateway/state/principals.json`:

```json
{"officer:jsmith": {"servers": {"directory": ["roster", "name"], "pupil-data": ["search", "pupil", "write"]},
 "urns": ["SCH01", "SCH02", "SCH03", "SCH04"], "max_clearance": 4}}
```

Give the person an approver key. Its public half is registered with the issuer, and the agent never sees it:

```bash
uv run python -m gateway.cli approver-keygen --principal officer:jsmith -o jsmith-approver.pem
```

## The mandate

A Dunmore roster for Year 10 and 11, at clearance 2. Clearance is needed: the `grants` tools are level 1, so a
mandate without `clearance` can't use them.

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem --ttl 3600 -o dunmore.jwt \
  --principal officer:jsmith --org school:SCH04 --claims '{"clearance": 2}' \
  --scope '[{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}]'
```

## A request it denies, and the agent asking for more

Brookmere's roster is outside the mandate:

```bash
uv run python -m gateway.cli call --mandate dunmore.jwt --agent-key gateway/state/agent.pem \
  --server directory --tool roster --args '{"urn": "SCH02", "year_group": 11}'
# 403 CONSTRAINT_VIOLATED urn='SCH02'
```

`grants.check` says what's missing; `grants.request` asks for it:

```bash
uv run python -m gateway.cli call --mandate dunmore.jwt --agent-key gateway/state/agent.pem --server grants \
  --tool request --args '{"scope": [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02"]}}],
  "ttl": 7200, "reason": "absence letters for Brookmere"}'
```

```text
200
"result": {
  "request_id": "sr_BYiYCNzhNgCG", "status": "pending", "number": 47,
  "approval_url": "http://localhost:8081/approve/sr_BYiYCNzhNgCG",
  "summary": "List Year 10 and 11 pupils' IDs and names at Brookmere High School (SCH02), for 2 hours.",
  "next_action": "ask_user",
  "text": "Approval needed: ... and choose 47 on the approval page. ... Replying \"yes\" here does not approve it."
}
```

The summary is the gateway's own words, generated from the structured scope. The agent's reason is shown on the page
separately, labelled as the agent's words.

## What the person sees and does

Approving works like number matching in a multi-device sign-in. Each request gets one two-digit number (10 to 99),
which only the agent is told, and two different decoys. The page shows all three in an order shuffled once, when the
request is made, so reloading shows the same order. Nothing the page or `/requests/{id}/view` returns says which one
is right.

Opening the approval URL without signing in shows the summary only, not the numbers. To decide, the person signs in
with their approver key: a one-time link, valid 5 minutes.

```bash
uv run python -m gateway.cli approver-login --principal officer:jsmith --approver-key jsmith-approver.pem \
  --request sr_BYiYCNzhNgCG
```

Signed in, the page shows what the agent can already do next to what it's asking for, the agent's ID, and its
reason as plain text, and the three numbers. The person chooses the number the agent gave them, can approve less
(fewer grants, a shorter time), and approves or rejects. Rejecting needs no number. The same decision works from the
terminal:

```bash
uv run python -m gateway.cli approve sr_BYiYCNzhNgCG --principal officer:jsmith \
  --approver-key jsmith-approver.pem --number 47
```

A wrong number ends the request, so a guess gets one try, not three. The request is marked rejected with
`reason_code: NUMBER_MISMATCH` (audit event `approval_denied`, reason `NUMBER_MISMATCH`), and `grants.status` tells
the agent `next_action: request_again`. Unlike a person's rejection, a mismatch doesn't block the agent asking again
for the same thing (`RECENTLY_REJECTED`). The number is only checked once the right person is signed in, so a
stranger's wrong guess can't end someone else's request.

Holding the URL or the number isn't enough to approve. Only the principal's approver key decides, and the issuer
checks it, not the page.

An `issuer/state/requests.db` from before number matching (with a `user_code` column) is migrated in place when the
issuer starts: its pending requests end as expired, and new requests get numbers.

## The new mandate, and a request it allows

The agent polls:

```bash
uv run python -m gateway.cli call --mandate dunmore.jwt --agent-key gateway/state/agent.pem --server grants \
  --tool status --args '{"request_id": "sr_BYiYCNzhNgCG"}'
# "status": "approved", "next_action": "retry", "mandate": "<new JWT>"
```

Decoded, the new mandate holds the same agent key and exactly the approved grant (approved for 30 minutes instead of
the 2 hours asked):

```json
{
  "scope": [{"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH02"]}}],
  "clearance": 2,
  "parent": {"jti": "<dunmore.jwt's jti>", "status": {"uri": "...", "idx": 3}, "mandate_hash": "sha256:..."},
  "approved_by": {"kind": "person", "id": "officer:jsmith", "request_id": "sr_BYiYCNzhNgCG"}
}
```

With it, the Brookmere roster goes through: `200 IN_SCOPE`, 39 rows of ID and name only. Revoking `dunmore.jwt`
kills the new mandate too (`PARENT_REVOKED`).

## Held calls go through once

A `pupil-data.write` is held (`202 SENSITIVE_TOOL`). The agent asks with
`held: {decision_id, server, tool, arguments}`. The person sees "Change FSMeligible to 1 for pupil P0011 at Dunmore
Community College (SCH04)". The approved mandate lets that exact call through once (`200 PREAPPROVED`) within 5
minutes. Different arguments, or a second try, are held again.

## From Claude Code: the MCP shim

`gateway/shim.py` is a local MCP server that holds the agent key and the mandates, so the agent never handles
either. It offers `call`, `my_grants`, `check_access`, `request_scopes` and `await_approval`. `call` uses the
narrowest mandate that covers the call and falls back to the base mandate. A refusal says what to do next, and a
held call comes back with the `held` object `request_scopes` needs. `held` may also be a list, released by one
approval. Any mandate in a result, whether newly approved or an earlier approval reused within the run, goes into
the shim's run wallet (`examples/mandate_wallet.py`) and is taken out of what the agent sees. Give it a mandate
with `clearance` (`dunmore.jwt` above):

```bash
claude mcp add mandates -e SHIM_AGENT_KEY=$PWD/gateway/state/agent.pem -e SHIM_MANDATE=$PWD/dunmore.jwt \
  -- uv --directory $PWD run python -m gateway.shim
```

Then ask Claude Code for Brookmere's Year 11 roster. It's refused, `check_access` names the missing grant, and
`request_scopes` returns the text to show you. Approve it with `cli approve` or on the page, and `await_approval`
picks up the new mandate. The retry goes through. `SHIM_GATEWAY_URL` points it at another gateway (default
`http://localhost:8082`). The wallet is saved next to the base mandate (`dunmore.wallet.json`, or `SHIM_WALLET`), so
a restarted shim keeps its approvals. A wallet file from a different base mandate is ignored.

## A supervising agent

A mandate with `"can_delegate": true` can approve a helper's request with `grants.decide`, but only for grants its
own scope and clearance cover. Anything wider is refused with `EXCEEDS_SUPERVISOR` and waits for the person. An
agent can't approve its own request (`SELF_APPROVAL`).

What a supervisor approves is tied to it. The minted mandate's `approved_by` carries the supervisor's status
entry, and the gateway checks it on every call: revoke the supervisor and everything it approved stops with
`APPROVER_REVOKED`. A minted mandate never outlives the supervisor that approved it, either.

## Seeing approvals together

Signed in, the approval page lists the earlier approvals for the same mandate that still work, under "Also
approved earlier, still active". Ten narrow asks read as their total, not as ten small things. The words for a grant
never say less than is enforced: an entry with no school constraint says "at every school", and row caps and call
rates are shown. Once a person approves less than was asked, the agent's `grants.status` summary and the minted
mandate's `purpose` describe what was approved.

## The gateway-to-tool hop

The MCP servers no longer trust whoever reaches them. Each forwarded call carries a tool grant, signed by the gateway
and bound to the server, the tool, the exact arguments, the schools and pupils, the data level and a row cap, for 30
seconds and one use. A call straight to `:8080` gets `GRANT_MISSING`. A server re-checks the arguments
(`GRANT_SCOPE`) and filters its own output, even if the gateway got a decision wrong.

## Audit

Every `grants.*` call is a normal audited tool call. The issuer sends `approval_requested`, `approval_granted`,
`approval_denied` and `approval_expired` events, signed with its key, into the same hash chain. An
`approval_granted` event names the mandate it minted (`minted_jti`).

## Still unresolved

- Approvers are a key file per person, not SSO or a passkey.
- The person's ceiling is a JSON file, not a real entitlement source.
- The issuer and `cli issue` both write `status_list.json`, with no lock between them.
- A helper still needs an original mandate of its own before it can ask; a parent agent can't hand a narrowed
  grant to a new key.
- Only the principal can approve, with nobody to cover when they're away, and one approval is enough even for
  special category data or a write.
