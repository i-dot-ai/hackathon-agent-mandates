# Proposal

## Why

A person can only pass down access they hold, but today what they hold is a hand-written JSON file
(`principals.json`), and who they are is a per-person approver key file plus a one-time CLI login link. Neither looks
like a real deployment, where the person signs in with an auth server and their bearer token carries their roles. The
file's shape is also too coarse to be safe: it lists servers, tools and schools as separate lists, so someone who can
edit at SCH04 and read aggregates at SCH01 passes the check for **editing at SCH01**.

This addresses **question 7** (what a person may pass down, and to whom) and **question 10** (what the person sees and
signs in with), in the **delegation and approval** layer built by `add-scope-requests`.

## What Changes

- **Access roles.** A named grant in exactly the shape of a mandate scope entry (`server`, `tools`, `constraints`,
  plus a `clearance`), e.g. `pupil-data-editor@SCH04`, `aggregate-reader@SCH01`. What a person can delegate is the set of
  access roles they hold, each one whole: a requested grant fits only if each scope entry sits inside one held access
  role.
- **User roles.** A named bundle of access roles, e.g. `attendance-officer@SCH04` = `roster-reader@SCH04` +
  `pupil-data-editor@SCH04`. Both are defined in one file the issuer reads, `roles.json`.
- **A stub auth server, hosted in the existing frontend.** A sign-in page where you choose who you are and tick user
  roles; the frontend signs a short-lived bearer token (`sub`, `roles`) with a new stub-IdP key. No new service is
  deployed. The issuer holds only the public half.
- **The issuer trusts the token, not a file.** Decisions on the approval page and from `cli approve` carry the bearer
  token; the issuer checks its signature, audience and expiry, that `sub` is the mandate's `delegator.principal`, and that
  the approved grant fits the token's roles.
- **Roles travel with the mandate.** A mandate issued for a signed-in person records the user roles they held
  (`delegator.roles`), so a request made while nobody is signed in (`grants.request`) is still checked against them.
- **BREAKING (for the approval flow only):** approver key files, `cli approver-keygen`, `cli approver-login`,
  `approvers.json`, `principals.json` and the approver session table are removed. `cli approve` takes a bearer token
  instead of an approver key; a new `cli user-token` mints one with the stub-IdP key.

Mandates without `delegator.roles` behave as before for every tool call: the gateway never reads roles, so the eval and
the Day 2 default mandate get the same decisions and question 0 keeps passing. Such a mandate simply can't have a scope
request approved (`EXCEEDS_PRINCIPAL`, "no roles recorded").

## Capabilities

### New Capabilities
- `user-roles`: access roles and user roles (definition, expansion, the whole-role fit check), the stub auth server and
  its bearer token, how the issuer verifies a person from that token, and roles recorded on mandates.

### Modified Capabilities
- None under `openspec/specs/`. `scope-requests` is still an in-flight change (`add-scope-requests`); its approver-key
  sign-in and `principals.json` ceiling requirements are superseded by `user-roles`, and that change's spec text is
  updated alongside this one rather than through a delta.

## Non-goals

- **No real auth server.** The stub signs whatever identity and roles are ticked. Anyone who reaches the sign-in page
  can be anyone; that is listed as unresolved, and the approval page is not a scoring target on Day 2 (only the
  gateway URL is).
- **No role administration, approval workflow for roles, or persisted user-role assignments.** Ticking roles at sign-in
  is the "grant credentials" step.
- **No change to gateway decisions.** The gateway doesn't read roles; it keeps trusting mandates.
- **No revocation of a bearer token.** Tokens live 15 minutes.
- **No change to number matching** (done separately) or to supervisor approval, beyond checking against recorded roles.

## Impact

- `issuer/app.py`, `issuer/store.py`: token verification, role expansion, removal of approver keys and sessions.
- `gateway/lib/scope_math.py`: `within_ceiling` replaced by a whole-role fit check built on `entry_covers`.
- `gateway/cli.py`, `gateway/lib/mandate_issuer.py`: `issue --user-token`, `user-token`, `approve --token`; approver
  commands removed.
- `frontend/`: sign-in page and token signing (one new npm dependency, `jose`), approval proxy forwards the token.
- `docker-compose.yaml`: mount `idp_key.pem` into the frontend and `idp_pub.jwk` + `roles.json` into the issuer.
- `docs/scope-requests.md`, `openspec/changes/add-scope-requests/` spec text, tests.
