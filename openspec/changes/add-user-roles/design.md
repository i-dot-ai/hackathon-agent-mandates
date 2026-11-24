# Design

## Context

`add-scope-requests` gave us a person-approval flow. Today a person proves who they are with an approver key file
(`approvers.json` holds the public half). `cli approver-login` turns it into a one-time link and then a session in the
issuer's store. What they may grant comes from `principals.json`, checked by `within_ceiling` in
`gateway/lib/scope_math.py`. That check treats servers, tools and schools as separate lists and allows any mix of them
(see proposal, Why).

What we can deploy is fixed. The team stack is the Compose project with `backend`, `frontend`, `slices`, `gateway` and
`issuer`. We can't add a service. The frontend (Astro SSR, Node) already runs server-side code and sits behind SSO
when deployed. Locally (`ENVIRONMENT=local`) it skips SSO.

Number matching (choose the number the agent shows) is a separate change in progress. This design assumes it and
doesn't depend on it.

## Goals / Non-Goals

**Goals:**
- The issuer's code takes the same shape it would with a real auth server: verify a signed token from a trusted
  issuer, read `sub` and `roles`, expand the roles. Swapping the stub for a real IdP should change configuration
  (trusted key, `iss`, `aud`) and the sign-in page, not the issuer.
- What a person can delegate is checked whole, role by role, with the same `entry_covers` maths the gateway uses for
  mandates.

**Non-Goals:**
- Real authentication on the sign-in page, refresh tokens, token revocation, and role administration.

## Decisions

### 1. The stub auth server lives in the frontend, not the issuer
The sign-in page and token signing are Astro server routes (`frontend/src/pages/approve/sign-in.astro` plus a
`POST` endpoint). The stub-IdP private key (`gateway/state/idp_key.pem`, Ed25519) is mounted only into the frontend
container. The issuer gets only `idp_pub.jwk`.

- *Alternative: routes on the issuer.* Less wiring, but then the service that mints mandates would also invent
  identities. One compromised process would hold both keys, and the issuer would end up trusting tokens it signed
  itself. Keeping them apart is how a real deployment is split.
- *Alternative: a new IdP container.* Ruled out because we can't deploy one.
- New dependency: `jose` (npm) to sign EdDSA JWTs in Node.

### 2. Token shape follows RFC 9068 (JWT access tokens)
Header `typ: at+jwt`, `alg: EdDSA`. Claims: `iss: "stub-idp"`, `aud: "mandate-issuer"`, `sub`, `roles` (list of
user-role names), `iat`, `exp` (15 minutes at most), and `jti`.

The frontend stores the token in an HTTP-only, `SameSite=Strict` cookie scoped to `/api/approve`, the way it stores
`approver_session` today. The approval proxy (`frontend/src/pages/api/approve/[...path].ts`) forwards it to the issuer
as `Authorization: Bearer`.

`cli user-token --principal P --roles a,b` signs the same token with the same key, for `cli approve --token` and
`cli issue --user-token`.

- *Alternative: carry access roles in the token instead of user-role names.* Tokens get bigger, and it isn't how IdPs
  usually work. Keeping the bundle definitions on the issuer side also means a fix to a role reaches the next token,
  not just future ones.

### 3. Roles file: `gateway/state/roles.json`, read by the issuer
```json
{
  "access_roles": {
    "roster-reader@SCH04":     {"server": "directory",  "tools": ["roster", "name"], "constraints": {"urn": ["SCH04"]}, "clearance": 2},
    "pupil-data-editor@SCH04": {"server": "pupil-data", "tools": ["search", "pupil", "write"], "constraints": {"urn": ["SCH04"]}, "clearance": 4},
    "aggregate-reader@SCH01":  {"server": "pupil-data", "tools": ["aggregate"], "constraints": {"urn": ["SCH01"]}, "clearance": 4}
  },
  "user_roles": {
    "attendance-officer@SCH04": {"description": "Attendance officer, Dunmore", "access_roles": ["roster-reader@SCH04", "pupil-data-editor@SCH04"]},
    "data-analyst@SCH01":       {"description": "Analyst, aggregates only",   "access_roles": ["aggregate-reader@SCH01"]}
  }
}
```
Names are plain strings with the school in the name. We don't use templated roles such as
`attendance-officer@{urn}`. That's simpler to read and review, and a dozen schools is a short file. `make hack`
writes a starter file. `principals.json` and `approvers.json` are deleted.

### 4. Fit check: `fits_roles(access_roles, scope, clearance) -> str | None`
This lives in `gateway/lib/scope_math.py` and replaces `within_ceiling`. A grant fits when every wanted entry has a
held access role `r` with `entry_covers(r, entry)`, and `max(SERVER_LEVELS[entry.server], clearance) <= r.clearance`.
It returns the first entry that doesn't fit, in words, or `None`. Clearance is checked per covering role, so a
high-clearance role at one school can't lift the clearance of a grant at another. It fails closed: empty or unknown
roles mean nothing fits.

### 5. Where each check runs, in order
- **`grants.request` (issuer `create_request`).** The checks run in the existing order, except that
  `fits_roles(expand(mandate.delegator.roles), …)` takes over the `principals.json` lookup. They still run before
  throttling and before anything is stored. Supplementary mandates still can't make requests (the existing one-level
  rule), so the roles always come from an original mandate. The issuer stores those role names on the request row,
  because it keeps only the mandate's hash. `mint_for` doesn't copy roles into the minted mandate. *(Builder's call,
  settled in review.)*
- **Person decision (issuer `person_decision`).** The checks run in this order:
  1. the number match (separate change);
  2. token present (`TOKEN_REQUIRED`), then verified (`TOKEN_INVALID`);
  3. `sub == delegator.principal` (`NOT_THE_APPROVER`);
  4. status is pending (`ALREADY_DECIDED`);
  5. `fits_roles(expand(token.roles), approved)` (`EXCEEDS_ROLES`);
  6. `_check_mintable`, which still applies the parent mandate's limits.

  All of these fail closed, and none of them changes the request's state.
- **Supervisor decision.** `_check_mintable` uses the roles stored on the request row in place of `principals.json`.
- **`cli issue --user-token`.** This runs locally where the issuer key already lives. It verifies the token with
  `idp_pub.jwk`, checks `fits_roles` against the scope, and writes `delegator.roles`. Without `--user-token`, issuing
  works as today and records no roles.
- **The gateway doesn't change.** It never reads roles. `delegator.roles` is a new optional property in
  `mandate.schema.json`.

### 6. Roles recorded on the mandate (decision for the team)
A request (`grants.request`) arrives while nobody is signed in, so the issuer needs the person's roles from somewhere.

**Chosen:** a snapshot at issue time in `delegator.roles`, checked again against the person's live token at decision
time. The mandate stays self-contained, and a role the person has since lost is caught at approval (`EXCEEDS_ROLES`).

- *Alternative: the issuer asks the auth server for the person's current roles* (userinfo or SCIM). That's what a real
  deployment would do, but the stub keeps no store of who holds which role, so there is nothing to ask.
- *Alternative: skip the check at request time and check only at decision time.* Simpler, but agents could fill the
  person's approval queue with requests that can never be approved, and the throttling assumes a request was
  plausible.

### 7. Approver sessions and keys are removed outright
There's no transition period. The bearer token replaces the session (`login_tokens` and the session table go), and
`cli approve --token` replaces signed decision JWTs. Keeping both would double the paths an attacker can try and the
paths we test.

## Risks / Trade-offs

- **Anyone who reaches the sign-in page can be anyone with any role.**
  - Deployed, the frontend's SSO is the only gate.
  - Day 2 scoring counts only the gateway URL, so this isn't scored, but it is the honest headline of "Still
    unresolved".
  - Mitigation for a demo: set `STUB_IDP_PRINCIPALS` so the page offers only a fixed list.
- **Roles in a mandate go stale.** A mandate keeps working after its person loses a role, until the mandate expires.
  The mitigation is to check at decision time and keep mandates short-lived. Live role lookup is future work.
- **Two holders of `roles.json`.** If the frontend and issuer disagree about role names, the sign-in page offers roles
  that grant nothing. The mitigation is that the frontend reads the list from the issuer (`GET /roles`) and never from
  the file.
- **Day 2.**
  - Closed: "Forged mandate: one you got the target to mint for you". Approving now needs a token signed by a key in
    the frontend container. The cross-product hole in the old ceiling check also goes.
  - Opened: none on the gateway URL. The frontend's sign-in page is out of bounds for scoring.
- **Fail closed everywhere.** If the roles file or IdP key is missing or unreadable, every decision is refused with
  `TOKEN_INVALID` or `EXCEEDS_PRINCIPAL`, and tool calls are unaffected.

## Migration Plan

1. `make hack` generates `idp_key.pem` and `idp_pub.jwk`, writes a starter `roles.json`, and stops writing
   `principals.json` and `approvers.json`.
2. Compose mounts `idp_key.pem` into `frontend` and `idp_pub.jwk` plus `roles.json` into `issuer`.
3. Existing pending requests and mandates without roles keep working for tool calls. Their scope requests are refused
   until they are reissued with `--user-token`.
4. Rollback: revert the change. Mandates with `delegator.roles` stay valid under the old code, which ignores the claim.

## Open Questions

- The exact starter set of user roles for the Day 2 feature mandate. This can be settled when we write the note for
  attacking teams.
