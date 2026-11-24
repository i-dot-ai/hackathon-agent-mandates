# Tasks

## 1. Roles and the fit check

- [ ] 1.1 Add `fits_roles(access_roles, scope, clearance)` to `gateway/lib/scope_math.py` (design decision 4) and an `expand_roles(user_roles, roles_file)` helper; unit tests cover the spec scenarios "edit at the school you edit", "edit at the school you only read", "clearance above the role" and "unknown role"; verify `uv run pytest gateway/tests -k roles`
- [ ] 1.2 Write a starter `roles.json` from `make hack` (design decision 3) and add `delegator.roles` as an optional property in `gateway/lib/mandate.schema.json`; verify `make hack` writes the file and `make eval_run` still passes 0 to 5

## 2. Bearer tokens and the CLI

- [ ] 2.1 Generate `idp_key.pem` / `idp_pub.jwk` in `make hack`; add `cli user-token --principal --roles` signing an `at+jwt` (design decision 2); test that the token verifies with `idp_pub.jwk` and carries the claims in the spec
- [ ] 2.2 Add `cli issue --user-token`: verify the token, refuse with `EXCEEDS_ROLES` when the scope doesn't fit, record `delegator.principal` from `sub` and `delegator.roles`; tests for "issuing for a signed-in person" and "issuing beyond the person's roles"
- [ ] 2.3 Replace `cli approve --approver-key` with `--token`; remove `approver-keygen`, `approver-login` and their helpers; verify `cli --help` lists no approver commands

## 3. Issuer

- [ ] 3.1 Issuer verifies `Authorization: Bearer` (`TOKEN_REQUIRED`, `TOKEN_INVALID`, `NOT_THE_APPROVER`, `EXCEEDS_ROLES`) in the order in design decision 5, leaving the request pending on every refusal; remove `approver/login`, sessions, `login_tokens`, `approvers.json`; tests per spec scenario in "authenticates a person" and "only the mandate's principal approves"
- [ ] 3.2 `create_request` and `_check_mintable` check against the requesting mandate's `delegator.roles`, stored on the request row (no roles → `EXCEEDS_PRINCIPAL`, "no roles recorded"); remove `principals.json` and `within_ceiling`; tests for "a mandate without roles can't get more" and the supervisor scenario
- [ ] 3.3 Add `GET /roles` (user roles, descriptions, access roles in words via `grants_words`); test that it returns no principals or tokens
- [ ] 3.4 Update `gateway/tests/test_scope_requests.py` fixtures from approver keys to tokens; verify `make test` and `make lint` pass

## 4. Frontend stub auth server

- [ ] 4.1 Add `jose`; `/approve/sign-in` page listing roles from the issuer's `GET /roles`, choosing a principal (`STUB_IDP_PRINCIPALS` if set) and signing the token server-side into an HTTP-only cookie; remove `approve/login.astro`; verify the cookie isn't readable from page scripts and the frontend builds
- [ ] 4.2 The approval proxy forwards the cookie as `Authorization: Bearer`; `ApprovalRequest.svelte` links to sign-in when the issuer returns `TOKEN_REQUIRED`/`TOKEN_INVALID` and shows "signed in as … with roles …"; verify by hand on `make hack` that the demo walkthrough (`demo.astro`) still works
- [ ] 4.3 Compose: mount `idp_key.pem` into `frontend`, `idp_pub.jwk` and `roles.json` into `issuer`; verify `docker compose exec issuer ls` shows no `idp_key.pem` and `docker compose exec frontend ls` shows no `issuer_key.pem`

## 5. Docs and spec text

- [ ] 5.1 Rewrite "Setup: a person who can approve" and "What the person sees and does" in `docs/scope-requests.md` for roles and sign-in; update "Still unresolved" (anyone can sign in as anyone; roles go stale until expiry)
- [ ] 5.2 Update `openspec/changes/add-scope-requests/specs/scope-requests/spec.md` requirements that name approver keys or `principals.json` to point to `user-roles`; verify `openspec validate add-user-roles --strict` and `openspec validate add-scope-requests` pass

## 6. Integration

- [ ] 6.1 On a rebuilt stack, run the worked example end to end: sign in as `officer:jsmith` with `attendance-officer@SCH04`, issue with `--user-token`, request `directory.roster` at SCH04 (approved) and `pupil-data.write` at SCH01 (refused `EXCEEDS_PRINCIPAL`), approve with a token for another principal (refused `NOT_THE_APPROVER`); `make eval_run`, `make test`, `make lint` all pass
