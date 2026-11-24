# AGENTS.md

You are helping a hackathon team. The question for the two days: **how should a person pass part of their access
down to an agent?** The repo's answer to start from is a signed, scoped, expiring, revocable **mandate**, checked by
a **gateway** in front of the pupil data. Your team's job is to find where that holds and where it breaks.

All pupil data is synthetic. Treat it as if it were real anyway: that is the point of the exercise.

## Get oriented

1. `make hack`: keys, a one-school (`SCH01`) mandate, the eval pack, containers, and one signed call.
2. `make eval_run`: PASS/FAIL for questions 0 to 5. The starter passes 0 to 2 and fails 3 to 5.
3. Read [questions/README.md](questions/README.md), then the question page your team is on.
4. Read [gateway/lib/gateway_verify.py](gateway/lib/gateway_verify.py). Every gateway decision lives there, and it is
   where most changes go.

Timetable: [AGENDA.md](AGENDA.md). Full walkthrough and CLI examples: [README.md](README.md).

## Map

| Thing | Where |
| --- | --- |
| Gateway endpoint (`POST /tools/call`, `:8082`) | [gateway/main.py](gateway/main.py) |
| Mandate, signature and scope checks | [gateway/lib/gateway_verify.py](gateway/lib/gateway_verify.py) |
| Issuing mandates, signing requests, revoking | [gateway/cli.py](gateway/cli.py), [gateway/lib/mandate_issuer.py](gateway/lib/mandate_issuer.py) |
| Adding a claim to a mandate (`cli issue --claims`) and reading it in the gateway | [docs/new_mandate.md](docs/new_mandate.md) |
| Trusted issuers, revocation list | [gateway/lib/trust_registry.py](gateway/lib/trust_registry.py), [gateway/lib/status_list.py](gateway/lib/status_list.py) |
| Mandate shape | [gateway/lib/mandate.schema.json](gateway/lib/mandate.schema.json) |
| Eval cases for questions 0 to 5 | [gateway/eval.py](gateway/eval.py), minted into `eval_pack/` |
| MCP server (no access control, `:8080`) | [mcp_server/api/routes_mcp.py](mcp_server/api/routes_mcp.py) |
| Keys and live mandate | `gateway/state/` (`agent.pem`, `mandate.jwt`, `issuer_key.pem`) |
| Data sources | [mcp_server/data/synthetic/synthetic_manifest.json](mcp_server/data/synthetic/synthetic_manifest.json) |
| Day 2 attack scoring | [day_2_attack/ATTACK_SCORING.md](day_2_attack/ATTACK_SCORING.md) |

## How the day runs

- **Questions 0 to 5 are eval based.** Done when `make eval_run` passes them all. Question 0 must keep passing whatever
  you change.
- **Questions 6 to 16 are open.** No eval cases and no single right answer, and no team is expected to cover them
  all. Each page ends with what to show: a mandate, a request it allows, a request it denies and what is unresolved,
  laid out like [questions/02-worked-example.md](questions/02-worked-example.md). A problem of the team's own is fine
  too.
- **Day 1 check-in** (time in [AGENDA.md](AGENDA.md)): each team shows that much for the open question it took, finished or not.
- **Day 2:** deploy the gateway, post its URL and two mandates per attacking team: the default one and a feature
  mandate from the team's open question, with a note of what it enforces. Then attack other teams with both. An attack
  lands when a request through *their gateway* returns data outside the mandate used.

## Leave alone

None of these are part of the problem. Changing them makes your results meaningless to other teams.

- **The data:** `mcp_server/data/synthetic/`, `mcp_server/synth/`. Every team works from the same pupils.
- **The demo UI's existing walkthrough:** `frontend/src/pages/demo.astro` and `MandateDemo.svelte`. Since 23 Nov the
  organisers allow this team to add pages to `frontend/` (for example the scope-request approval page); keep the
  demo walkthrough working.

## Rules of thumb

- Keep the request shape of `POST /tools/call` unchanged; other teams' tools and the eval depend on it.
- A mandate cannot be edited. To change one, issue a new one and revoke the old (README, "Changing a mandate").
- `EXPIRED` locally? Run `make gateway_issue`.
- Never commit or post `gateway/state/*.pem`. Share only public keys and mandates.
- Going straight to `:8080` bypasses the gateway. That is a known hole to reason about, not a way to pass a question.
- Before finishing a change: `make eval_run`, `make test`, `make lint`.
