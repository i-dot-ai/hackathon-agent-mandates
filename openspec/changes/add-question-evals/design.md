## Context

`gateway/eval.py` belongs to the organisers. It checks decisions for questions 0 to 5 from a pre-minted pack. `day_2_attack/self_attack.py` mints its own mandates and looks for flags, but at import time it mints and creates `agent.pem`. The gateway itself now does much more than decide: it strips columns, folds counts, enforces budgets, holds calls for approval and records an audit chain. This change adds an eval of all of that, run against the live gateway. It changes no gateway code.

## Goals / Non-Goals

**Goals:**
- One command gives PASS/FAIL/GAP per question, 0 to 16, against `:8082` or a deployed URL that trusts the local issuer.
- It checks results as well as decisions.
- It cleans up after itself.
- It is safe to run while other sessions use the same stack.

**Non-Goals:**
- Changing decisions.
- Testing teams whose issuer we don't hold.
- Waiting out real expiry.

## Decisions

1. **Where it runs.** It is a client of `POST /tools/call`, the issuer's `/requests/{id}/decision`, and `/audit/head`. Nothing is added to `gateway_verify.py` or `main.py`. The order of checks it observes is the gateway's own.

2. **Helpers come from `self_attack`.** `mint`, `signed`, `post` and `FLAGS` move into import-safe functions. `mint` takes `key`, `ttl`, `principal`, `org` and `purpose`; `signed` takes `key`; `post` returns `(status, text, headers)` through a `post_full` variant, and `post` keeps its current 2-tuple. The script's own mandates and cases are built inside `run()`, so importing it mints nothing.

3. **Case model.** A case is `(question, name, outcome-if-wrong: FAIL|GAP, check)`.
   - `check` returns a list of problems; an empty list is a pass.
   - Generic checks run on every response: no 500, `decision_id` present, no flag outside `entitled`. The flag scan reads `result` and `error` only.
   - Every call goes through `Run.call`, which also records those generic problems per question. Each question ends with one case, "all N responses: a decision_id, no 500, no flag value". This covers calls that no case checks itself, such as finder searches and refusals counted for alerts.
   - Expectations are keyword arguments to one `expect()` helper: `status`, `reason`, `rows`, `min_rows`, `max_rows`, `pupils`, `pupils_only`, `level_at_most`, `columns`, `retry_after`, `no_result`, `entitled`.

4. **Keys.** A fresh Ed25519 key per question (`generate_keypair`), never `gateway/state/agent.pem`. This keeps each question under the 300-per-minute key ceiling, keeps other sessions' traffic from interfering, and gives question 7 distinct agent IDs.

5. **Time cases without waiting.**
   - Expired mandates are issued with a negative ttl: `issue_mandate(ttl=-120)` and `ttl=-1`.
   - A future `nbf` clashes with the built-in claim in `extra`. So the eval decodes an issued token, sets `nbf = now + 3600`, and re-signs it with the issuer key from `_load_status`, with the same `kid`. The gateway sees a genuine issuer signature.
   - The supplementary mandate for `PARENT_REVOKED` in question 1 is issued with a `parent` claim pointing at a revoked mandate's status entry. Question 7 covers the same through the real loop.

6. **Principals.**
   - No case depends on `officer:jsmith`'s limits. Other sessions edit them: during the first run they widened from SCH01-SCH04 at clearance 2 to all twelve schools at clearance 4.
   - Question 13 uses `eval:shrink` (directory at SCH05 only) for `EXCEEDS_PRINCIPAL` and for the shrink.
   - Question 16 uses `eval:questions` as the person and `officer:jsmith` only as "another person". Forged traffic therefore lands in an eval log, not a real person's.
   - For the rest, the eval adds `eval:questions` and `eval:shrink` to `principals.json`, and their approver keys to `approvers.json`. The approver keys are generated in memory.
   - The entries are added at start and removed in `finally`, each by a read-modify-write of one key, so concurrent edits to other keys survive. Question 13's shrink edits `eval:shrink` only.
   - This is the one shared-file edit. It is reported in the run's output.

7. **Approval loop.** The eval builds the decision as `cli approve` does: it signs a decision token with `gateway.cli.decision_token` and posts it to `ISSUER_URL` (default `http://localhost:8083`).
   - The negative cases post an unsigned decision ("URL only") and one signed with a key that isn't the approver's. Both must leave the request pending.
   - Pending requests the eval created are rejected in cleanup.

8. **Alerts.** `ALERT_PUPIL_TARGETED` has a deterministic ID per pupil per clock hour (`alert_id(pupil, "targeted", hour)`). `P0004` is touched by every eval and attack run, so its alert has almost certainly been recorded this hour under another mandate, and ours would be deduplicated. The eval therefore picks a random current pupil at SCH08, SCH10 or SCH12. It picks from the census file, read only, so no finder mandate receives the pupil first. It returns that pupil to three of its own claim-less mandates and looks for the alert under those mandates' `jti`s and the `pupil_id`. If that pupil was already alerted this hour, it retries with up to two other pupils. This changes the brief's "P0004".

9. **Audit verify.**
   - `cli audit anchor` runs against the gateway's `/audit/head` with `gateway/state/gateway.pub`, writing to a temp file.
   - The store lives in the container's volume, in WAL mode, so a plain file copy can miss recent events. The eval takes a consistent snapshot with `docker exec <container> python -c "sqlite3 ... backup"`, copies it with `docker cp`, deletes the copy in the container, and runs `cli audit verify --db <snapshot> --anchors <file>`.
   - The container name comes from `EVAL_GATEWAY_CONTAINER` (default `gateway`). With `EVAL_AUDIT_DB` set, that file is used instead. With neither available, a NOTE says verify was skipped.

10. **Flood.**
    - Off by default.
    - `--flood` runs the flood case alone, after the preflight. Once the ceiling trips, every unverified case after it would get `RATE_LIMITED` instead of its own reason, so the flood never shares a run with the other cases.
    - The eval sends forged requests (an unparseable mandate) until it gets a 429, up to `EVAL_FLOOD_MAX` (default 200). It expects `RATE_LIMITED` with `Retry-After`.
    - It is meant for a private uvicorn gateway started with `GATEWAY_LIMIT_CEILINGS_UNVERIFIED_PER_SOURCE_PER_MINUTE=5`.
    - The unverified calls of a normal run are kept to about 15: expired, revoked and forged cases only. The per-source ceiling (120 a minute) is shared by every session on this machine.

11. **GAP cases are probes.** Each GAP states the behaviour we want and checks for it. When the gateway gains that behaviour, the case becomes `GAP-FIXED`.
    - **Q7** (static): is there a grants tool (`delegate` or `hand_on`) that hands a narrowed grant to a key holding no mandate yet? A live probe would turn "fixed" if the gateway accepted an empty mandate, which would be a hole, not a fix.
    - **Q10:** a mandate drafted from a sentence. Nothing builds one, so this is a static GAP.
    - **Q12:** two mandates differing only in `purpose` should get different decisions for an out-of-purpose call.
    - **Q13:** after `eval:shrink` loses SCH05, its mandate should be refused.
    - **Q2:** a lone surrogate (`\ud800`) in an argument should be refused, not crash. Today the gateway on main returns HTTP 500. `day_2_attack/self_attack.py` found this too, so it is a live Day 2 crash, recorded as a GAP until it is fixed.

## Failure mode

The eval fails closed on itself:
- an unexpected exception in a case is a FAIL for that case, not a crash;
- a preflight failure exits 2;
- cleanup (revoking, rejecting pending requests, removing eval principals) always runs.

The gateway's own failure modes are unchanged.

## Day 2

- No attack is opened or closed. The eval exercises the attack classes in `ATTACK_SCORING.md` against our own gateway: bulk, path, forged mandate, crash, flags at levels 2 and 4, budget, audit leaks.
- It needs the issuer key, so it can't be pointed at another team's gateway.
- The eval principals exist only during a run, so they never grant anything on a deployed issuer.

## Risks / Trade-offs

- **Shared state edits.** If a run is killed with SIGKILL, the eval principals stay in `principals.json` until the next run removes them. The next run's start also removes stale ones.
- **Shared rate windows.** Another session flooding from this address could push our unverified cases into `RATE_LIMITED`. The eval reports the reason it got, so this shows up as a readable FAIL.
- **Writes.** The question 9 write appends one correction line, tagged `eval_questions`, to `mcp_server/data/writes/corrections.jsonl`. That file is outside `synthetic/`.
- **Clock.** The eval compares the gateway's `decision.ts` with local time once. If they differ by more than 1 second, it prints a NOTE, since the 1-second expiry case could flake.
