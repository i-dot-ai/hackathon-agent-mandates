# Adding a claim to a mandate

The starter mandate says which tools, which argument values, until when, and who granted it. Most open questions
need it to say something more: a clearance, a limit, a purpose the gateway can check. This page is how to put a new
field into a mandate and make the gateway act on it.

There are two halves. Issuing needs no code. Enforcing is the work: **until the gateway reads your field, it is
ignored**, and the mandate behaves exactly as it did without it.

## 1. Put it in the mandate

Choose the place by what the field limits.

| It limits | Where it goes | Flag on `cli issue` |
| --- | --- | --- |
| The whole mandate | A top-level claim | `--claims '{"clearance": 2}'` |
| One grant (one tool at one school) | A key in that scope entry, beside `constraints` | `--scope '[{..., "columns": [...]}]'` |

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/clearance.jwt \
  --clearance 4 \
  --claims '{"clearance": 2}' \
  --scope '[{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]},
             "columns": ["URN", "AcademicYear"]}]'
uv run python -m gateway.cli decode gateway/state/clearance.jwt   # check it is in there
```

- `clearance` and `columns` are only examples. The names and what they mean are yours.
- `--clearance` is required. A `clearance` key inside `--claims` replaces it, which is what the command above does. `--role safeguarding-lead` is what lets a level 4 result through.
- `--claims` refuses a name the mandate already uses (`scope`, `exp`, `cnf` and so on), so it cannot quietly replace
  one.
- Do not put a new field inside `constraints`. Every key there is treated as a request argument that must be present
  and must have one of the listed values.
- For long JSON, keep it in a file: `--claims "$(cat clearance.json)"`.
- From Python, pass `extra={"clearance": 2}` to `issue_mandate` in [gateway/cli.py](../gateway/cli.py).

## 2. Make the gateway read it

Everything is in [gateway/lib/gateway_verify.py](../gateway/lib/gateway_verify.py).

**A top-level claim:** in `Gateway.decide`, straight after `verify_mandate` returns. By then the signature, the dates
and revocation have been checked, so `claims` is what the issuer signed.

```python
claims = verify_mandate(req.mandate, self.registry, self.status_lists)
clearance = claims.get("clearance")  # None for every mandate issued without it
if ...:  # your rule
    raise Reject("CLEARANCE_TOO_LOW", f"clearance={clearance}")
```

**A key in a scope entry:** in `check_request`, inside the `for entry in scope` loop, with `entry.get("columns")`.
Return `"DENY", "YOUR_REASON_CODE", detail` the way the constraint checks do.

**To change what comes back** instead of whether the call runs: the result passes through `tools_call` in
[gateway/main.py](../gateway/main.py) on its way to the agent.

Then rebuild the gateway. The CLI runs on your laptop, but the gateway's code is copied into its container:

```bash
docker compose up -d --build gateway
```

## What catches people out

- **Mandates without your claim.** The eval pack, the default mandate and the Day 2 attack mandates do not carry
  it. Decide what a missing claim means. Refusing every mandate without it fails question 0, so run `make eval_run`.
- **Only the mandate is signed by the issuer.** The agent cannot edit a claim (the signature breaks), but it writes every
  argument in the request. Never read a clearance or a purpose from the request.
- **Only your gateway knows the claim.** Another team's gateway ignores it. On Day 2, say what yours enforces in
  your enforcement note.
- **A different value is a different mandate.** Issue a new one and revoke the old
  ([README, "Changing a mandate"](../README.md#changing-a-mandate)).
- **Tell other teams.** Add the claim to [gateway/lib/mandate.schema.json](../gateway/lib/mandate.schema.json). It is
  documentation only: nothing validates a mandate against it.
- **Leave the request alone.** The shape of `POST /tools/call` stays as it is.
