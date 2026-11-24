# Run budgets: question 11

OpenSpec change `add-run-budgets`. Every call can be allowed while the whole run is a bulk export: an agent that
looks pupils up one at a time ends up with the cohort. The gateway now judges the run.

- **A mandate's own limits** (signed claims, never request arguments):
  - `budget: {"distinct_pupils": N, "calls": N}`: across the mandate's life;
  - per scope entry, `rate: {"per_minute": N, "max_calls": N}`.

  A malformed claim gets `403 BUDGET_INVALID`.
- **Pupils are counted before release.** An allowed result is held, its new pupils counted, and the whole result
  withheld with `429 BUDGET_EXHAUSTED` if the budget would be passed. Pupils already received are free.
- **Supplementary mandates share the family.** One pointing at its parent (`parent.jti`) counts against the same
  pupils and calls. The issuer copies the parent's `budget` into it.
- **Every caller has a ceiling:** calls per agent key per minute, and failed verifications per source address
  per minute. The second is checked before any signature work, so a forged flood can't crash the gateway or grow the
  audit log fast. Over either: `429 RATE_LIMITED` with `Retry-After`.
- **Mandates without budget claims are never refused on history.** Instead the audit trail gets an `alert` event,
  which `audit.events` shows:
  - `ALERT_REFUSALS`: 5 refusals in a row;
  - `ALERT_MANY_PUPILS`: more than 200 pupils received;
  - `ALERT_PUPIL_TARGETED`: one pupil returned to 3 or more mandates within an hour. Every Day 2 attacker going for
    P0011 trips it.

## Configuration

`gateway/config/limits.yaml`:

| Key | Default | What it does |
| --- | --- | --- |
| `ceilings.per_key_per_minute` | 300 | Calls per agent key per minute. One eval run is about 32. |
| `ceilings.unverified_per_source_per_minute` | 120 | Failed verifications per source address per minute |
| `ceilings.record_per_second` | 1 | Audit events per caller per second while a ceiling holds |
| `ceilings.retry_after_seconds` | 60 | `Retry-After` on `RATE_LIMITED` |
| `budgets.default_distinct_pupils` | `null` | A pupil budget for mandates with no budget claim. `null` keeps them as before. |
| `budgets.default_calls` | `null` | The same, for calls |
| `alerts.refusals_in_a_row` | 5 | `ALERT_REFUSALS` threshold |
| `alerts.many_pupils` | 200 | `ALERT_MANY_PUPILS` threshold |
| `alerts.pupil_targeted_mandates` | 3 | Mandates returning one pupil before `ALERT_PUPIL_TARGETED` |
| `alerts.pupil_targeted_window_minutes` | 60 | Window for that count |

- **Overrides:** any value can be set with `GATEWAY_LIMIT_<SECTION>_<KEY>`, for example
  `GATEWAY_LIMIT_CEILINGS_PER_KEY_PER_MINUTE=600`.
- **Another file:** `GATEWAY_LIMITS_CONFIG=/path/to/limits.yaml`.
- **Off:** `0` turns a ceiling or alert off.
- **Validation:** a typo, a negative number or a missing named file stops the gateway at startup.
- **Visible:** `GET /describe` lists the limits in effect.

Setting a default budget changes answers for mandates without claims, including the eval's and Day 2's default
mandate. Question 0 makes about 12 lookups over roughly 107 pupils, so a default below that fails it.

## The mandate

An Elmwood job with a 3-pupil budget:

```bash
uv run python -m gateway.cli issue --agent-key agent2.pem -o walk.jwt --purpose "Elmwood Year 11 free school meals" \
  --claims '{"budget": {"distinct_pupils": 3}}' \
  --scope '[{"server": "pupil-data", "tools": ["pupil"], "constraints": {"urn": ["SCH05"]}}]'
```

## A run that is allowed, then stopped

```bash
for p in P0007 P0060 P0067 P0085 P0007; do
  uv run python -m gateway.cli call --mandate walk.jwt --agent-key agent2.pem --tool pupil \
    --args "{\"pupil_id\": \"$p\", \"urn\": \"SCH05\"}"
done
```

```text
P0007  200 ALLOW IN_SCOPE
P0060  200 ALLOW IN_SCOPE
P0067  200 ALLOW IN_SCOPE
P0085  429 DENY  BUDGET_EXHAUSTED  distinct_pupils 3   (no result)
P0007  200 ALLOW IN_SCOPE                              (already received: free)
```

`audit saw` afterwards lists `P0007`, `P0060`, `P0067`: the fourth pupil never left the gateway.

## Still unresolved

- **Per-minute windows are in memory.** A restart loosens them for a minute. Lifetime budgets come from the audit
  store and survive.
- **Alerts are signals, not controls.** A careful agent stays under the thresholds; mandates that need a hard limit
  carry `budget`.
- **A child's budget depends on the issuer copying it.** A supplementary mandate minted without the parent's
  `budget` isn't limited by it.
