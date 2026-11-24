# Feature mandate: question 6, clearance

Issued with

```bash
make attack_mandates FEATURE_SCOPE=day_2_attack/feature_scope.json
```

which signs `day_2_attack/feature_scope.json` at **clearance 2, with no role**, for 24 hours.

## What it enforces

The mandate names Castleton School (`SCH03`) and a clearance. The gateway labels everything a call could return
from the manifest's classification (1 public to 4 special category) and refuses the call **before it runs** when
any of it is above the clearance. Level 4 also needs a role the gateway lists. The decision cannot depend on whether
rows matched, so a refusal says nothing about the data.

## It allows

- `roster` at Castleton: pseudo IDs and display names, level 2.

  ```bash
  uv run python -m gateway.cli call --mandate <team>.feature.jwt --agent-key attack.pem --url <gateway> \
    --tool roster --args '{"urn": "SCH03", "year_group": 11}'
  ```

- `get` on `synthetic/synthetic_schools.csv`, level 1.

## It refuses

- `search` at Castleton: census rows carry ethnicity and care status (level 4) and free school meals (level 3).
  The refusal is `CLEARANCE_TOO_LOW` whether or not the query matches anything.
- Anything at another school, any other file, and every other tool.
- Every level 3 or 4 column, at any school.
