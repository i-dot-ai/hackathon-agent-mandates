# Interface slices: clearance against data levels

**Questions 6 and 15.** Layer 0 of our design: each data server can express only one class of data, and a mandate
says the highest class it is cleared for. OpenSpec change: `openspec/changes/add-interface-slices/`.

Laid out like [the worked example](../questions/02-worked-example.md). Everything below runs after `make hack` and
`docker compose up -d --build gateway slices`. Each laptop is its own issuer, so issue these mandates yourself rather
than copying tokens.

## The servers

| Server | Data level | Tools | Returns |
| --- | --- | --- | --- |
| `schools` | 1 public | `list`, `classification` | Schools and the classification table |
| `directory` | 2 basic PII | `roster`, `name` | `Psuedo ID` and `DisplayName` only |
| `special` | 4 special category | `record` | Ethnicity and care status for one pupil, no name. Always held for approval |
| `pupil-data` | 4 (the starter server, unchanged) | the original eight | Whole census rows |

The levels are the gateway's (`gateway/lib/interfaces.py`) and come from the manifest's classification. The
interface servers also cap themselves: they read every file through `data_slices/reader.py`, which drops any column
above the server's level, so a call that skips the gateway still gets one slice. They run in the `slices` container,
which publishes no port.

## The mandates

A letters agent, cleared to level 2, for names at Dunmore (`SCH04`):

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/directory.jwt \
  --claims '{"clearance": 2}' --org school:SCH04 --purpose "Dunmore Year 11 names for absence letters" \
  --scope '[{"server": "directory", "tools": ["roster", "name"], "constraints": {"urn": ["SCH04"]}}]'
```

A newsletter agent, cleared to level 1, whose scope was written too wide by mistake: it lists `directory.roster` and
`pupil-data.search` as well as `schools.list`.

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/newsletter.jwt \
  --claims '{"clearance": 1}' --org school:SCH04 --purpose "School newsletter" \
  --scope '[{"server": "schools", "tools": ["list"]},
            {"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}},
            {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH04"]}}]'
```

## Requests they allow

The letters agent gets Dunmore's Year 11 list, names and pseudo IDs only:

```bash
uv run python -m gateway.cli call --mandate gateway/state/directory.jwt --agent-key gateway/state/agent.pem \
  --server directory --tool roster --args '{"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}'
```

```text
200  ALLOW  IN_SCOPE  41 rows, each with exactly "Psuedo ID" and "DisplayName"
```

The newsletter agent lists the schools:

```bash
uv run python -m gateway.cli call --mandate gateway/state/newsletter.jwt --agent-key gateway/state/agent.pem \
  --server schools --tool list
```

```text
200  ALLOW  IN_SCOPE  12 schools: URN, SchoolName, SchoolLA
```

## Requests they deny

The newsletter agent asks for the same roster. Its scope lists the tool, but the server is above its clearance:

```bash
uv run python -m gateway.cli call --mandate gateway/state/newsletter.jwt --agent-key gateway/state/agent.pem \
  --server directory --tool roster --args '{"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}'
```

```text
403  DENY  CLEARANCE_TOO_LOW  "directory is level 2, clearance is 1"
```

And a census search on the starter server, which can return ethnicity and care status:

```bash
uv run python -m gateway.cli call --mandate gateway/state/newsletter.jwt --agent-key gateway/state/agent.pem \
  --server pupil-data --tool search --args '{"query": "P0011", "urn": "SCH04"}'
```

```text
403  DENY  CLEARANCE_TOO_LOW  "pupil-data is level 4, clearance is 1"
```

Level 4 data is held even at clearance 4:

```bash
uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/special.jwt \
  --claims '{"clearance": 4}' --org school:SCH04 --purpose "Safeguarding review" \
  --scope '[{"server": "special", "tools": ["record"], "constraints": {"urn": ["SCH04"]}}]'
uv run python -m gateway.cli call --mandate gateway/state/special.jwt --agent-key gateway/state/agent.pem \
  --server special --tool record --args '{"pupil_id": "P0011", "urn": "SCH04"}'
```

```text
202  STEP_UP  SENSITIVE_TOOL  "special.*"   (not forwarded, no data)
```

A mandate with no `clearance`, such as the default one, keeps working on `pupil-data` exactly as before and is refused
on the new servers:

```bash
uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
  --server schools --tool list
```

```text
403  DENY  CLEARANCE_MISSING  "schools is level 1; the mandate has no clearance"
```

## Reason codes

| Code | When |
| --- | --- |
| `CLEARANCE_TOO_LOW` | The server's level is above the mandate's `clearance` |
| `CLEARANCE_MISSING` | No `clearance` claim, calling an interface server (not `pupil-data`) |
| `CLEARANCE_INVALID` | `clearance` is not an integer from 1 to 4 (`true`, `"high"`, `2.0` all fail) |
| `UNKNOWN_SERVER` | The gateway has no data level for the server named |

Clearance is checked after `deny` rules and before scope, and it is read only from the signed mandate: a
`clearance` key in the tool arguments changes nothing.

## Still unresolved

Pupil IDs are the same on every server, so an agent holding both `directory` and an approved `special` call can join
a name to a care status. `special` stepping up every call is what stops that today; pseudonyms per mandate are the
next change. The three interface servers also share one process; splitting them into one container each is Day 2
hardening.
