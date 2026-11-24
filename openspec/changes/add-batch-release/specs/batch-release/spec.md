## Purpose

Lets one approval release every held call of a job, so a 25-letter task asks the person once, while each released call still goes through only once and exactly as shown.

## ADDED Requirements

### Requirement: The agent is told to batch
The `draft` tool's description SHALL say to put every pupil in one call, because each call is held for approval. The `grants.request` description and `grants.check`'s hint for a held call SHALL say that several held calls can be released with one request.

#### Scenario: The hint is visible to the agent
- **WHEN** an agent reads the gateway's `/describe` and calls `grants.check` on a `draft` call
- **THEN** the `draft` description tells it to put every pupil in one call, and the check's `missing.held` says held calls can be passed as one list

### Requirement: One request can release several held calls
`grants.request` SHALL accept `held` as one held call `{decision_id, server, tool, arguments}` or a list of 1 to 50 of them. Every entry MUST be a call the requesting mandate made and had held, with exactly the arguments it was held with. A list that is empty, longer than 50, names a held call twice, or contains anything else MUST be refused with `403 REQUEST_INVALID` and no request created.

#### Scenario: Three single-pupil drafts, one prompt
- **WHEN** an agent's three `draft` calls, each for one pupil, are held, and it calls `grants.request` with all three in `held`
- **THEN** one pending request is created and the person has one approval to give

#### Scenario: A call this mandate didn't make
- **WHEN** a `held` list includes a decision_id that isn't a held call of this mandate
- **THEN** the gateway returns `403 REQUEST_INVALID` and no request is created

### Requirement: The person sees every held call before approving
The approval page SHALL list every held call in the request in plain words, every argument value shown as plain text, and the decision SHALL apply to all of them together.

#### Scenario: Twenty-five pupils shown
- **WHEN** a request releases one `draft` call naming 25 pupils
- **THEN** the signed-in approver's view names all 25 pupils

### Requirement: Each released call goes through once
On approval, the minted mandate SHALL pre-approve one action hash per held call. Each released call SHALL be allowed once with reason `PREAPPROVED`. Repeating a released call, or making a call that wasn't in the request, SHALL be held again with `SENSITIVE_TOOL`.

#### Scenario: Released once each
- **WHEN** three held drafts were approved together, and the agent makes each once and then repeats the first
- **THEN** the three calls return `200 PREAPPROVED`, and the repeat returns `202 SENSITIVE_TOOL`
