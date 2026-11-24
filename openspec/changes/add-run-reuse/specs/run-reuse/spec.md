## Purpose

Asks the person once per job: within one run, access they already approved is reused instead of requested again, so prompts stay rare enough to be read.

## ADDED Requirements

### Requirement: A run is a base mandate and what was minted under it
A run SHALL be identified by the base mandate's `jti`: the mandate a person issued for the job, together with every supplementary mandate minted from requests it made. A supplementary mandate SHALL NOT start or extend a run: requests SHALL keep coming from the base mandate, as `grants.request` already requires.

#### Scenario: A new base mandate is a new run
- **WHEN** an approval was given in a run, and the person issues a new base mandate for the next job with the same agent key
- **THEN** a request from the new mandate is not covered by the earlier approval and goes to the person

### Requirement: An earlier approval in the run is reused instead of asking
When the issuer receives a scope request from a base mandate, it SHALL, before creating a pending request, look for an approved request from the same base mandate that released no held call, whose minted mandate verifies (issuer signature, not expired, not revoked, parent not revoked) and whose scope and clearance cover the new request. If one exists, it SHALL return `status: "already_granted"` with that minted mandate, its `jti` and the reused `request_id`, and SHALL NOT create a request, mint a mandate, notify the person or count the call against the request throttles.

#### Scenario: Asking again after losing the mandate
- **WHEN** a request for `directory.roster` at `SCH02` was approved earlier in the run, and the agent, having restarted, asks for the same again with its base mandate
- **THEN** `grants.request` returns `200 ALLOW` with `status: "already_granted"`, the earlier minted mandate and the earlier `request_id`, and the person's pending requests are unchanged

#### Scenario: A narrower ask is covered
- **WHEN** an approval granted `directory.roster` at `SCH02` and `SCH03`, and the agent asks for `directory.roster` at `SCH02` only
- **THEN** the earlier mandate is returned

#### Scenario: A wider ask still asks
- **WHEN** the approval granted `directory.roster` at `SCH02`, and the agent asks for `SCH02` and `SCH04`, or for a higher clearance
- **THEN** a new pending request is created and the person is asked

### Requirement: Some approvals are never reused
An approval that released a held call SHALL NOT be reused, because it pre-approves one exact action once. A minted mandate that has expired, has been revoked, or whose base mandate has been revoked SHALL NOT be reused.

#### Scenario: Revoked approval
- **WHEN** the mandate minted by an earlier approval is revoked, and the agent asks for the same access again
- **THEN** a new pending request is created

#### Scenario: Held call released once
- **WHEN** an earlier approval released one held `write`, and the agent asks to release the same call again
- **THEN** a new request is created for it

### Requirement: The agent keeps its run's mandates
The project SHALL provide an agent-side run wallet that holds the base mandate and every supplementary mandate received in the run, persists them to a file, chooses for each call the narrowest held mandate whose scope allows it, adds the mandate from an `approved` status or an `already_granted` result, and drops mandates that have expired.

#### Scenario: Restart keeps approvals
- **WHEN** an agent's wallet holds a supplementary mandate for `directory.roster` at `SCH02` and the agent restarts with the same wallet file
- **THEN** its next `directory.roster` call at `SCH02` is signed with that supplementary mandate and allowed, with no new request
