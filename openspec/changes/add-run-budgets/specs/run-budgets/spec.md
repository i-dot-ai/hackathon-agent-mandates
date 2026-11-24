## Purpose

Limits how much a mandate can take over its whole run, not just per call, and keeps any one caller from flooding the gateway, so an agent can't assemble a bulk export from many small allowed calls.

## ADDED Requirements

### Requirement: Budgets come only from signed claims
A mandate MAY carry a top-level `budget` claim `{"distinct_pupils": N, "calls": N}` and, on any scope entry, a `rate` `{"per_minute": N, "max_calls": N}`, each field optional and a positive integer. The gateway SHALL read them only from the verified mandate, never from request arguments. A `budget` or `rate` that is not of that form MUST be refused on every call with `403 BUDGET_INVALID`.

#### Scenario: Budget in the arguments is ignored
- **WHEN** a mandate with `budget: {"distinct_pupils": 5}` calls `pupil-data.search` with an extra argument `"budget": {"distinct_pupils": 1000}`
- **THEN** the gateway applies the budget of 5

#### Scenario: Malformed budget
- **WHEN** a mandate with `budget: {"distinct_pupils": "lots"}` makes any call
- **THEN** the gateway returns `403 DENY` with reason `BUDGET_INVALID`

### Requirement: The distinct-pupil budget is checked before anything is released
For a mandate with `budget.distinct_pupils` (or, for a mandate with no budget or rate claims, a configured default), after an allowed call returns, the gateway SHALL count the distinct pupil IDs in the result that the mandate's family (the mandate, its parent and other children of that parent) has not received before. If the family's total would exceed the budget, the gateway MUST NOT return any of the result, and SHALL return `429` with reason `BUDGET_EXHAUSTED` and detail naming the budget. A result that adds no new pupils SHALL always be returned. The audit event for a withheld call SHALL record the decision `DENY` with reason `BUDGET_EXHAUSTED` and no pupils received.

#### Scenario: One pupil at a time, then stopped
- **WHEN** a mandate for Elmwood (`SCH05`) with `budget: {"distinct_pupils": 3}` looks up three different pupils with `pupil-data.pupil`, each returning one record, then asks for a fourth
- **THEN** the first three calls return `200 ALLOW`, the fourth returns `429` with reason `BUDGET_EXHAUSTED` and no `result`, and `audit.saw` for the mandate lists exactly three pupils

#### Scenario: A result that would cross the budget is withheld whole
- **WHEN** a mandate with `budget: {"distinct_pupils": 10}` has received 8 pupils and a search would return rows for 5 more
- **THEN** the gateway returns `429 BUDGET_EXHAUSTED` and none of the 5

#### Scenario: Seeing the same pupil again is free
- **WHEN** a mandate whose budget is used up looks up a pupil it has already received
- **THEN** the gateway returns `200 ALLOW` with the record

#### Scenario: A supplementary mandate shares its parent's budget
- **WHEN** a parent mandate with `budget: {"distinct_pupils": 3}` has received 3 pupils, and a supplementary mandate with `parent.jti` set to it, carrying the parent's `budget`, asks for a fourth pupil
- **THEN** the gateway returns `429 BUDGET_EXHAUSTED`

### Requirement: A supplementary mandate carries its parent's budget
The family's pupils and calls are counted across the parent and its supplementary mandates, but the limit is read from the mandate making the call. An issuer that mints a supplementary mandate (with `parent.jti`) SHALL copy the parent's `budget` claim into it unchanged, so asking for more access never lifts the budget.

#### Scenario: A child without the budget isn't limited by it
- **WHEN** a supplementary mandate is minted without its parent's `budget`
- **THEN** the gateway applies no pupil budget to it, which is why the issuer must copy the claim

### Requirement: Call budgets and rates limit how often
For a mandate with `budget.calls`, the gateway SHALL refuse with `429 BUDGET_EXHAUSTED` any call after the family has made that many allowed calls. For a scope entry with `rate.max_calls`, it SHALL refuse with `429 BUDGET_EXHAUSTED` any call matched by that entry after that many allowed calls through it. For a scope entry with `rate.per_minute`, it SHALL refuse with `429 RATE_LIMITED` any call matched by that entry beyond that many allowed calls in the last 60 seconds. Refused calls SHALL NOT count toward these limits.

#### Scenario: Per-minute rate
- **WHEN** a mandate whose `search` entry has `rate: {"per_minute": 2}` makes three allowed searches within 10 seconds
- **THEN** the third returns `429` with reason `RATE_LIMITED`, and a search 60 seconds after the first is allowed again

### Requirement: A ceiling protects the gateway from any one caller
The gateway SHALL refuse with `429 RATE_LIMITED` any call from an agent key that has made more than the configured ceiling of calls in the last 60 seconds (default 300), whatever its mandate says. It SHALL also refuse with `429 RATE_LIMITED`, before verifying anything, requests from a source address that has sent more than the configured number of requests that failed verification in the last 60 seconds (default 120). Requests refused by either ceiling SHALL still be recorded, at most one audit event per caller per second while the ceiling holds.

#### Scenario: The eval is far below the ceiling
- **WHEN** `make eval_run` runs twice in a row against the gateway
- **THEN** no call is refused with `RATE_LIMITED`, and question 0 passes 12/12 both times

#### Scenario: Forged flood
- **WHEN** one address sends 500 requests with forged mandates within a minute
- **THEN** after 120 refusals the rest get `429 RATE_LIMITED` without verification, and the audit trail grows by at most one event per second for that address

### Requirement: Mandates without budget claims get alerts, not refusals
For a mandate with no `budget` claim and no `rate` on any entry, the history of the run SHALL NOT change any decision. The gateway SHALL instead record an `alert` event in the audit chain, naming the mandate `jti` and a reason, when: the mandate has been refused 5 times in a row (`ALERT_REFUSALS`); its family has received more than 200 distinct pupils (`ALERT_MANY_PUPILS`); or one pupil has been returned to 3 or more different mandates within an hour (`ALERT_PUPIL_TARGETED`, naming the pupil ID). Each alert SHALL be recorded once per mandate and reason, or for `ALERT_PUPIL_TARGETED` once per pupil per hour.

#### Scenario: The eval raises no refusals
- **WHEN** `make eval_run` sends 6 refusals in a row on one claim-less mandate and then allowed calls on it
- **THEN** every call gets the same decision as before, and an `ALERT_REFUSALS` alert is recorded once

#### Scenario: A pupil being targeted
- **WHEN** three different mandates each receive pupil `P0011` within an hour
- **THEN** one `ALERT_PUPIL_TARGETED` alert naming `P0011` is recorded, and the next call returning `P0011` is still allowed

#### Scenario: The person sees the alert
- **WHEN** an alert is recorded for a mandate delegated by `officer:jsmith`
- **THEN** `audit.events(principal="officer:jsmith")` lists it as an event of type `alert` with its reason

### Requirement: Limits are configurable
The gateway SHALL read its ceilings, default budgets and alert thresholds from a YAML file, `gateway/config/limits.yaml` by default or the file named by `GATEWAY_LIMITS_CONFIG`, with sections `ceilings`, `budgets` and `alerts`. Any value SHALL be overridable by an environment variable `GATEWAY_LIMIT_<SECTION>_<KEY>` in upper case. Values SHALL be non-negative integers, with `0` turning a ceiling or alert off; the default budgets `default_distinct_pupils` and `default_calls` MAY be `null` (none), which SHALL be their shipped value. A default budget SHALL apply only to mandates with no budget or rate claim of their own. The gateway MUST refuse to start when the file or an override names an unknown section or key, holds a value of the wrong kind, or when `GATEWAY_LIMITS_CONFIG` names a file that doesn't exist. `GET /describe` SHALL list the limits in effect.

#### Scenario: Override by environment
- **WHEN** the gateway starts with `GATEWAY_LIMIT_CEILINGS_PER_KEY_PER_MINUTE=600`
- **THEN** `GET /describe` shows `per_key_per_minute: 600` and the key ceiling is 600

#### Scenario: A typo stops the gateway
- **WHEN** the limits file has `ceilings: {per_key_per_minut: 5}`
- **THEN** the gateway refuses to start, naming the unknown key

#### Scenario: A default budget for mandates without claims
- **WHEN** `budgets.default_distinct_pupils` is set to 1, and a mandate with no budget claim receives one pupil and asks for another
- **THEN** the second call returns `429 BUDGET_EXHAUSTED`, while a mandate carrying its own `budget` is limited only by its own
