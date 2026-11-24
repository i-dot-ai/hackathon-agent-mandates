# Deploying for Day 2

Only the gateway is public. Everything else stays on the Compose network or the host's loopback.

| Service | Reachable at | Why |
| --- | --- | --- |
| gateway | `:8082`, public | The one way in: `POST /tools/call` |
| backend (MCP), slices | Compose network only | Only the gateway calls them, with a signed tool grant |
| frontend (approval page) | `127.0.0.1:8081` | For your approvers, through an SSH tunnel |
| issuer | `127.0.0.1:8083` | The CLI's `approve`; the UI and gateway reach it over the network |

`docker-compose.deploy.yaml` makes these changes on top of the base file:
- it removes the backend's published port;
- it binds the UI to loopback;
- it forces the `/demo` routes off.

## Where the issuer key lives

The issuer key (`gateway/state/issuer_key.pem`) signs every mandate and the revocation list. Anyone holding it can
grant anything, and a leaked key scores 50 points on Day 2. The gateway container no longer has it; only the issuer
service mounts it. Pick one setup:

| | Key on the server, in the issuer container | Key on a laptop only |
| --- | --- | --- |
| Approvals during Day 2 (scope requests, released held calls) | Work | Don't: the issuer can't mint |
| Revoking a team's mandate | `cli revoke` on the server | `cli revoke` on the laptop, then copy `status_list.jwt` and `status_list.json` to the server |
| Who can take the key | Anyone with a shell on the server | Nobody on the server |

- **Showing approvals live:** use the first setup and keep shell access to the server to the team.
- **Otherwise:** use the second. Run `make hack` on the laptop, then copy to the server only the public files the
  gateway mounts:
  - `trusted_list.json`, `status_list.json`, `status_list.jwt`;
  - `gateway_key.pem`, `gateway.pub`;
  - `tool_grant_key.pem`, `tool_grant.pub`.

  Leave out the `issuer` service: requests to `grants.request` then fail closed.

Either way, issue the attack mandates with `make attack_mandates` on the machine that holds the key, and post only
the `.jwt` files. Never post or copy `*.pem` beyond the list above.

## Steps

1. **On the server:** `make install`, and put the state files in place (above).
2. **Start:** `make deploy_up`.
3. **Check from outside the server:** `make deploy_check DEPLOY_URL=http://<host>:8082`. Wants:
   - 32/32, question 0 at 12/12;
   - demo routes `404`;
   - `{"store": "sqlite", "durable": true}`.

   Don't post the URL until all three hold.
4. **Mandates:** put each attacking team's `<team>.jwk` in `day_2_attack/keys/`, run `make attack_mandates` (with
   `FEATURE_SCOPE` and `FEATURE_CLAIMS` for the feature mandate), and post `day_2_attack/mandates/` with the
   enforcement note.
5. **During the attack window:**
   - from a laptop, not the server, save the audit chain head every minute:
     `while true; do uv run python -m gateway.cli audit anchor --url http://<host>:8082; sleep 60; done`
   - watch for `ALERT_PUPIL_TARGETED` and `ALERT_REFUSALS` with `cli audit events`, using a reader mandate for your
     principal ([audit-trail.md](audit-trail.md)).
6. **Afterwards:** check the chain against the saved heads, `cli audit verify --db <copy> --anchors audit_anchors.jsonl`.

## Changed for Day 2 (this change)

- **No grace on `exp`.** A mandate is refused from the second it expires. The 30 seconds of clock skew stay on `nbf`
  only, where they forgive a freshly issued mandate. An expired mandate accepted for 30 seconds would have scored as a
  "Dead mandate".
- **`/demo` is off unless `GATEWAY_ENABLE_DEMO=1`.** It answers `404`. The walkthrough at `:8081/demo` no longer works
  even with the variable set: it mints and revokes with the issuer key, which stays with the issuer service. Use the
  CLI (`cli issue`, `cli call`, `cli revoke`) instead.
