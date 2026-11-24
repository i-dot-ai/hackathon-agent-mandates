"""Hand an agent part of your access, then use it.

A mandate is a signed note from an issuer to an agent. It says what the agent may do, what it must
never do, and until when. The gateway checks the note on every call. The issuer can cancel it at any time.

    python -m gateway.cli init                                      # issuer: one-off setup
    python -m gateway.cli keygen -o agent.pem                       # agent: make a key, send the printed JWK
    python -m gateway.cli issue --agent-key team.jwk -o mandate.jwt # issuer: write a mandate for that key
    python -m gateway.cli discover --url http://localhost:8082      # agent: see what a gateway offers
    python -m gateway.cli revoke --idx 0                            # issuer: cancel mandate 0
    python -m gateway.cli decode mandate.jwt                        # anyone: read what a mandate says
    python -m gateway.cli audit anchor --url http://localhost:8082  # anyone: save the audit chain head locally
    python -m gateway.cli audit saw --mandate reader.jwt --agent-key reader.pem --jti <jti>  # what it received
    python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \\
        --server pupil-data --tool search --args '{"query": "P0004", "urn": "SCH01"}'

Keys and mandates live in $GATEWAY_STATE_DIR (default gateway/state). It holds private keys: never commit it.
"""

import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path

from gateway.lib.common import (
    b64u,
    b64u_decode,
    generate_keypair,
    jwk_to_pub,
    priv_from_pem,
    priv_to_pem,
    pub_from_pem,
    pub_to_jwk,
    pub_to_pem,
    sign_bytes,
    verify_bytes,
)
from gateway.lib.gateway_verify import Request
from gateway.lib.mandate_issuer import MandateIssuer
from gateway.lib.status_list import StatusListIssuer
from tool_grants import ensure_keypair

# search pupils of SCH01 only; get only the two files that hold no pupil data. Also the Day 2 attack mandate.
DEFAULT_SCOPE = [
    {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}},
    {
        "server": "pupil-data",
        "tools": ["get"],
        "constraints": {"path": ["synthetic/synthetic_schools.csv", "synthetic/synthetic_manifest.json"]},
    },
]
DEFAULT_DENY = ["*.write", "pii.*"]


def _load_status(state: Path) -> tuple[StatusListIssuer, dict]:
    meta = json.loads((state / "status_list.json").read_text())
    issuer = StatusListIssuer(meta["issuer"], meta["uri"], priv_from_pem((state / "issuer_key.pem").read_bytes()))
    issuer.bits = bytearray(b64u_decode(meta["bits_b64u"]))
    issuer._next = meta["next"]  # noqa: SLF001
    return issuer, meta


def _save_status(state: Path, issuer: StatusListIssuer, meta: dict) -> None:
    meta.update(next=issuer._next, bits_b64u=b64u(bytes(issuer.bits)))  # noqa: SLF001
    (state / "status_list.json").write_text(json.dumps(meta, indent=2))
    # a week: the gateway fails closed on a stale list and nothing republishes between CLI runs
    (state / "status_list.jwt").write_text(issuer.publish(ttl=7 * 86400))


def load_or_create_key(path: Path):
    if path.exists():
        return priv_from_pem(path.read_bytes())
    priv, _ = generate_keypair()
    path.write_bytes(priv_to_pem(priv))
    return priv


def load_agent_pub(path: Path):
    """Public key from a JWK JSON file, a public PEM or a private PEM; creates a private PEM if missing."""
    if not path.exists():
        return load_or_create_key(path).public_key()
    raw = path.read_bytes()
    if raw.lstrip().startswith(b"{"):
        return jwk_to_pub(json.loads(raw))
    if b"PRIVATE" in raw:
        return priv_from_pem(raw).public_key()
    return pub_from_pem(raw)


def scope_warnings(scope: list[dict]) -> list[str]:
    """Scope entries add up: the gateway allows a call if any one entry accepts it, and an entry only restricts
    the arguments it names. Entries for one tool that constrain different arguments are usually a mistake."""
    seen: dict[tuple[str, str], set[frozenset]] = {}
    for entry in scope:
        for tool in entry["tools"]:
            seen.setdefault((entry["server"], tool), set()).add(frozenset(entry.get("constraints", {})))
    return [
        f"warning: {server}.{tool} has entries constraining different arguments "
        f"({', '.join(str(sorted(k)) for k in sorted(keys, key=sorted))}); each entry is a separate grant, "
        "so the tool is as wide as its loosest entry"
        for (server, tool), keys in seen.items()
        if len(keys) > 1
    ]


def issue_mandate(
    state: Path,
    agent_pub,
    *,
    scope: list[dict],
    deny: list[str],
    ttl: int,
    purpose: str,
    principal: str,
    org: str,
    extra: dict | None = None,
) -> tuple[str, int]:
    """Issue a mandate from the state dir's issuer key. Returns (jwt, status-list index)."""
    for warning in scope_warnings(scope):
        print(warning, file=sys.stderr)
    status, meta = _load_status(state)
    idx = status._next  # noqa: SLF001
    token = MandateIssuer(meta["issuer"], meta["kid"], status.priv, status).issue(
        delegator={"principal": principal, "org": org, "authority": "hackathon"},
        delegate_pub=agent_pub,
        purpose=purpose,
        scope=scope,
        deny=deny,
        ttl=ttl,
        extra=extra,
    )
    _save_status(state, status, meta)
    return token, idx


def revoke_mandate(state: Path, idx: int) -> None:
    status, meta = _load_status(state)
    status.revoke(idx)
    _save_status(state, status, meta)


def sign_request(agent_priv, *, server: str, tool: str, arguments: dict, mandate: str) -> dict:
    req = Request(
        server=server,
        tool=tool,
        arguments=arguments,
        mandate=mandate,
        nonce=secrets.token_urlsafe(16),
        ts=int(time.time()),
        sig="",
    )
    req.sig = sign_bytes(agent_priv, req.signing_input())
    return req.__dict__


def cmd_init(a) -> None:
    state = a.state
    if (state / "trusted_list.json").exists() and not a.force:
        sys.exit(f"{state} already initialised; pass --force to overwrite")
    state.mkdir(parents=True, exist_ok=True)
    issuer_priv, issuer_pub = generate_keypair()
    gateway_priv, gateway_pub = generate_keypair()
    (state / "issuer_key.pem").write_bytes(priv_to_pem(issuer_priv))
    (state / "gateway_key.pem").write_bytes(priv_to_pem(gateway_priv))
    (state / "gateway.pub").write_bytes(pub_to_pem(gateway_pub))
    # tool grants (gateway -> MCP servers): the gateway signs, the servers get only tool_grant.pub
    for name in ("tool_grant_key.pem", "tool_grant.pub"):
        (state / name).unlink(missing_ok=True)
    ensure_keypair(state / "tool_grant_key.pem", state / "tool_grant.pub")
    trusted = {"issuers": {a.issuer: {a.kid: pub_to_jwk(issuer_pub)}}}
    (state / "trusted_list.json").write_text(json.dumps(trusted, indent=2))
    meta = {"issuer": a.issuer, "kid": a.kid, "uri": f"{a.issuer}/status/1", "next": 0, "bits_b64u": ""}
    _save_status(state, StatusListIssuer(a.issuer, meta["uri"], issuer_priv), meta)
    print(f"initialised {state}")


def cmd_issue(a) -> None:
    token, idx = issue_mandate(
        a.state,
        load_agent_pub(a.agent_key),
        scope=json.loads(a.scope),
        deny=json.loads(a.deny),
        ttl=a.ttl,
        purpose=a.purpose,
        principal=a.principal,
        org=a.org,
        extra=json.loads(a.claims),
    )
    if a.out:
        a.out.write_text(token)
        print(f"wrote mandate (status idx {idx}) to {a.out}")
    else:
        print(token)


def cmd_keygen(a) -> None:
    if a.out.exists():
        sys.exit(f"{a.out} already exists")
    priv = load_or_create_key(a.out)
    print(json.dumps(pub_to_jwk(priv.public_key())))


# ---------------------------------------------------------------- approvers (add-scope-requests)

APPROVER_LOGIN_TYP = "approver-login+jwt"
APPROVER_DECISION_TYP = "approver-decision+jwt"


def register_approver(state: Path, principal: str, pub) -> None:
    """Add a person's approver public key to the issuer's approvers.json."""
    path = state / "approvers.json"
    approvers = json.loads(path.read_text()) if path.exists() else {}
    approvers[principal] = pub_to_jwk(pub)
    path.write_text(json.dumps(approvers, indent=2))


def login_token(priv, principal: str, ttl: int = 300) -> str:
    """A one-time login token for the approval page, signed with the person's approver key."""
    import jwt  # noqa: PLC0415

    now = int(time.time())
    claims = {"sub": principal, "jti": secrets.token_urlsafe(16), "iat": now, "exp": now + ttl}
    return jwt.encode(claims, priv_to_pem(priv), algorithm="EdDSA", headers={"typ": APPROVER_LOGIN_TYP})


def decision_token(priv, principal: str, request_id: str, decision: str, approved: dict | None = None) -> str:
    """A person's decision on a scope request, signed with their approver key (single use)."""
    import jwt  # noqa: PLC0415

    from gateway.lib.common import canonical, sha256_hex  # noqa: PLC0415

    now = int(time.time())
    claims = {
        "sub": principal,
        "request_id": request_id,
        "decision": decision,
        "approved_hash": sha256_hex(canonical(approved)),
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(claims, priv_to_pem(priv), algorithm="EdDSA", headers={"typ": APPROVER_DECISION_TYP})


def cmd_approver_keygen(a) -> None:
    if a.out.exists():
        sys.exit(f"{a.out} already exists")
    priv = load_or_create_key(a.out)
    register_approver(a.state, a.principal, priv.public_key())
    print(f"approver key for {a.principal} written to {a.out}; public half registered in {a.state / 'approvers.json'}")


def cmd_approver_login(a) -> None:
    token = login_token(priv_from_pem(a.approver_key.read_bytes()), a.principal)
    target = f"/approve/{a.request}" if a.request else "/approve"
    print(f"{a.ui}/approve/login?token={token}&next={target}")


def cmd_approve(a) -> None:
    decision = "reject" if a.reject else "approve"
    if decision == "approve" and a.number is None:
        sys.exit("approving needs --number: the number the agent told you to choose")
    approved = json.loads(a.approved) if a.approved else None
    signed = decision_token(priv_from_pem(a.approver_key.read_bytes()), a.principal, a.request_id, decision, approved)
    body = {"decision": decision, "number": a.number, "approved": approved, "signed": signed}
    req = urllib.request.Request(  # noqa: S310
        f"{a.url}/requests/{a.request_id}/decision",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            status, text = resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    print(status)
    print(json.dumps(json.loads(text), indent=2))


def cmd_grant_key(a) -> None:
    ensure_keypair(a.state / "tool_grant_key.pem", a.state / "tool_grant.pub")
    print(f"tool grant key ready: {a.state / 'tool_grant.pub'}")


def cmd_discover(a) -> None:
    with urllib.request.urlopen(f"{a.url}/describe") as resp:  # noqa: S310
        print(json.dumps(json.load(resp), indent=2))


def cmd_revoke(a) -> None:
    revoke_mandate(a.state, a.idx)
    print(f"revoked idx {a.idx}")


def cmd_decode(a) -> None:
    # reads the claims only: the signature is not checked here, the gateway does that on every call
    payload = (a.mandate or a.state / "mandate.jwt").read_text().split(".")[1]
    print(json.dumps(json.loads(b64u_decode(payload)), indent=2))


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(  # noqa: S310
        f"{url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def cmd_call(a) -> None:
    body = sign_request(
        priv_from_pem(a.agent_key.read_bytes()),
        server=a.server,
        tool=a.tool,
        arguments=json.loads(a.args),
        mandate=a.mandate.read_text().strip(),
    )
    status, payload = _post(a.url, body)
    print(status)
    print(json.dumps(payload, indent=2))


# ---------------------------------------------------------------- audit trail (docs/audit-trail.md)


def cmd_audit_anchor(a) -> None:
    """Save the gateway's signed chain head on this machine, out of the gateway operator's reach."""
    with urllib.request.urlopen(f"{a.url}/audit/head") as resp:  # noqa: S310
        head = json.load(resp)
    if not verify_bytes(pub_from_pem(a.gateway_pub.read_bytes()), head["event_hash"].encode(), head["sig"]):
        sys.exit("head signature does not match the gateway key: not saved")
    with a.out.open("a") as f:
        f.write(json.dumps({**head, "url": a.url, "saved_at": int(time.time())}) + "\n")
    print(f"anchored seq {head['seq']} to {a.out}")


def cmd_audit_verify(a) -> None:
    """Recompute every hash and signature in the audit store and check saved anchors."""
    import asyncio  # noqa: PLC0415

    from gateway.lib import audit  # noqa: PLC0415

    if not a.db or not Path(a.db).exists():
        sys.exit(f"no audit database at {a.db!r}: pass --db or set {audit.AUDIT_DB_ENV}")
    store = audit.SqliteStore(None, Path(a.db), read_only=True)
    try:
        chain = asyncio.run(store.all_events())
    finally:
        store.close()
    anchors = [json.loads(line) for line in a.anchors.read_text().splitlines() if line.strip()] if a.anchors else []
    problems = audit.verify_chain(chain, pub_from_pem(a.gateway_pub.read_bytes()), anchors)
    if problems:
        print("\n".join(problems))
        sys.exit(1)
    print(f"chain intact: {len(chain)} events, {len(anchors)} anchors checked")


def _audit_call(a, tool: str, arguments: dict) -> None:
    body = sign_request(
        priv_from_pem(a.agent_key.read_bytes()),
        server="audit",
        tool=tool,
        arguments=arguments,
        mandate=a.mandate.read_text().strip(),
    )
    status, payload = _post(a.url, body)
    if status != HTTPStatus.OK:
        print(status)
        print(json.dumps(payload, indent=2))
        sys.exit(1)
    print(json.dumps(payload["result"], indent=2))


def cmd_audit_saw(a) -> None:
    _audit_call(a, "saw", {k: v for k, v in {"jti": a.jti, "principal": a.principal}.items() if v})


def cmd_audit_events(a) -> None:
    args = {"jti": a.jti, "principal": a.principal, "since": a.since, "until": a.until, "limit": a.limit}
    _audit_call(a, "events", {k: v for k, v in args.items() if v is not None})


def _add_audit_parsers(sub) -> None:
    s = sub.add_parser("audit", help="anchor, verify and read the gateway's audit trail")
    asub = s.add_subparsers(dest="audit_cmd", required=True)
    pub_default = lambda: Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state")) / "gateway.pub"  # noqa: E731

    t = asub.add_parser("anchor", help="save the gateway's signed chain head to a local file")
    t.add_argument("--url", default="http://localhost:8082", help="gateway address")
    t.add_argument("--gateway-pub", type=Path, default=pub_default(), help="the gateway's public key (PEM)")
    t.add_argument("-o", "--out", type=Path, default=Path("audit_anchors.jsonl"), help="file to append to")
    t.set_defaults(fn=cmd_audit_anchor)

    t = asub.add_parser("verify", help="check every hash, signature and saved anchor in the audit store")
    t.add_argument("--db", default=os.environ.get("GATEWAY_AUDIT_DB"), help="the audit SQLite file")
    t.add_argument("--anchors", type=Path, help="file of heads saved with `audit anchor`")
    t.add_argument("--gateway-pub", type=Path, default=pub_default(), help="the gateway's public key (PEM)")
    t.set_defaults(fn=cmd_audit_verify)

    for name, fn, text in (
        ("saw", cmd_audit_saw, "what a mandate received, in plain words (question 14)"),
        ("events", cmd_audit_events, "the request log for a principal or a mandate (question 16)"),
    ):
        t = asub.add_parser(name, help=text)
        t.add_argument("--mandate", type=Path, required=True, help="your audit-reader mandate")
        t.add_argument("--agent-key", type=Path, required=True, help="the key that mandate was issued to")
        t.add_argument("--jti", help="the mandate to read about")
        t.add_argument("--principal", help="the person whose mandates to read about")
        t.add_argument("--url", default="http://localhost:8082", help="gateway address")
        if name == "events":
            t.add_argument("--since", help="ISO time, inclusive")
            t.add_argument("--until", help="ISO time, inclusive")
            t.add_argument("--limit", type=int, help="at most this many events (max 500)")
        t.set_defaults(fn=fn)


def main(argv: list[str] | None = None) -> None:  # noqa: PLR0915  (one parser per subcommand)
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--state",
        type=Path,
        default=Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state")),
        help="folder holding keys and mandates",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="become an issuer: make the keys that sign mandates (run once)")
    s.add_argument("--issuer", default="https://issuer.hack.local", help="your name as an issuer")
    s.add_argument("--kid", default="issuer-2026-11", help="label for this signing key")
    s.add_argument("--force", action="store_true", help="replace existing keys")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("keygen", help="make an agent key; prints the public half for the issuer")
    s.add_argument("-o", "--out", type=Path, default=Path("agent.pem"), help="where to save the private key")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("approver-keygen", help="make a person's approver key and register it with the issuer")
    s.add_argument("--principal", required=True, help="the person, e.g. officer:jsmith")
    s.add_argument("-o", "--out", type=Path, required=True, help="where to save the private approver key")
    s.set_defaults(fn=cmd_approver_keygen)

    s = sub.add_parser("approver-login", help="print a one-time login link for the approval page")
    s.add_argument("--principal", required=True)
    s.add_argument("--approver-key", type=Path, required=True)
    s.add_argument("--request", help="request ID to open after signing in")
    s.add_argument("--ui", default=os.environ.get("FRONTEND_URL", "http://localhost:8081"), help="team UI address")
    s.set_defaults(fn=cmd_approver_login)

    s = sub.add_parser("approve", help="approve (or --reject) a scope request with your approver key")
    s.add_argument("request_id")
    s.add_argument("--principal", required=True)
    s.add_argument("--approver-key", type=Path, required=True)
    s.add_argument(
        "--number", type=int, help="the number the agent told you to choose (needed to approve); a wrong one ends it"
    )
    s.add_argument("--reject", action="store_true")
    s.add_argument("--approved", help="approve less than asked: JSON {scope, clearance, ttl}")
    s.add_argument("--url", default=os.environ.get("ISSUER_URL", "http://localhost:8083"), help="issuer address")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("grant-key", help="make sure the gateway's tool-grant key exists (servers mount the .pub)")
    s.set_defaults(fn=cmd_grant_key)

    s = sub.add_parser("discover", help="show what a gateway offers and how to sign a call")
    s.add_argument("--url", default="http://localhost:8082", help="gateway address")
    s.set_defaults(fn=cmd_discover)

    s = sub.add_parser("issue", help="write a mandate for an agent key")
    s.add_argument("--agent-key", type=Path, required=True, help="the agent's public key (JWK or PEM)")
    s.add_argument("--scope", default=json.dumps(DEFAULT_SCOPE), help="what the agent may do (JSON)")
    s.add_argument("--deny", default=json.dumps(DEFAULT_DENY), help="what it must never do (JSON)")
    s.add_argument("--ttl", type=int, default=7200, help="seconds until it expires")
    s.add_argument("--purpose", default="Pupil-data lookups for school SCH01", help="why the agent needs it")
    s.add_argument("--principal", default="officer:jsmith", help="the person handing over access")
    s.add_argument("--org", default="school:SCH01", help="who that person acts for")
    s.add_argument("--claims", default="{}", help="claims of your own to sign in, e.g. '{\"clearance\": 2}' (JSON)")
    s.add_argument("-o", "--out", type=Path, help="file to write to (default: print it)")
    s.set_defaults(fn=cmd_issue)

    s = sub.add_parser("revoke", help="cancel a mandate; takes effect on the next call")
    s.add_argument("--idx", type=int, required=True, help="number printed when it was issued")
    s.set_defaults(fn=cmd_revoke)

    s = sub.add_parser("decode", help="print a mandate's claims as JSON, without checking its signature")
    s.add_argument("mandate", type=Path, nargs="?", help="the mandate file (default: mandate.jwt in --state)")
    s.set_defaults(fn=cmd_decode)

    s = sub.add_parser("call", help="ask the gateway to run a tool, using a mandate")
    s.add_argument("--mandate", type=Path, required=True, help="the mandate file")
    s.add_argument("--agent-key", type=Path, required=True, help="private key the mandate was issued to")
    s.add_argument("--server", default="pupil-data", help="which data server behind the gateway")
    s.add_argument("--tool", required=True, help="tool name, e.g. search")
    s.add_argument("--args", default="{}", help="tool arguments (JSON)")
    s.add_argument("--url", default="http://localhost:8082", help="gateway address")
    s.set_defaults(fn=cmd_call)

    _add_audit_parsers(sub)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
