"""Hand an agent part of your access, then use it.

A mandate is a signed note from an issuer to an agent. It says what the agent may do, what it must
never do, and until when. The gateway checks the note on every call. The issuer can cancel it at any time.

    python -m gateway.cli init                                      # issuer: one-off setup
    python -m gateway.cli keygen -o agent.pem                       # agent: make a key, send the printed JWK
    python -m gateway.cli issue --agent-key team.jwk --clearance 4 --role safeguarding-lead -o mandate.jwt
    python -m gateway.cli discover --url http://localhost:8082      # agent: see what a gateway offers
    python -m gateway.cli revoke --idx 0                            # issuer: cancel mandate 0
    python -m gateway.cli decode mandate.jwt                        # anyone: read what a mandate says
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
import urllib.request
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
)
from gateway.lib.gateway_verify import Request
from gateway.lib.mandate_issuer import MandateIssuer
from gateway.lib.status_list import StatusListIssuer

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
        extra={"clearance": a.clearance, **({"role": a.role} if a.role else {}), **json.loads(a.claims)},
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


def cmd_call(a) -> None:
    body = sign_request(
        priv_from_pem(a.agent_key.read_bytes()),
        server=a.server,
        tool=a.tool,
        arguments=json.loads(a.args),
        mandate=a.mandate.read_text().strip(),
    )
    req = urllib.request.Request(  # noqa: S310
        f"{a.url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310
            status, text = resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    print(status)
    print(json.dumps(json.loads(text), indent=2))


def main(argv: list[str] | None = None) -> None:
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

    s = sub.add_parser("discover", help="show what a gateway offers and how to sign a call")
    s.add_argument("--url", default="http://localhost:8082", help="gateway address")
    s.set_defaults(fn=cmd_discover)

    s = sub.add_parser("issue", help="write a mandate for an agent key")
    s.add_argument("--agent-key", type=Path, required=True, help="the agent's public key (JWK or PEM)")
    s.add_argument(
        "--clearance",
        type=int,
        choices=[1, 2, 3, 4],
        required=True,
        help="PII level the agent may receive: 1 public to 4 special category (required)",
    )
    s.add_argument(
        "--role",
        help="a role the person holds, signed in for the agent; level 4 also needs a role the gateway lists",
    )
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

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
