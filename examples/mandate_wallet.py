"""An agent's run wallet (OpenSpec add-run-reuse): every mandate it holds for one job, kept across restarts.

A run is one base mandate (the one the person issued for the job) and every supplementary mandate minted from
requests it made. The wallet:

    pick(server, tool, arguments)   the mandate to sign this call with: the narrowest held mandate whose scope
                                    allows it, else the base mandate (so a refusal and grants.check work as usual)
    absorb(result)                  keep the mandate from an approved grants.status or an already_granted
                                    grants.request result
    save() / RunWallet.load(...)    a small JSON file, so a restarted agent keeps its approvals

It reads mandates without verifying them, only to choose one; the gateway verifies every call. Requests for more
access (grants.request) must always be signed with `wallet.base`.

    wallet = RunWallet.load(Path("run_wallet.json"), base_mandate)
    body = sign_request(key, server=s, tool=t, arguments=a, mandate=wallet.pick(s, t, a))
    ...
    wallet.absorb(response["result"]); wallet.save()
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import jwt

from gateway.lib.gateway_verify import Request, check_request

# held is fine too: it means the mandate covers the call and the gateway will ask for approval
COVERS = ("ALLOW", "STEP_UP")


def claims_of(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


class RunWallet:
    def __init__(self, path: Path, base: str, minted: list[str] | None = None):
        self.path = Path(path)
        self.base = base.strip()
        self.base_jti = claims_of(self.base)["jti"]
        self.minted: list[str] = []
        for token in minted or []:
            self.add(token)

    @classmethod
    def load(cls, path: Path, base: str) -> RunWallet:
        """The wallet for this base mandate. A file from another run (another base mandate) is ignored."""
        path = Path(path)
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            doc = {}
        wallet = cls(path, base)
        if doc.get("base_jti") == wallet.base_jti:
            for token in doc.get("minted", []):
                wallet.add(token)
        return wallet

    def save(self) -> None:
        self.path.write_text(json.dumps({"base_jti": self.base_jti, "minted": self.valid()}, indent=2))

    def add(self, token: str) -> bool:
        """Keep a supplementary mandate of this run. Returns False for one that isn't (or has expired)."""
        token = token.strip()
        try:
            claims = claims_of(token)
        except jwt.PyJWTError:
            return False
        parent = claims.get("parent") or {}
        if parent.get("jti") != self.base_jti or claims.get("exp", 0) <= time.time() or token in self.minted:
            return False
        self.minted.append(token)
        return True

    def absorb(self, result: dict | None) -> bool:
        """Keep the mandate in a grants.status or grants.request result, if it has one."""
        mandate = (result or {}).get("mandate")
        return bool(mandate) and self.add(mandate)

    def valid(self) -> list[str]:
        now = time.time()
        self.minted = [t for t in self.minted if claims_of(t).get("exp", 0) > now]
        return list(self.minted)

    def pick(self, server: str, tool: str, arguments: dict) -> str:
        """The narrowest held mandate whose scope allows this call; the base mandate if none does."""
        req = Request(server=server, tool=tool, arguments=arguments, mandate="", nonce="", ts=0, sig="")
        candidates = [*self.valid(), self.base]  # supplementary first: they are narrower
        for token in candidates:
            claims = claims_of(token)
            if claims.get("exp", 0) <= time.time():
                continue
            decision, _, _ = check_request(req, claims.get("scope", []), claims.get("deny", []), [], claims)
            if decision in COVERS:
                return token
        return self.base
