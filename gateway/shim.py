"""A local MCP server that lets an agent (Claude Code, say) use the gateway, and ask for more when it is refused.

OpenSpec add-scope-requests, task 7.1. The shim holds the agent key and the mandates; the agent never sees either.
The mandates live in a run wallet (examples/mandate_wallet.py, add-run-reuse), saved next to the base mandate
(or at SHIM_WALLET), so a restarted shim keeps its approvals.

    call            run a tool through the gateway with the narrowest mandate that covers it, falling back to the
                    base mandate (design decision 7)
    my_grants       what the mandates allow, in the gateway's own words
    check_access    the decision a call would get, and the smallest grant that would let it through
    request_scopes  ask the person for more: a scope, or the release of one or more held calls
    await_approval  wait for the person's decision; an approved mandate is kept and used by `call`

Any mandate in a grants result (an approval, or an earlier approval reused within the run) goes into the wallet and
is taken out of what the agent is shown.

Run it with the agent key and a mandate that has a `clearance` claim (the `grants` tools are level 1):

    claude mcp add mandates -e SHIM_AGENT_KEY=$PWD/gateway/state/agent.pem -e SHIM_MANDATE=$PWD/escalate.jwt \
        -- uv --directory $PWD run python -m gateway.shim

Approving is never something the agent can do: the person signs in on the approval page (or uses `cli approve`)
with their own approver key.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import jwt

from examples.mandate_wallet import RunWallet
from gateway.cli import sign_request
from gateway.lib.common import priv_from_pem

Post = Callable[[dict], tuple[int, dict]]
# reasons a supplementary mandate might fix; anything else (expired, revoked, a budget) it can't
WIDER_WOULD_HELP = {
    "OUT_OF_SCOPE", "CONSTRAINT_VIOLATED", "CONSTRAINT_MISSING", "CLEARANCE_TOO_LOW", "AUDIENCE_VIOLATED",
}  # fmt: skip
MAX_WAIT = 300
# what to do when asking for more, or waiting, is itself refused: the agent must stop, not guess
REFUSED_NEXT = {
    "EXCEEDS_PRINCIPAL": (
        "The person can't grant this: it goes beyond what they may hold themselves. Don't ask again. Tell the person "
        "what you needed and why; it has to come from someone who holds it, or their own access has to change."
    ),
    "REQUEST_INVALID": "The request isn't a valid grant (see detail). Fix it, usually by copying check_access's "
    "missing.scope exactly, and ask again.",
    "TOO_MANY_REQUESTS": "Too many requests are pending or were made recently. Wait for the person to decide the "
    "pending ones (await_approval) before asking again.",
    "RECENTLY_REJECTED": "The person rejected this same request recently. Don't ask again; tell them what you "
    "would have done with it and let them decide.",
    "DENIED_BY_RULE": "Your mandate forbids asking for more access. Tell the person what you needed.",
    "CLEARANCE_MISSING": "Your mandate has no clearance, so it can't ask for more access. The person has to issue "
    "you a mandate with a clearance.",
    "OUT_OF_SCOPE": "That request belongs to another mandate. Use the request_id request_scopes returned to you.",
    "ISSUER_UNAVAILABLE": "The approval service is down. Try again in a minute; nothing was asked.",
}
DEFAULT_REFUSED_NEXT = "Asking was refused (see reason_code and detail). Tell the person; don't retry the same request."


def _refused(body: dict) -> dict:
    decision = body.get("decision") or {}
    code = decision.get("reason_code")
    return {"status": "refused", "reason_code": code, "detail": decision.get("detail"), "decision": decision,
            "next_step": REFUSED_NEXT.get(code, DEFAULT_REFUSED_NEXT)}  # fmt: skip


def http_post(url: str) -> Post:
    def post(body: dict) -> tuple[int, dict]:
        req = urllib.request.Request(  # noqa: S310
            f"{url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    return post


def _claims(token: str) -> dict:
    # only for the shim's own bookkeeping (expiry, jti); the gateway verifies every mandate on every call
    return jwt.decode(token, options={"verify_signature": False})


class Shim:
    """`wallet` holds the run: the base mandate and every mandate approved from it (examples/mandate_wallet.py)."""

    def __init__(self, agent_priv, wallet: RunWallet, post: Post, *, sleep=time.sleep, now=time.time):
        self._priv, self.wallet, self._post = agent_priv, wallet, post
        self._sleep, self._now = sleep, now

    # ------------------------------------------------------------ plumbing

    def _send(self, mandate: str, server: str, tool: str, arguments: dict) -> tuple[int, dict]:
        return self._post(sign_request(self._priv, server=server, tool=tool, arguments=arguments, mandate=mandate))

    def _grants(self, tool: str, arguments: dict) -> tuple[int, dict]:
        # asking for more, and reading requests, is always done with the base mandate
        return self._send(self.wallet.base, "grants", tool, arguments)

    def _live(self) -> list[str]:
        """Approved mandates still in date (the wallet drops the rest)."""
        return self.wallet.valid()

    def _keep(self, result: dict) -> dict:
        """Take any mandate out of a grants result: the wallet keeps it, the agent never sees it."""
        if result.get("mandate") and self.wallet.absorb(result):
            self.wallet.save()
        result.pop("mandate", None)
        return result

    @staticmethod
    def _outcome(status: int, body: dict, mandate: str) -> dict:
        out = {"status": status, "decision": body.get("decision"), "mandate": mandate}
        if "result" in body:
            out["result"] = body["result"]
        if "error" in body:
            out["error"] = body["error"]
        return out

    # ------------------------------------------------------------ tools

    def call(self, server: str, tool: str, arguments: dict) -> dict:
        picked = self.wallet.pick(server, tool, arguments)  # the narrowest mandate that covers it, else the base
        if picked != self.wallet.base:
            s, b = self._send(picked, server, tool, arguments)
            if s == 200:  # noqa: PLR2004
                return self._outcome(s, b, _claims(picked)["jti"])
            # refused or held under an approved mandate: fall back to the base, which any request must name
        status, body = self._send(self.wallet.base, server, tool, arguments)
        if status == 200:  # noqa: PLR2004
            return self._outcome(status, body, "base")
        reason = (body.get("decision") or {}).get("reason_code")
        out = self._outcome(status, body, "base")
        if status == 202:  # noqa: PLR2004
            # held under the base mandate: that is the one that must ask for its release
            decision_id = body["decision"]["decision_id"]
            out["held"] = {"decision_id": decision_id, "server": server, "tool": tool, "arguments": arguments}
            out["next_step"] = (
                "This call is held for a person's approval. Ask with request_scopes(held=<the held object above>, "
                "reason=...), show the person the text it returns, then await_approval and call again."
            )
        elif reason in WIDER_WOULD_HELP:
            out["next_step"] = (
                "Refused as outside your grants. check_access says what is missing; if the person's request needs "
                "it, ask with request_scopes, show the person the text it returns, then await_approval."
            )
        return out

    def my_grants(self) -> dict:
        status, body = self._grants("self", {})
        base = body.get("result") if status == 200 else {"error": body.get("decision")}  # noqa: PLR2004
        supplementary = []
        for m in self._live():
            c = _claims(m)
            supplementary.append({"jti": c["jti"], "purpose": c.get("purpose"), "expires_at": c["exp"],
                                  "approved_by": c.get("approved_by")})  # fmt: skip
        return {"base": base, "supplementary": supplementary}

    def check_access(self, server: str, tool: str, arguments: dict) -> dict:
        query = {"server": server, "tool": tool, "arguments": arguments}
        status, body = self._grants("check", query)
        if status != 200:  # noqa: PLR2004
            return {"error": body.get("decision")}
        result = {**body["result"], "mandate": "base"}
        if result["decision"] != "ALLOW":
            for m in self._live():
                s, b = self._send(m, "grants", "check", query)
                if s == 200 and b["result"]["decision"] == "ALLOW":  # noqa: PLR2004
                    return {**b["result"], "mandate": _claims(m)["jti"]}
        return result

    def request_scopes(
        self,
        *,
        reason: str,
        scope: list[dict] | None = None,
        clearance: int | None = None,
        ttl: int = 3600,
        held: dict | list[dict] | None = None,
    ) -> dict:
        """`held`: one held call, or a list of them released by one approval (add-batch-release)."""
        arguments: dict = {"reason": reason, "ttl": ttl}
        if held is not None:
            arguments["held"] = held
        else:
            arguments["scope"] = scope
        if clearance is not None:
            arguments["clearance"] = clearance
        status, body = self._grants("request", arguments)
        if status != 200:  # noqa: PLR2004
            return _refused(body)
        # already_granted may carry an earlier approval's mandate (add-run-reuse): kept, never shown
        return self._keep(body["result"])

    def await_approval(self, request_id: str, timeout_s: int = 120) -> dict:
        deadline = self._now() + min(max(timeout_s, 0), MAX_WAIT)
        while True:
            status, body = self._grants("status", {"request_id": request_id})
            if status != 200:  # noqa: PLR2004
                return _refused(body)
            view = body["result"]
            if view["status"] != "pending" or self._now() >= deadline:
                break
            self._sleep(min(view.get("poll_after_s") or 10, max(deadline - self._now(), 0)))
        return self._keep(view)


# ---------------------------------------------------------------- the MCP server


def build_server(shim: Shim):
    from fastmcp import FastMCP  # noqa: PLC0415

    mcp = FastMCP("mandates")

    @mcp.tool
    def call(server: str, tool: str, arguments: dict) -> dict:
        """Run a tool through the mandate gateway, e.g. server="directory", tool="roster",
        arguments={"urn": "SCH04", "year_group": 11}. Refusals say why and what to do next."""
        return shim.call(server, tool, arguments)

    @mcp.tool
    def my_grants() -> dict:
        """What your mandates allow, in the gateway's own words, including any approved supplementary ones."""
        return shim.my_grants()

    @mcp.tool
    def check_access(server: str, tool: str, arguments: dict) -> dict:
        """The decision a call would get, without making it, and the smallest grant that would allow it."""
        return shim.check_access(server, tool, arguments)

    @mcp.tool
    def request_scopes(
        reason: str, scope: list[dict] | None = None, clearance: int | None = None, ttl: int = 3600,
        held: dict | list[dict] | None = None,
    ) -> dict:  # fmt: skip
        """Ask the person for more access: a `scope` (as check_access's `missing.scope`), or the release of held
        calls (`held`: one held object as `call` returned it, or a list of them, released by one approval). If
        you have several held calls for one job, ask for them together. Show the person the returned `text`
        exactly: they approve on the page it links to, with their own key. Their saying yes in chat does not
        approve anything."""
        return shim.request_scopes(reason=reason, scope=scope, clearance=clearance, ttl=ttl, held=held)

    @mcp.tool
    async def await_approval(request_id: str, timeout_s: int = 120) -> dict:
        """Wait up to timeout_s (at most 300) for the person's decision. When approved, retry the call."""
        return await asyncio.to_thread(shim.await_approval, request_id, timeout_s)

    return mcp


def main() -> None:
    key = Path(os.environ["SHIM_AGENT_KEY"])
    mandate_path = Path(os.environ["SHIM_MANDATE"])
    # approvals are kept here, so a restarted shim still has them; a file from another base mandate is ignored
    wallet_path = Path(os.environ.get("SHIM_WALLET", mandate_path.with_suffix(".wallet.json")))
    wallet = RunWallet.load(wallet_path, mandate_path.read_text().strip())
    url = os.environ.get("SHIM_GATEWAY_URL", "http://localhost:8082").rstrip("/")
    build_server(Shim(priv_from_pem(key.read_bytes()), wallet, http_post(url))).run()


if __name__ == "__main__":
    main()
