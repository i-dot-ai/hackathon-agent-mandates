"""Zero-trust grants for the gateway -> tool hop (OpenSpec add-scope-requests, capability tool-grants).

The gateway signs one short-lived, single-use grant per forwarded call. It names the server and tool, the exact
arguments, whose data the call may concern (schools, pupils), the highest data level it may return and a row cap.
The MCP servers verify it and apply it to their own output, so a gateway bug, or a caller that reaches a server
directly, gets no more than one grant allows.

Shared by the gateway (mint) and the servers (verify, check_args, enforce). Self-contained on purpose: the server
images copy only this package, not the gateway.
"""

from __future__ import annotations

import base64
import contextvars
import functools
import hashlib
import inspect
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TYP = "tool-grant+jwt"
ISSUER = "mandate-gateway"
HEADER = "x-tool-grant"
TTL = 30  # seconds a grant lives
SKEW = 5  # seconds of clock skew tolerated between containers
DEFAULT_MAX_ROWS = 100
UNLISTED_LEVEL = 4
# columns tools derive rather than read: their level, not the unlisted default
DERIVED_LEVELS = {"letter": 2, "total": 1, "count": 1}
PUPIL_ID = re.compile(r"^P\d{4}$")

# the verified grant for the tool call being served over HTTP; None for in-process calls
current_grant: contextvars.ContextVar[Grant | None] = contextvars.ContextVar("current_grant", default=None)
# set for every request that came in over HTTP through GrantMiddleware: such a call must carry a grant
over_http: contextvars.ContextVar[bool] = contextvars.ContextVar("over_http", default=False)


class GrantError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


# ---------------------------------------------------------------- encoding


def canonical(obj: Any) -> bytes:
    """Same canonical JSON as gateway.lib.common.canonical, so both sides hash the same bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def args_hash(arguments: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(arguments)).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------- keys


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("tool grant key must be Ed25519")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("tool grant public key must be Ed25519")
    return key


def ensure_keypair(priv_path: Path, pub_path: Path) -> Ed25519PrivateKey:
    """Load the grant signing key, creating it (and its public half) on first use."""
    if priv_path.exists():
        priv = load_private(priv_path)
    else:
        priv = Ed25519PrivateKey.generate()
        priv_path.write_bytes(
            priv.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
    if not pub_path.exists():
        pub_path.write_bytes(
            priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
    return priv


# ---------------------------------------------------------------- the grant


@dataclass(frozen=True)
class Grant:
    jti: str
    server: str
    tool: str
    args_hash: str
    mandate_jti: str
    agent_id: str | None
    principal: str | None
    level: int
    urns: tuple[str, ...] | None
    pupils: frozenset[str] | None
    constraints: dict = field(default_factory=dict)
    max_rows: int = DEFAULT_MAX_ROWS
    exp: int = 0


def mint(
    priv: Ed25519PrivateKey,
    *,
    server: str,
    tool: str,
    arguments: dict,
    decision_id: str,
    mandate_jti: str,
    agent_id: str | None,
    principal: str | None,
    level: int,
    urns: list[str] | None,
    pupils: list[str] | None,
    constraints: dict,
    max_rows: int,
    now: float | None = None,
) -> str:
    now = int(now if now is not None else time.time())
    claims = {
        "iss": ISSUER,
        "aud": server,
        "tool": tool,
        "args_hash": args_hash(arguments),
        "jti": decision_id,
        "sub": mandate_jti,
        "agent_id": agent_id,
        "principal": principal,
        "level": level,
        "subjects": {"urns": urns, "pupils": pupils},
        "constraints": constraints,
        "max_rows": max_rows,
        "iat": now,
        "exp": now + TTL,
    }
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return jwt.encode(claims, pem, algorithm="EdDSA", headers={"typ": TYP})


def verify(token: str | None, pub: Ed25519PublicKey, *, server: str, tool: str, arguments: dict) -> Grant:
    """The verified grant for this exact call. Raises GrantError. Replay is checked separately (SeenGrants)."""
    if not token:
        raise GrantError("GRANT_MISSING")
    try:
        if jwt.get_unverified_header(token).get("typ") != TYP:
            raise GrantError("GRANT_INVALID", "wrong token type")
        pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        claims = jwt.decode(
            token,
            pem,
            algorithms=["EdDSA"],
            audience=server,
            issuer=ISSUER,
            leeway=SKEW,
            options={"require": ["exp", "iat", "jti", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError as e:
        raise GrantError("GRANT_EXPIRED") from e
    except jwt.InvalidAudienceError as e:
        raise GrantError("GRANT_MISMATCH", "grant is for another server") from e
    except jwt.PyJWTError as e:
        raise GrantError("GRANT_INVALID", type(e).__name__) from e
    if claims.get("tool") != tool:
        raise GrantError("GRANT_MISMATCH", "grant is for another tool")
    if claims.get("args_hash") != args_hash(arguments):
        raise GrantError("GRANT_MISMATCH", "arguments differ from the granted ones")
    subjects = claims.get("subjects") or {}
    level = claims.get("level")
    max_rows = claims.get("max_rows")
    if type(level) is not int or type(max_rows) is not int:
        raise GrantError("GRANT_INVALID", "malformed level or max_rows")
    return Grant(
        jti=claims["jti"],
        server=server,
        tool=tool,
        args_hash=claims["args_hash"],
        mandate_jti=claims.get("sub"),
        agent_id=claims.get("agent_id"),
        principal=claims.get("principal"),
        level=level,
        urns=tuple(subjects["urns"]) if subjects.get("urns") is not None else None,
        pupils=frozenset(subjects["pupils"]) if subjects.get("pupils") is not None else None,
        constraints=claims.get("constraints") or {},
        max_rows=max_rows,
        exp=claims["exp"],
    )


class SeenGrants:
    """Grant IDs a server has already served, kept for twice a grant's lifetime."""

    def __init__(self, keep: int = 2 * TTL):
        self.keep = keep
        self._seen: dict[str, float] = {}

    def check_and_add(self, jti: str, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        for k in [k for k, t in self._seen.items() if t < now - self.keep]:
            del self._seen[k]
        if jti in self._seen:
            raise GrantError("GRANT_REPLAYED")
        self._seen[jti] = now


# ---------------------------------------------------------------- enforcement at the tool


def check_args(grant: Grant, arguments: dict) -> None:
    """Refuse (GRANT_SCOPE) a call whose arguments reach outside the grant, before the tool runs."""
    urn = arguments.get("urn")
    if grant.urns is not None and urn is not None and str(urn) not in grant.urns:
        raise GrantError("GRANT_SCOPE", f"urn={urn!r}")
    if grant.pupils is not None:
        named = []
        if "pupil_id" in arguments:
            named.append(str(arguments["pupil_id"]))
        ids = arguments.get("pupil_ids")
        if isinstance(ids, list):
            named.extend(str(p) for p in ids)
        for p in named:
            if p not in grant.pupils:
                raise GrantError("GRANT_SCOPE", f"pupil {p}")
    for k, allowed in grant.constraints.items():
        if k not in arguments:
            raise GrantError("GRANT_SCOPE", f"{k} missing")
        value = arguments[k]
        if k == "path" and isinstance(value, str):
            import posixpath  # noqa: PLC0415

            value = posixpath.normpath(value)
        if str(value) not in set(map(str, allowed)):
            raise GrantError("GRANT_SCOPE", f"{k}={arguments[k]!r}")


def _row_allowed(row: dict, grant: Grant, urn_arg: str | None) -> bool:
    school = row.get("URN", urn_arg)
    if grant.urns is not None and school not in grant.urns:
        return False
    if grant.pupils is not None:
        pupil = row.get("Psuedo ID", row.get("pupil_id"))
        if pupil not in grant.pupils:
            return False
    return True


def _project(row: dict, grant: Grant, level_of) -> dict:
    return {k: v for k, v in row.items() if level_of(k) <= grant.level}


def matches_visible(row: dict, query: str) -> bool:
    """A search hit only if the query is in a column the caller may see. The server matched the whole row, so
    without this the choice of rows would reveal a stripped value (search "ASIA" returns exactly those pupils)."""
    return query.lower() in ",".join(str(v) for v in row.values()).lower()


def enforce(data: Any, grant: Grant | None, arguments: dict, level_of) -> Any:
    """Apply a grant to a tool's output: rows outside its schools or pupils dropped, columns above its level
    dropped, a search's rows kept only if its query matches a column left, at most max_rows rows.
    `level_of(column)` gives a column's data level. No grant (in process): as is.
    """
    if grant is None:
        return data
    urn_arg = arguments.get("urn")
    query = arguments.get("query")
    if isinstance(data, list):
        rows = [r for r in data if not isinstance(r, dict) or _row_allowed(r, grant, urn_arg)]
        rows = [_project(r, grant, level_of) if isinstance(r, dict) else r for r in rows]
        if isinstance(query, str):
            rows = [r for r in rows if not isinstance(r, dict) or matches_visible(r, query)]
        return rows[: grant.max_rows]
    if isinstance(data, dict) and data and ("Psuedo ID" in data or "URN" in data):
        if not _row_allowed(data, grant, urn_arg):
            return {}
        return _project(data, grant, level_of)
    return data


def column_levels(manifest_path: Path) -> dict[str, int]:
    """Each column name's highest level in any table of the manifest's classification."""
    try:
        columns = json.loads(manifest_path.read_text())["classification"]["columns"]
    except (OSError, KeyError, ValueError):
        return {}
    levels: dict[str, int] = {}
    for table in columns.values():
        for name, level in table.items():
            levels[name] = max(levels.get(name, 0), level)
    return levels


def level_function(manifest_path: Path):
    levels = column_levels(manifest_path)

    def level_of(column: str) -> int:
        return levels.get(column, DERIVED_LEVELS.get(column, UNLISTED_LEVEL))

    return level_of


def granted(level_of):
    """Decorate a tool function: check its arguments against the current grant, then enforce it on the output."""

    def wrap(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def tool(*args, **kwargs):
            grant = current_grant.get()
            if grant is None:
                if over_http.get():  # fail closed: an HTTP tool call that reached here without a verified grant
                    from fastmcp.exceptions import ToolError  # noqa: PLC0415

                    raise ToolError("GRANT_MISSING")
                return fn(*args, **kwargs)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments = dict(bound.arguments)
            try:
                check_args(grant, arguments)
            except GrantError as e:
                from fastmcp.exceptions import ToolError  # noqa: PLC0415

                raise ToolError(str(e)) from e
            return enforce(fn(*args, **kwargs), grant, arguments, level_of)

        return tool

    return wrap


# ---------------------------------------------------------------- HTTP entry point


def mode() -> str:
    """'enforce' (the default) or 'off'. Turning grants off needs TOOL_GRANTS=off said out loud."""
    value = os.environ.get("TOOL_GRANTS", "enforce").strip().lower()
    if value not in ("enforce", "off"):
        msg = f"TOOL_GRANTS must be 'enforce' or 'off', not {value!r}"
        raise RuntimeError(msg)
    return value


class GrantMiddleware:
    """ASGI middleware for one MCP HTTP app: every JSON-RPC tools/call must carry a valid, unused grant.

    initialize, tools/list and other methods pass through, so discovery keeps working. A refused call gets a
    tool error naming the reason, and the tool never runs.
    """

    def __init__(self, app, server: str, pub_path: Path | None):
        self.app, self.server = app, server
        self.pub = load_public(pub_path) if pub_path and pub_path.exists() else None
        self.seen = SeenGrants()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        marker = over_http.set(True)
        try:
            return await self._handle(scope, receive, send)
        finally:
            over_http.reset(marker)

    async def _handle(self, scope, receive, send):
        if scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        body = b""
        more = True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)

        replayed = False

        async def replay():
            # hand the buffered body over once, then fall through to the real channel (disconnect detection)
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        try:
            rpc = json.loads(body or b"{}")
        except ValueError:
            return await self.app(scope, replay, send)
        if not isinstance(rpc, dict) or rpc.get("method") != "tools/call":
            return await self.app(scope, replay, send)

        params = rpc.get("params") or {}
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        try:
            if self.pub is None:
                raise GrantError("GRANT_INVALID", "server has no grant key")
            grant = verify(
                headers.get(HEADER),
                self.pub,
                server=self.server,
                tool=str(params.get("name")),
                arguments=params.get("arguments") or {},
            )
            self.seen.check_and_add(grant.jti)
        except GrantError as e:
            return await _tool_error(send, rpc.get("id"), str(e))
        token = current_grant.set(grant)
        try:
            return await self.app(scope, replay, send)
        finally:
            current_grant.reset(token)


async def _tool_error(send, rpc_id, text: str) -> None:
    try:  # the MCP library's own model, so the result matches the protocol version in use
        import mcp.types as mt  # noqa: PLC0415

        result = mt.CallToolResult(content=[mt.TextContent(type="text", text=text)], isError=True).model_dump(
            by_alias=True, exclude_none=True, mode="json"
        )
    except Exception:  # noqa: BLE001
        result = {"content": [{"type": "text", "text": text}], "isError": True}
    payload = canonical({"jsonrpc": "2.0", "id": rpc_id, "result": result})
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def protect(app, server: str):
    """Wrap an MCP HTTP app per TOOL_GRANTS; the public key path comes from TOOL_GRANT_PUB."""
    if mode() == "off":
        return app
    pub = os.environ.get("TOOL_GRANT_PUB")
    return GrantMiddleware(app, server, Path(pub) if pub else None)


def pupil_id_like(value: Any) -> bool:
    return isinstance(value, str) and bool(PUPIL_ID.match(value))
