"""Audit trail (OpenSpec add-audit-trail): one signed, chained event per call, and mandated reads of it."""

import asyncio
import json
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib import audit
from gateway.lib.common import b64u, b64u_decode, priv_from_pem, pub_from_pem
from gateway.lib.gateway_verify import AuditContext
from gateway.tests.test_gateway import gw  # noqa: F401  (fixture)

READER_KEY = "reader.pem"


def issue(state, out, *, key="agent.pem", scope=None, deny=None, claims=None, principal="officer:jsmith"):
    args = ["--state", str(state), "issue", "--agent-key", str(state / key), "-o", str(state / out),
            "--principal", principal]  # fmt: skip
    if scope is not None:
        args += ["--scope", json.dumps(scope)]
    if deny is not None:
        args += ["--deny", json.dumps(deny)]
    if claims is not None:
        args += ["--claims", json.dumps(claims)]
    cli.main(args)
    return (state / out).read_text()


def caller(state, mandate, key="agent.pem"):
    priv = priv_from_pem((state / key).read_bytes())

    def call(client, server, tool, **arguments):
        body = cli.sign_request(priv, server=server, tool=tool, arguments=arguments, mandate=mandate)
        return client.post("/tools/call", json=body)

    return call


def claims_of(mandate: str) -> dict:
    return json.loads(b64u_decode(mandate.split(".")[1]))


def all_events():
    return asyncio.run(audit.get_store().all_events())


def reader(state, *, principal=None, jti=None, clearance=2):
    constraints = {"principal": [principal]} if principal else {"jti": [jti]}
    mandate = issue(state, "reader.jwt", key=READER_KEY, principal="officer:jsmith",
                    scope=[{"server": "audit", "tools": ["events", "saw"], "constraints": constraints}],
                    claims={"clearance": clearance})  # fmt: skip
    return caller(state, mandate, key=READER_KEY)


# ---------------------------------------------------------------- recording


def test_every_call_writes_one_event_with_matching_decision_id(gw):  # noqa: F811
    client, call, state = gw
    write_mandate = issue(
        state,
        "write.jwt",
        deny=[],
        scope=[{"server": "pupil-data", "tools": ["write"], "constraints": {"urn": ["SCH04"]}}],
        claims={"clearance": 3},
    )
    write = caller(state, write_mandate)

    responses = [
        call(client, "search", query="P0004", urn="SCH01", limit=1)[0],  # ALLOW
        call(client, "search", query="SPR", urn="SCH02")[0],  # DENY
        write(
            client, "pupil-data", "write", pupil_id="P0011", urn="SCH04", column="FSMeligible", value="1", reason="test"
        ),  # STEP_UP
        client.post(
            "/tools/call",
            json={
                "server": "pupil-data",
                "tool": "search",
                "arguments": {},
                "mandate": "garbage",
                "nonce": "n1",
                "ts": 0,
                "sig": "x",
            },
        ),
    ]
    assert [r.status_code for r in responses] == [200, 403, 202, 403]
    events = all_events()
    assert len(events) == 4
    for r, e in zip(responses, events, strict=True):
        assert r.json()["decision"]["decision_id"] == e["decision_id"]
        assert e["http_status"] == r.status_code
    assert [e["decision"] for e in events] == ["ALLOW", "DENY", "STEP_UP", "DENY"]
    assert events[0]["arg_keys"] == ["limit", "query", "urn"]
    assert events[0]["scope_urn"] == "SCH01"
    assert events[2]["reason_code"] == "SENSITIVE_TOOL"


def test_garbage_and_iss_less_mandates_are_refused_not_crashed(gw):  # noqa: F811
    client, _, _ = gw
    payload = b64u(json.dumps({"jti": "urn:uuid:no-iss"}).encode())
    no_iss = f"{b64u(json.dumps({'typ': 'mandate+jwt', 'alg': 'EdDSA'}).encode())}.{payload}.c2ln"
    for mandate in ("garbage", no_iss):
        body = {"server": "pupil-data", "tool": "search", "arguments": {}}
        r = client.post("/tools/call", json=body | {"mandate": mandate, "nonce": mandate[:8], "ts": 0, "sig": "x"})
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "MANDATE_MALFORMED")
    garbage, iss_less = all_events()
    assert garbage["jti"] is None
    assert garbage["iss"] is None
    assert not garbage["identity_verified"]
    assert iss_less["jti"] == "urn:uuid:no-iss"
    assert iss_less["agent_id"] is None


def test_forged_mandate_records_claimed_identity(gw):  # noqa: F811
    client, _, state = gw
    mandate = (state / "mandate.jwt").read_text()
    header, payload, sig = mandate.split(".")
    claims = json.loads(b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = ["SCH01", "SCH07"]
    forged = f"{header}.{b64u(json.dumps(claims).encode())}.{sig}"
    r = caller(state, forged)(client, "pupil-data", "search", query="P0586", urn="SCH07")
    assert r.json()["decision"]["reason_code"] == "SIG_INVALID"
    (event,) = all_events()
    assert event["jti"] == claims["jti"]
    assert not event["identity_verified"]
    assert event["agent_id"] is None
    assert event["principal"] is None


def test_values_are_not_stored(gw):  # noqa: F811
    client, call, _ = gw
    call(client, "search", query="Zara Okafor", urn="SCH01")
    (event,) = all_events()
    assert "Zara Okafor" not in json.dumps(event)
    assert event["arg_keys"] == ["query", "urn"]
    assert event["arg_hash"].startswith("sha256:")


def test_what_came_back_is_recorded(gw):  # noqa: F811
    client, call, _ = gw
    r, _ = call(client, "search", query="P0004", urn="SCH01")
    call(client, "get", path="synthetic/synthetic_schools.csv")
    search, schools = all_events()
    assert search["rows_returned"] == len(r.json()["result"])
    assert search["pupil_ids_returned"] == ["P0004"]
    # a claim-less mandate gets basic data only (add-graded-pupil-data), and the log records what was released
    assert search["max_pii_level"] == 2
    assert "Ethnicity" not in search["columns_returned"]
    assert schools["rows_returned"] == 12
    assert schools["pupil_ids_returned"] == []
    assert schools["max_pii_level"] == 1
    assert search["result_hash"] == audit.summarise(r.json()["result"]).result_hash


def test_summarise_draft_letters():
    s = audit.summarise([{"Psuedo ID": "P0011", "letter": "Dear parent or carer of Zara Okafor"}])
    assert (s.rows, s.pupil_ids, s.columns, s.max_pii_level) == (1, ["P0011"], ["Psuedo ID", "letter"], 2)
    assert audit.summarise([]).max_pii_level is None
    assert audit.summarise({}).rows == 0
    doc = audit.summarise({"banner": "SYNTHETIC", "classification": {"levels": {}}, "seed": 1})
    assert (doc.rows, doc.columns, doc.max_pii_level) == (1, [], 1)
    assert audit.summarise({"jti": "x", "pupil_ids": ["P0004"]}).max_pii_level == 2


def test_store_failure_withholds_results_but_keeps_refusals(gw, monkeypatch):  # noqa: F811
    client, call, _ = gw

    async def broken(_event):
        msg = "down"
        raise audit.AuditUnavailable(msg)

    monkeypatch.setattr(audit.get_store(), "append", broken)
    r, _ = call(client, "search", query="P0004", urn="SCH01")
    assert r.status_code == 503
    assert "result" not in r.json()
    assert r.json()["decision"]["reason_code"] == "AUDIT_UNAVAILABLE"
    assert r.json()["decision"]["decision_id"]
    r, _ = call(client, "search", query="SPR", urn="SCH02")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")


# ---------------------------------------------------------------- the chain


def test_hash_is_deterministic_and_field_sensitive():
    e = dict.fromkeys(audit.FIELDS) | {"ts": audit.now_iso(), "arg_keys": ["b", "a"], "decision": "ALLOW"}
    assert audit.event_hash(audit.content_of(e)) == audit.event_hash(audit.content_of(dict(e)))
    assert audit.content_of(e)["arg_keys"] == ["a", "b"]
    assert audit.event_hash(audit.content_of(e)) != audit.event_hash(audit.content_of({**e, "decision": "DENY"}))


def test_chain_links_verifies_and_detects_tampering(gw):  # noqa: F811
    client, call, state = gw
    for q in ("P0004", "P0007", "SPR"):
        call(client, "search", query=q, urn="SCH01")
    events = all_events()
    pub = pub_from_pem((state / "gateway.pub").read_bytes())
    assert events[0]["prev_hash"] == audit.ZERO_HASH
    assert [e["prev_hash"] for e in events[1:]] == [e["event_hash"] for e in events[:-1]]
    head = client.get("/audit/head").json()
    assert set(head) == {"seq", "event_hash", "sig"}
    assert head["seq"] == 3
    assert audit.verify_chain(events, pub, [head]) == []

    edited = [dict(e) for e in events]
    edited[1]["reason_code"] = "IN_SCOPE_EDITED"
    assert audit.verify_chain(edited, pub)[0].startswith("seq 2: content does not match")

    # a whole replacement chain, re-signed with the gateway key, still breaks the saved anchor
    signer = audit.Signer(state)
    store = audit.MemoryStore(signer)
    for e in events:
        asyncio.run(store.append({**e, "reason_code": "REWRITTEN"}))
    rewritten = asyncio.run(store.all_events())
    assert audit.verify_chain(rewritten, pub) == []
    assert "anchor seq 3" in audit.verify_chain(rewritten, pub, [head])[0]


def test_query_cap(gw):  # noqa: F811
    assert gw  # the fixture sets up the store
    with pytest.raises(ValueError, match="limit"):
        asyncio.run(audit.events({"principal": "officer:jsmith", "limit": 501}))


# ---------------------------------------------------------------- reading


def test_reader_sees_own_principal_only_and_reads_are_recorded(gw):  # noqa: F811
    client, call, state = gw
    call(client, "search", query="P0004", urn="SCH01")
    jti = claims_of((state / "mandate.jwt").read_text())["jti"]
    read = reader(state, principal="officer:jsmith")

    r = read(client, "audit", "events", principal="officer:jsmith")
    assert r.status_code == 200, r.text
    verified = r.json()["result"]["verified"]
    assert [e["jti"] for e in verified] == [jti]
    assert verified[0]["tool"] == "search"
    assert "pupil_ids_returned" not in verified[0]

    r = read(client, "audit", "events", principal="officer:priya")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")
    assert "result" not in r.json()
    reads = [e for e in all_events() if e["server"] == "audit"]
    assert [e["decision"] for e in reads] == ["ALLOW", "DENY"]


def test_operational_mandate_cannot_read_the_log(gw):  # noqa: F811
    client, _, state = gw
    jti = claims_of((state / "mandate.jwt").read_text())["jti"]
    r = caller(state, (state / "mandate.jwt").read_text())(client, "audit", "events", jti=jti)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_MISSING")
    low = issue(
        state,
        "low.jwt",
        claims={"clearance": 1},
        scope=[{"server": "audit", "tools": ["events"], "constraints": {"principal": ["officer:jsmith"]}}],
    )
    r = caller(state, low)(client, "audit", "events", principal="officer:jsmith")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CLEARANCE_TOO_LOW")


def test_forged_calls_show_up_as_claimed(gw):  # noqa: F811
    client, call, state = gw
    mandate = (state / "mandate.jwt").read_text()
    call(client, "search", query="P0004", urn="SCH01")
    header, payload, sig = mandate.split(".")
    claims = json.loads(b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = ["SCH07"]
    caller(state, f"{header}.{b64u(json.dumps(claims).encode())}.{sig}")(
        client, "pupil-data", "search", query="P0586", urn="SCH07"
    )
    r = reader(state, jti=claims["jti"])(client, "audit", "events", jti=claims["jti"])
    out = r.json()["result"]
    assert [e["reason_code"] for e in out["verified"]] == ["IN_SCOPE"]
    assert [e["reason_code"] for e in out["claimed"]] == ["SIG_INVALID"]
    assert out["claimed"][0]["identity_verified"] is False


def test_saw_after_revoke_and_never_used(gw):  # noqa: F811
    client, call, state = gw
    jti = claims_of((state / "mandate.jwt").read_text())["jti"]
    seen = set()
    for q in ("P0004", "P0022", "AUT"):
        r, _ = call(client, "search", query=q, urn="SCH01", limit=2)
        seen |= {row["Psuedo ID"] for row in r.json()["result"]}
    cli.main(["--state", str(state), "revoke", "--idx", "0"])
    read = reader(state, jti=jti)

    out = read(client, "audit", "saw", jti=jti).json()["result"]
    assert out["revoked"] is True
    assert out["calls"]["allowed"] == 3
    assert out["max_pii_level"] == 2  # claim-less: stripped to basic data
    assert out["pupil_ids"] == sorted(seen)
    assert out["schools"] == ["SCH01"]
    assert out["summary"].startswith("Before it was revoked, this access returned basic personal data such as names")

    unused = issue(state, "unused.jwt")
    out = reader(state, jti=claims_of(unused)["jti"])(client, "audit", "saw", jti=claims_of(unused)["jti"])
    out = out.json()["result"]
    assert out["calls"] == {"allowed": 0, "held": 0, "refused": 0}
    assert out["summary"] == "This access was never used."


# ---------------------------------------------------------------- history for other layers


def test_history_counts_verified_events_only(gw):  # noqa: F811
    client, call, state = gw
    mandate = (state / "mandate.jwt").read_text()
    jti = claims_of(mandate)["jti"]
    call(client, "search", query="P0004", urn="SCH01")
    call(client, "search", query="SPR", urn="SCH02")
    call(client, "search", query="SPR", urn="SCH03")
    header, payload, sig = mandate.split(".")
    caller(state, f"{header}.{payload[:-2]}AA.{sig}")(client, "pupil-data", "search", query="x", urn="SCH09")

    h = asyncio.run(audit.history(jti))
    assert h.calls_by_tool == {"pupil-data.search": 3}
    assert h.allowed_by_tool == {"pupil-data.search": 1}
    assert h.reasons == {"IN_SCOPE": 1, "CONSTRAINT_VIOLATED": 2}
    assert h.refusals_in_a_row == 2
    assert h.distinct_pupils == 1
    assert h.max_pii_level == 2  # claim-less: stripped to basic data
    assert h.first_ts <= h.last_ts


def test_approval_event_joins_the_chain(gw):  # noqa: F811
    client, call, state = gw
    jti = claims_of((state / "mandate.jwt").read_text())["jti"]
    r, _ = call(client, "search", query="P0004", urn="SCH01")
    held_id = r.json()["decision"]["decision_id"]
    asyncio.run(
        audit.record_external(
            "approval_granted",
            jti=jti,
            server="pupil-data",
            tool="write",
            ref_decision_id=held_id,
            reason_code="APPROVED",
            principal="officer:jsmith",
        )
    )
    first, approval = all_events()
    assert approval["prev_hash"] == first["event_hash"]
    assert approval["ref_decision_id"] == held_id
    with pytest.raises(ValueError, match="event_type"):
        asyncio.run(audit.record_external("approval_maybe", jti=jti, server="s", tool="t", ref_decision_id=held_id,
                                          reason_code="X"))  # fmt: skip
    out = reader(state, principal="officer:jsmith")(client, "audit", "events", principal="officer:jsmith").json()
    assert [e["event_type"] for e in out["result"]["verified"]] == ["decision", "approval_granted"]


def test_context_is_not_in_the_response(gw):  # noqa: F811
    client, call, _ = gw
    r, _ = call(client, "search", query="P0004", urn="SCH01")
    assert set(r.json()["decision"]) == {"decision", "reason_code", "policy_version", "mandate_hash",
                                         "request_hash", "agent_id", "ts", "detail", "decision_id"}  # fmt: skip
    assert AuditContext().identity_verified is False


# ---------------------------------------------------------------- SQLite


def _bare_event(**extra) -> dict:
    base = dict.fromkeys(audit.FIELDS) | {
        "server": "pupil-data", "tool": "search", "arg_hash": "sha256:x", "decision": "ALLOW",
        "reason_code": "IN_SCOPE", "event_type": "decision", "identity_verified": False,
    }  # fmt: skip
    return base | {"decision_id": str(uuid.uuid4()), "ts": audit.now_iso()} | extra


def test_sqlite_concurrent_appends_keep_one_chain(tmp_path):
    cli.main(["--state", str(tmp_path), "init"])
    pub = pub_from_pem((tmp_path / "gateway.pub").read_bytes())
    store = audit.SqliteStore(audit.Signer(tmp_path), tmp_path / "audit.sqlite")

    async def run():
        await asyncio.gather(*(store.append(_bare_event(arg_keys=["q"])) for _ in range(50)))
        return await store.all_events()

    chain = asyncio.run(run())
    assert len(chain) == 50
    assert [e["seq"] for e in chain] == list(range(1, 51))
    assert chain[0]["arg_keys"] == ["q"]
    assert audit.verify_chain(chain, pub) == []


def test_sqlite_is_append_only_and_durable(tmp_path):
    cli.main(["--state", str(tmp_path), "init"])
    path = tmp_path / "audit.sqlite"
    store = audit.SqliteStore(audit.Signer(tmp_path), path)
    first = asyncio.run(store.append(_bare_event()))
    store.close()

    raw = sqlite3.connect(path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("UPDATE audit_events SET reason_code = 'EDITED'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw.execute("DELETE FROM audit_events")
    raw.close()

    reopened = audit.SqliteStore(audit.Signer(tmp_path), path)
    second = asyncio.run(reopened.append(_bare_event()))
    assert second["prev_hash"] == first["event_hash"]
    assert second["seq"] == 2
    pub = pub_from_pem((tmp_path / "gateway.pub").read_bytes())
    assert audit.verify_chain(asyncio.run(reopened.all_events()), pub) == []


def test_gateway_writes_sqlite_when_configured(gw, tmp_path, monkeypatch):  # noqa: F811
    _, call, _ = gw
    path = tmp_path / "audit" / "audit.sqlite"
    monkeypatch.setenv("GATEWAY_AUDIT_DB", str(path))
    with TestClient(main.app) as client:  # a fresh lifespan picks the store up from the environment
        assert client.get("/healthcheck/audit").json() == {"store": "sqlite", "durable": True}
        r, _ = call(client, "search", query="P0004", urn="SCH01")
        assert r.status_code == 200
        head = client.get("/audit/head").json()
    stored = audit.SqliteStore(None, path, read_only=True)
    (event,) = asyncio.run(stored.all_events())
    assert event["decision_id"] == r.json()["decision"]["decision_id"]
    assert event["event_hash"] == head["event_hash"]
    assert event["pupil_ids_returned"] == ["P0004"]


# ---------------------------------------------------------------- for scope requests (audit asks)


def test_gateway_server_results_scored_at_server_level(gw):  # noqa: F811
    status = audit.summarise({"request_id": "sr_1", "status": "pending", "summary": "roster at SCH02"}, "grants")
    assert (status.columns, status.max_pii_level, status.rows) == ([], 1, 1)
    assert audit.summarise({"verified": [], "claimed": []}, "audit").max_pii_level == 2
    assert audit.summarise({"request_id": "sr_1", "status": "pending"}).max_pii_level == 4  # not a gateway server

    client, call, state = gw
    call(client, "search", query="P0004", urn="SCH01")
    reader(state, principal="officer:jsmith")(client, "audit", "events", principal="officer:jsmith")
    read_event = all_events()[-1]
    assert read_event["server"] == "audit"
    assert read_event["max_pii_level"] == 2
    assert read_event["columns_returned"] == []


def test_parent_jti_comes_from_the_parent_claim(gw):  # noqa: F811
    client, _, state = gw
    # a real parent claim names a status list the gateway can read (add-scope-requests checks the parent's bit)
    uri = json.loads((state / "status_list.json").read_text())["uri"]
    child = issue(state, "child.jwt", claims={"parent": {"jti": "urn:uuid:parent-1", "status": {"uri": uri, "idx": 0}}})
    caller(state, child)(client, "pupil-data", "search", query="P0004", urn="SCH01")
    (event,) = all_events()
    assert event["parent_jti"] == "urn:uuid:parent-1"
    assert audit._parent_jti({"parent_jti": "urn:uuid:p2"}) == "urn:uuid:p2"  # noqa: SLF001
    assert audit._parent_jti({"parent": "not-an-object"}) is None  # noqa: SLF001


def issuer_signer(state):
    meta = json.loads((state / "status_list.json").read_text())
    return priv_from_pem((state / "issuer_key.pem").read_bytes()), meta["issuer"], meta["kid"]


def approval(state, **overrides):
    default_priv, iss, kid = issuer_signer(state)
    priv = overrides.pop("priv", default_priv)
    fields = {
        "iss": iss, "kid": kid, "event_type": "approval_granted", "mandate_jti": "urn:uuid:job-1",
        "server": "directory", "tool": "roster", "ref_decision_id": str(uuid.uuid4()), "reason_code": "APPROVED",
        "principal": "officer:jsmith",
    } | overrides  # fmt: skip
    return audit.sign_external_event(priv, **fields)


def test_issuer_signed_event_is_recorded_once_and_readable(gw):  # noqa: F811
    client, _, state = gw
    token = approval(state)
    r = client.post("/internal/audit-events", json={"token": token})
    assert r.status_code == 201, r.text
    assert r.json()["duplicate"] is False
    again = client.post("/internal/audit-events", json={"token": token})  # the issuer's outbox retries
    assert again.status_code == 200
    assert again.json()["duplicate"] is True
    assert again.json()["decision_id"] == r.json()["decision_id"]
    (event,) = all_events()
    assert (event["event_type"], event["jti"], event["principal"]) == ("approval_granted", "urn:uuid:job-1",
                                                                        "officer:jsmith")  # fmt: skip
    out = reader(state, principal="officer:jsmith")(client, "audit", "events", principal="officer:jsmith").json()
    assert [e["event_type"] for e in out["result"]["verified"]] == ["approval_granted"]


@pytest.mark.parametrize(
    ("make", "status", "code"),
    [
        (lambda _state: "garbage", 400, "EVENT_INVALID"),
        (lambda state: (state / "mandate.jwt").read_text(), 400, "EVENT_INVALID"),  # a mandate, wrong typ
        (lambda state: approval(state, iss="https://someone-else.example"), 403, "ISSUER_NOT_ACCREDITED"),
        (
            lambda state: approval(state, priv=priv_from_pem(cli.priv_to_pem(cli.generate_keypair()[0]))),
            403,
            "SIG_INVALID",
        ),
        (lambda state: approval(state, ttl=-10), 403, "EVENT_EXPIRED"),
        (lambda state: approval(state, event_type="approval_maybe"), 400, "EVENT_REJECTED"),
        (lambda state: approval(state, event_id="not-a-uuid"), 400, "EVENT_REJECTED"),
    ],
)
def test_unsigned_or_wrong_events_are_refused(gw, make, status, code):  # noqa: F811
    client, _, state = gw
    r = client.post("/internal/audit-events", json={"token": make(state)})
    assert (r.status_code, r.json()["reason_code"]) == (status, code)
    assert all_events() == []


# ---------------------------------------------------------------- minted mandate on approval events


def test_unset_optional_field_keeps_old_hashes():
    e = _bare_event()
    content = audit.content_of(e)
    assert "minted_jti" not in content  # unset: hashed exactly as before the field existed
    assert audit.content_of({**e, "minted_jti": "urn:uuid:m1"})["minted_jti"] == "urn:uuid:m1"


def test_old_audit_file_gains_the_column_and_still_verifies(tmp_path):
    cli.main(["--state", str(tmp_path), "init"])
    path = tmp_path / "audit.sqlite"
    raw = sqlite3.connect(path)
    raw.executescript(audit.SQLITE_SCHEMA.replace(" minted_jti TEXT,", ""))  # a file from before the field
    raw.close()
    store = audit.SqliteStore(audit.Signer(tmp_path), path)
    asyncio.run(store.append(_bare_event()))
    asyncio.run(store.append(_bare_event(event_type="approval_granted", decision=None, minted_jti="urn:uuid:m1")))
    pub = pub_from_pem((tmp_path / "gateway.pub").read_bytes())
    chain = asyncio.run(store.all_events())
    assert [e["minted_jti"] for e in chain] == [None, "urn:uuid:m1"]
    assert audit.verify_chain(chain, pub) == []


def test_signed_approval_carries_the_minted_mandate(gw):  # noqa: F811
    client, _, state = gw
    r = client.post("/internal/audit-events", json={"token": approval(state, minted_jti="urn:uuid:minted-1")})
    assert r.status_code == 201, r.text
    (event,) = all_events()
    assert event["minted_jti"] == "urn:uuid:minted-1"
    out = reader(state, principal="officer:jsmith")(client, "audit", "events", principal="officer:jsmith").json()
    assert out["result"]["verified"][0]["minted_jti"] == "urn:uuid:minted-1"
    bad = client.post("/internal/audit-events", json={"token": approval(state, minted_jti=7)})
    assert (bad.status_code, bad.json()["reason_code"]) == (400, "EVENT_REJECTED")
