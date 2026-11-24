"""gateway/eval_questions.py (OpenSpec add-question-evals): import-safe, outcomes map to the exit code, flag scan."""

import json
import os
import subprocess
import sys
from pathlib import Path

from gateway.eval_questions import Report, Resp, expect, flags_in

ROOT = Path(__file__).resolve().parents[2]


def test_importing_mints_nothing_and_calls_nothing(tmp_path):
    code = (
        "import urllib.request\n"
        "def boom(*a, **k): raise AssertionError('network call at import')\n"
        "urllib.request.urlopen = boom\n"
        "import gateway.eval_questions\n"
        "from day_2_attack import self_attack as sa\n"
        "assert sa.minted == [] and sa._agent is None\n"
    )
    env = {**os.environ, "GATEWAY_STATE_DIR": str(tmp_path)}
    done = subprocess.run(  # noqa: S603  (this interpreter, a fixed snippet)
        [sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert list(tmp_path.iterdir()) == []  # no agent.pem created, no status list touched


def _report(*outcomes) -> Report:
    r = Report()
    for q, problems, gap in outcomes:
        r.add(q, "case", problems, gap=gap)
    return r


def test_only_a_fail_fails_the_run():
    assert _report((0, [], False), (7, ["still open"], True)).exit_code() == 0
    assert _report((0, [], False), (3, ["wrong"], False)).exit_code() == 1


def test_a_passing_gap_is_reported_fixed():
    r = _report((10, [], True), (10, ["x"], True), (10, [], False))
    assert r.totals()[10] == {"PASS": 1, "FAIL": 0, "GAP": 1, "GAP-FIXED": 1}
    assert r.exit_code() == 0


def _resp(status: int, body: dict) -> Resp:
    return Resp(status, json.dumps(body))


def test_flag_scan_reads_the_result_not_the_decision():
    decision = {"decision_id": "d", "decision": "DENY", "reason_code": "X", "detail": "query='Zara Okafor'",
                "ts": 1700000000.2505}  # fmt: skip
    assert flags_in(_resp(403, {"decision": decision})) == []
    leaked = _resp(200, {"decision": {**decision, "decision": "ALLOW"}, "result": [{"DisplayName": "Zara Okafor"}]})
    assert flags_in(leaked) == ["Zara Okafor"]
    assert expect(leaked, status=200)  # a leak fails the case whatever else matches
    assert not expect(leaked, status=200, entitled=("Zara Okafor",))


def test_every_response_needs_a_decision_id_and_no_500():
    assert "no decision.decision_id" in expect(_resp(403, {"decision": {"reason_code": "X"}}), status=403)
    assert any("HTTP 500" in p for p in expect(Resp(500, "Internal Server Error")))
