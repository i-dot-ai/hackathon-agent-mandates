"""Offline Day 2 checks. Run with python -m pytest day_2_attack/tests."""

import jwt
import pytest
from starlette.routing import Match

from gateway import main
from gateway.lib import gateway_verify as verify


def test_default_gateway_keeps_demo_administration_separate():
    # Inspect the actual routing table without executing any demo operation.
    scope = {"type": "http", "method": "POST", "path": "/tools/call"}
    assert any(route.matches(scope)[0] == Match.FULL for route in main.app.routes)
    for path in ("/demo/mandate", "/demo/revoke", "/demo/call"):
        scope["path"] = path
        assert all(route.matches(scope)[0] != Match.FULL for route in main.app.routes), (
            "The default gateway mounts privileged demo operations"
        )


def test_mandate_parser_error_returns_a_denial(monkeypatch):
    def parser_error(_token):
        raise jwt.DecodeError

    monkeypatch.setattr(verify.jwt, "get_unverified_header", parser_error)
    gateway = verify.Gateway(registry=None, status_lists={})
    request = verify.Request("fixture", "read", {}, mandate="fixture", nonce="fixture", ts=0, sig="")
    assert gateway.decide(request).decision == "DENY"


@pytest.mark.parametrize(
    ("filter_level", "measure_level", "expected_level"),
    [(1, 1, 1), (1, 4, 4), (4, 1, 4)],
    ids=["public-count", "restricted-measure", "restricted-filter"],
)
def test_aggregate_clearance_covers_columns_used_to_compute_count(filter_level, measure_level, expected_level):
    # Invented column labels and a fixed result exercise only the policy function.
    columns = {"group": 1, "indicator": measure_level, "category": filter_level}
    arguments = {"group_by": ["group"], "measure": "indicator", "where": {"category": "example"}}
    rows = [{"group": "example", "total": 30, "count": 20}]
    levels = verify.result_levels("aggregate", arguments, rows, columns, {}, max_level=4)
    assert verify.sensitivity_record(levels, {}, clearance=1)["level"] == expected_level


@pytest.mark.parametrize(
    ("path", "expected_level"),
    [
        ("synthetic/synthetic_manifest.json", 1),
        ("synthetic/synthetic_directory.csv", 1),
        ("synthetic/synthetic_casework.csv", 3),
        ("synthetic/synthetic_unclassified.csv", 4),
        ("synthetic/synthetic_unclassified.json", 4),
    ],
    ids=["public-manifest", "public-table", "restricted-table", "unknown-csv", "unknown-json"],
)
def test_get_classifies_files_before_release(path, expected_level):
    # The manifest is public by design. New data files should default to the highest level until labelled.
    tables = {"directory": 1, "casework": 3}
    payload = [{"example": "fixture"}] if path.endswith(".csv") else {"example": "fixture"}
    levels = verify.result_levels("get", {"path": path}, payload, {}, tables, max_level=4)
    assert verify.sensitivity_record(levels, {}, clearance=1)["level"] == expected_level
