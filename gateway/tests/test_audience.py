"""Mandate audience (OpenSpec add-scope-requests, spec mandate-audience)."""

import pytest

from gateway.lib.audience import check_audience

AUDIENCE = {"pupils": ["P0011", "P0042"]}


@pytest.mark.parametrize(
    ("entry", "arguments", "expected"),
    [
        ({}, {"pupil_id": "P0099"}, None),  # no audience: unchanged
        ({"audience": AUDIENCE}, {"pupil_id": "P0011"}, None),
        ({"audience": AUDIENCE}, {"pupil_id": "P0099"}, ("AUDIENCE_VIOLATED", "P0099")),
        ({"audience": AUDIENCE}, {"pupil_ids": ["P0011", "P0099"]}, ("AUDIENCE_VIOLATED", "P0099")),
        ({"audience": AUDIENCE}, {"pupil_ids": ["P0042", "P0011"]}, None),
        ({"audience": AUDIENCE}, {"urn": "SCH04", "year_group": 11}, None),  # names nobody: filtered at the tool
        ({"audience": {"InCareAtCurrentSchool": "1"}}, {}, ("AUDIENCE_INVALID", None)),
        ({"audience": {"pupils": []}}, {}, ("AUDIENCE_INVALID", None)),
        ({"audience": {"pupils": ["Zara"]}}, {}, ("AUDIENCE_INVALID", None)),
        ({"audience": {"pupils": ["P0011"], "year_group": 11}}, {}, ("AUDIENCE_INVALID", None)),
        ({"audience": ["P0011"]}, {}, ("AUDIENCE_INVALID", None)),
    ],
)
def test_check_audience(entry, arguments, expected):
    result = check_audience(entry, arguments)
    if expected is None:
        assert result is None
    else:
        code, detail = expected
        assert result[:2] == ("DENY", code)
        if detail:
            assert result[2] == detail


def test_too_many_pupils_is_invalid():
    entry = {"audience": {"pupils": [f"P{i:04d}" for i in range(501)]}}
    assert check_audience(entry, {})[1] == "AUDIENCE_INVALID"


# ---------------------------------------------------------------- through the gateway


def test_entry_without_audience_unchanged(stack):
    client, mandate, call, _ = stack
    scope = [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}]
    status, resp = call(client, mandate(scope), "pupil-data", "search", query="P0004", urn="SCH01", limit=1)
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")


def test_audience_defined_by_attribute(stack):
    client, mandate, call, _ = stack
    scope = [
        {
            "server": "pupil-data",
            "tools": ["pupil"],
            "constraints": {"urn": ["SCH07"]},
            "audience": {"InCareAtCurrentSchool": "1"},
        }
    ]
    status, resp = call(client, mandate(scope, clearance=3), "pupil-data", "pupil", pupil_id="P0586", urn="SCH07")
    assert (status, resp["decision"]["reason_code"]) == (403, "AUDIENCE_INVALID")
    assert "result" not in resp


def test_pupil_not_on_the_list(stack):
    client, mandate, call, _ = stack
    scope = [{"server": "pupil-data", "tools": ["pupil"], "constraints": {"urn": ["SCH04"]}, "audience": AUDIENCE}]
    token = mandate(scope, clearance=3)
    status, resp = call(client, token, "pupil-data", "pupil", pupil_id="P0099", urn="SCH04")
    assert (status, resp["decision"]["reason_code"], resp["decision"]["detail"]) == (403, "AUDIENCE_VIOLATED", "P0099")
    status, resp = call(client, token, "pupil-data", "pupil", pupil_id="P0011", urn="SCH04")
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")


def test_one_letter_outside_the_list(stack):
    client, mandate, call, _ = stack
    scope = [{"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": ["SCH04"]}, "audience": AUDIENCE}]
    status, resp = call(
        client, mandate(scope, deny=(), clearance=3), "pupil-data", "draft", urn="SCH04", pupil_ids=["P0011", "P0099"]
    )
    assert (status, resp["decision"]["reason_code"], resp["decision"]["detail"]) == (403, "AUDIENCE_VIOLATED", "P0099")


def test_another_entry_can_still_allow(stack):
    """Each entry is a whole grant: an audience refusal in one entry doesn't block a wider entry."""
    client, mandate, call, _ = stack
    scope = [
        {"server": "pupil-data", "tools": ["pupil"], "constraints": {"urn": ["SCH04"]}, "audience": AUDIENCE},
        {"server": "pupil-data", "tools": ["pupil"], "constraints": {"urn": ["SCH04"]}},
    ]
    status, resp = call(client, mandate(scope, clearance=3), "pupil-data", "pupil", pupil_id="P0099", urn="SCH04")
    assert (status, resp["decision"]["reason_code"]) == (200, "IN_SCOPE")
