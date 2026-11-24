"""Plain words for grants (OpenSpec add-scope-requests): never narrower than what is enforced."""

from gateway.lib.grant_words import entry_words, marks_level_4


def test_no_school_constraint_says_every_school():
    entry = {"server": "pupil-data", "tools": ["search"]}
    assert "at every school" in entry_words(entry)


def test_a_school_constraint_names_the_school():
    entry = {"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}}
    words = entry_words(entry)
    assert "Dunmore Community College (SCH04)" in words
    assert "every school" not in words


def test_files_and_labels_are_not_per_school():
    assert "school" not in entry_words({"server": "pupil-data", "tools": ["get", "classification"]})


def test_row_cap_and_rate_are_shown():
    entry = {"server": "directory", "tools": ["roster"], "constraints": {"urn": ["SCH04"]}, "max_rows": 20,
             "rate": {"per_minute": 5, "max_calls": 40}}  # fmt: skip
    words = entry_words(entry)
    assert "at most 20 rows a call" in words
    assert "at most 5 calls a minute" in words
    assert "40 calls in all" in words


def test_graded_words_say_what_each_clearance_returns():
    entry = {"server": "pupil-data", "tools": ["search", "pupil"], "constraints": {"urn": ["SCH04"]}}
    at2 = entry_words(entry, 2)
    assert "basic details only" in at2
    assert "including ethnicity" not in at2
    assert "free school meals and language, but not ethnicity" in entry_words(entry, 3)
    assert "including ethnicity and care status" in entry_words(entry, 4)


def test_graded_pupil_data_is_level_4_only_at_clearance_4():
    scope = [{"server": "pupil-data", "tools": ["search"]}]
    assert not marks_level_4(scope, 2)
    assert marks_level_4(scope, 4)
    assert marks_level_4([{"server": "special", "tools": ["record"]}], 2)
