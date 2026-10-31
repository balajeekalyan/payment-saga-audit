from harness.guard_stress import run


def test_guard_contains_every_unsafe_mutant_and_passes_correct_ones():
    result = run()
    assert result["uncontained_unsafe"] == []
    assert result["correct_recommendations_blocked"] == []
    assert result["by_kind"]["swap"]["unsafe"] > 0
