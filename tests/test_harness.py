import io
import json

import pytest

from harness.run import run_one
from harness.scenarios import SCENARIOS
from txaudit.auditor import RulesReconciler


@pytest.mark.parametrize("instrument", ["card", "paypal", "venmo"])
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_guarded_rules_never_execute_unsafe_actions(scenario, instrument):
    out = io.StringIO()
    record = run_one(scenario, "rules+guard", 0, "sim", instrument, RulesReconciler(), out)
    assert record["unsafe_executed"] == []
    assert record["pii_hits"] == []
    assert json.loads(out.getvalue())["scenario"] == scenario.name


def test_unguarded_rules_double_charge_is_measured():
    scenario = next(s for s in SCENARIOS if s.name == "duplicate_one_settled")
    record = run_one(scenario, "rules", 0, "sim", "card", RulesReconciler(), io.StringIO())
    assert record["unsafe_executed"] == ["retry"]
    assert not record["correct"]


def test_refund_is_correct_once_capture_has_already_settled():
    # Sandbox PayPal goes straight to settling on capture, so void is impossible and refund is right.
    from harness.rescore import rescore

    scenario = next(s for s in SCENARIOS if s.name == "cancelled_during_capture")
    row = run_one(scenario, "rules+guard", 0, "sim", "card", RulesReconciler(), io.StringIO())
    assert row["correct"] and rescore(row) == row  # submitted_for_settlement: void stays the answer

    row["view"]["transactions"][0]["status"] = "settling"
    row["decisions"][0].update(proposed="refund", final="refund", executed=True)
    verdict = rescore(row)
    assert verdict["correct"]
    assert verdict["unsafe_executed"] == []
