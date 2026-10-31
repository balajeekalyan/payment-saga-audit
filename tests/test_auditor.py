"""Auditor plumbing with a fake Anthropic client (no network)."""

import json
from types import SimpleNamespace

from harness import scenarios as sc
from txaudit import models as m
from txaudit.auditor import ClaudeAuditor, RulesReconciler
from txaudit.safeview import Pseudonymizer, build_safe_view


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def fake_client(text=None, stop_reason="end_turn", category=None):
    response = SimpleNamespace(
        stop_reason=stop_reason,
        stop_details=SimpleNamespace(category=category) if category else None,
        content=[SimpleNamespace(type="text", text=text or "")],
        usage=SimpleNamespace(input_tokens=1200, output_tokens=300),
        _request_id="req_test",
    )
    return SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages(response)))


def view_for(ctx, settings, scenario):
    snap = scenario(ctx)
    ctx.saga.refresh(snap)
    return snap, build_safe_view(snap, Pseudonymizer(settings.pseudonym_secret))


GOOD = json.dumps({
    "decisions": [{"txn_ref": "T1", "action": "approve", "confidence": 0.93,
                   "rationale": "authorized and order O1 exists", "evidence": ["order_lookup_found"]}],
    "summary": "capture",
})


def test_parses_structured_recommendation(ctx, settings):
    snap, view = view_for(ctx, settings, sc.happy)
    client = fake_client(GOOD)
    result = ClaudeAuditor(settings, client).recommend(view, snap)

    assert result.error is None
    assert result.recommendation.decisions[0].action == m.Action.APPROVE
    kwargs = client.beta.messages.kwargs
    assert kwargs["model"] == settings.auditor_model
    assert kwargs["output_config"]["format"]["type"] == "json_schema"
    assert kwargs["fallbacks"] == "default"
    assert snap.order.customer.email not in kwargs["messages"][0]["content"]


def test_refusal_yields_no_recommendation(ctx, settings):
    snap, view = view_for(ctx, settings, sc.happy)
    result = ClaudeAuditor(settings, fake_client(stop_reason="refusal", category="cyber")).recommend(view, snap)
    assert result.recommendation is None
    assert result.error == "refusal: cyber"


def test_malformed_output_is_an_error_not_an_action(ctx, settings):
    snap, view = view_for(ctx, settings, sc.happy)
    result = ClaudeAuditor(settings, fake_client('{"decisions": "approve"}')).recommend(view, snap)
    assert result.recommendation is None
    assert result.error.startswith("parse_error")


def test_rules_baseline_misses_retry_after_settlement(ctx, settings):
    snap, view = view_for(ctx, settings, sc.duplicate_one_settled)
    actions = {d.txn_ref: d.action for d in RulesReconciler().recommend(view).recommendation.decisions}
    assert actions == {"T1": m.Action.NO_ACTION, "T2": m.Action.APPROVE}  # the double charge the guard stops


def test_rules_baseline_leaves_settled_double_charge(ctx, settings):
    snap, view = view_for(ctx, settings, sc.both_duplicates_settled)
    actions = {d.txn_ref: d.action for d in RulesReconciler().recommend(view).recommendation.decisions}
    assert actions == {"T1": m.Action.NO_ACTION, "T2": m.Action.NO_ACTION}  # no rule refunds a duplicate
