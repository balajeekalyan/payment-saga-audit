from decimal import Decimal

from harness import scenarios as sc
from txaudit import models as m
from txaudit.auditor import Decision, Recommendation
from txaudit.policy import Guard
from txaudit.safeview import Pseudonymizer, build_safe_view

A = m.Action


def setup(ctx, settings, scenario):
    snap = scenario(ctx)
    ctx.saga.refresh(snap)
    pz = Pseudonymizer(settings.pseudonym_secret)
    build_safe_view(snap, pz)  # assigns T1, T2 in creation order
    return snap, pz, {t.txn_id: t for t in snap.transactions}


def rec(*decisions):
    return Recommendation(
        decisions=[Decision(txn_ref=r, action=a, confidence=c, rationale="", evidence=[]) for r, a, c in decisions],
        summary="",
    )


def verdicts(ctx, settings, scenario, *decisions):
    snap, pz, txns = setup(ctx, settings, scenario)
    out = Guard(settings.auditor_min_confidence).evaluate(rec(*decisions), txns, snap.order, pz)
    return {g.txn_ref: g.blocked_by for g in out}


def test_allows_correct_capture(ctx, settings):
    assert verdicts(ctx, settings, sc.happy, ("T1", A.APPROVE, 0.95)) == {"T1": None}


def test_blocks_illegal_transition(ctx, settings):
    v = verdicts(ctx, settings, sc.cancelled_after_settlement, ("T1", A.VOID, 0.95))
    assert v["T1"] == "I1_illegal_void_from_settled"


def test_blocks_double_capture(ctx, settings):
    v = verdicts(ctx, settings, sc.duplicate_one_settled, ("T1", A.NO_ACTION, 0.9), ("T2", A.APPROVE, 0.9))
    assert v["T2"] == "I2_double_capture"


def test_blocks_amount_mismatch_capture(ctx, settings):
    v = verdicts(ctx, settings, sc.amount_mismatch, ("T1", A.APPROVE, 0.95))
    assert v["T1"] == "I3_amount_mismatch"


def test_blocks_capture_without_order(ctx, settings):
    v = verdicts(ctx, settings, sc.order_timeout_no_order, ("T1", A.APPROVE, 0.95))
    assert v["T1"] == "I4_no_live_order"


def test_blocks_rollback_that_leaves_live_order_unpaid(ctx, settings):
    v = verdicts(ctx, settings, sc.duplicate_click, ("T1", A.VOID, 0.9), ("T2", A.VOID, 0.9))
    assert v == {"T1": "I5_live_order_left_unpaid", "T2": "I5_live_order_left_unpaid"}


def test_missing_and_unknown_refs_escalate(ctx, settings):
    v = verdicts(ctx, settings, sc.duplicate_click, ("T1", A.APPROVE, 0.9), ("T7", A.VOID, 0.9))
    assert v["T7"] == "unknown_ref"
    assert v["T2"] == "I6_missing_decision"


def test_low_confidence_escalates(ctx, settings):
    v = verdicts(ctx, settings, sc.happy, ("T1", A.APPROVE, 0.4))
    assert v["T1"] == "I7_low_confidence"


def test_blocked_decisions_become_escalations(ctx, settings):
    snap, pz, txns = setup(ctx, settings, sc.amount_mismatch)
    out = Guard(0.7).evaluate(rec(("T1", A.APPROVE, 0.99)), txns, snap.order, pz)
    assert out[0].final == A.ESCALATE
    assert snap.order.total == Decimal("95.00")
