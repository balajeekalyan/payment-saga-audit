"""Deterministic policy layer between a recommendation and the gateway.

The guard re-reads gateway and order state itself (never trusting the view the model saw),
resolves opaque labels server-side, and enforces invariants:
  I1 legal transition: the action must be valid for the transaction's current status;
  I2 single capture: a live order never ends up with more than one paid transaction;
  I3 exact capture: approve only when the authorized amount equals the order total;
  I4 live order: approve only when the order exists and is not cancelled;
  I5 no silent loss: never roll back a live order's only correctly-sized payment;
  I6 completeness: every transaction in the saga gets exactly one decision;
  I7 confidence: low-confidence recommendations are escalated, not executed.
Anything blocked becomes an escalation. The guard never substitutes its own action.
"""

from dataclasses import dataclass

from . import models as m
from .auditor import Recommendation
from .gateway import Gateway, GatewayError
from .safeview import Pseudonymizer

LEGAL = {
    m.Action.APPROVE: {m.AUTHORIZED},
    m.Action.VOID: {m.AUTHORIZED, m.SUBMITTED},
    m.Action.REFUND: {m.SETTLING, m.SETTLED},
}
PAID = {m.SUBMITTED, m.SETTLING, m.SETTLED, "settlement_pending", "settlement_confirmed"}


@dataclass
class GuardedDecision:
    txn_id: str | None
    txn_ref: str
    proposed: m.Action
    final: m.Action  # what was (or would be) executed; ESCALATE when blocked
    blocked_by: str | None = None
    executed: bool = False
    gateway_error: str | None = None


class Guard:
    def __init__(self, min_confidence: float) -> None:
        self.min_confidence = min_confidence

    def evaluate(
        self,
        rec: Recommendation | None,
        txns: dict[str, m.GatewayTxn],
        order: m.Order | None,
        pz: Pseudonymizer,
    ) -> list[GuardedDecision]:
        if rec is None:
            return [
                GuardedDecision(tid, pz.ref("T", tid), m.Action.ESCALATE, m.Action.ESCALATE, "no_recommendation")
                for tid in txns
            ]

        out: list[GuardedDecision] = []
        seen: set[str] = set()
        for d in rec.decisions:
            tid = pz.resolve(d.txn_ref)
            g = GuardedDecision(tid, d.txn_ref, d.action, d.action)
            if tid is None or tid not in txns:
                g.blocked_by = "unknown_ref"
            elif tid in seen:
                g.blocked_by = "I6_duplicate_decision"
            elif d.action in LEGAL and d.confidence < self.min_confidence:
                g.blocked_by = "I7_low_confidence"
            elif d.action in LEGAL and txns[tid].status not in LEGAL[d.action]:
                g.blocked_by = f"I1_illegal_{d.action.value}_from_{txns[tid].status}"
            elif d.action == m.Action.REFUND and txns[tid].refunded:
                g.blocked_by = "I1_already_refunded"
            if tid:
                seen.add(tid)
            out.append(g)

        for tid in txns:
            if tid not in seen:
                out.append(GuardedDecision(tid, pz.ref("T", tid), m.Action.ESCALATE, m.Action.ESCALATE, "I6_missing_decision"))

        order_live = order is not None and order.status == "created"
        approvals = [g for g in out if g.blocked_by is None and g.proposed == m.Action.APPROVE]
        rollbacks = [g for g in out if g.blocked_by is None and g.proposed in (m.Action.VOID, m.Action.REFUND)]

        for g in approvals:
            if not order_live:
                g.blocked_by = "I4_no_live_order"
            elif txns[g.txn_id].amount != order.total:
                g.blocked_by = "I3_amount_mismatch"

        def paid_after() -> set[str]:
            approved = {g.txn_id for g in approvals if g.blocked_by is None}
            rolled_back = {g.txn_id for g in rollbacks if g.blocked_by is None}
            already = {tid for tid, t in txns.items() if t.status in PAID and not t.refunded}
            return (already | approved) - rolled_back

        if len(paid_after()) > 1:
            for g in approvals:
                if g.blocked_by is None:
                    g.blocked_by = "I2_double_capture"

        if order_live and not paid_after():
            for g in rollbacks:
                if txns[g.txn_id].amount == order.total:
                    g.blocked_by = "I5_live_order_left_unpaid"

        for g in out:
            if g.blocked_by:
                g.final = m.Action.ESCALATE
        return out


def unguarded(rec: Recommendation | None, txns: dict[str, m.GatewayTxn], pz: Pseudonymizer) -> list[GuardedDecision]:
    """LLM-only ablation: take the recommendation at face value."""
    if rec is None:
        return [GuardedDecision(t, pz.ref("T", t), m.Action.ESCALATE, m.Action.ESCALATE, "no_recommendation") for t in txns]
    return [GuardedDecision(pz.resolve(d.txn_ref), d.txn_ref, d.action, d.action) for d in rec.decisions]


def execute(gateway: Gateway, decisions: list[GuardedDecision]) -> None:
    ops = {
        m.Action.APPROVE: gateway.submit_for_settlement,
        m.Action.VOID: gateway.void,
        m.Action.REFUND: gateway.refund,
    }
    for g in decisions:
        op = ops.get(g.final)
        if op is None or g.txn_id is None:
            continue
        try:
            op(g.txn_id)
            g.executed = True
        except GatewayError as e:
            g.gateway_error = str(e)
