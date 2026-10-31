"""Fault-injection scenarios. Each one drives a real saga (sim or Braintree sandbox) into a
specific state and states which final actions count as correct.

`anticipated` marks whether the rules baseline's decision table was written with that
failure mode in mind. Report results for both groups separately; the honest claim is about
the unanticipated ones.
"""

import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable

from txaudit import models as m
from txaudit.saga import Saga

A = m.Action

# Canary PII. If any of these strings reaches a prompt, the scanner fails the run.
CANARY = m.Customer(
    name="Zelda Quixote-Canary",
    email="zelda.canary@example.org",
    address="742 Evergreen Terrace, Springfield",
    phone="+1 415-555-0199",
)


@dataclass
class Ctx:
    saga: Saga
    pm_token: str
    roles: dict[str, str] = field(default_factory=dict)  # txn_id -> role

    def auth(self, snap: m.SagaSnapshot, amount: str, role: str) -> m.GatewayTxn | None:
        txn = self.saga.authorize(snap, self.pm_token, Decimal(amount))
        if txn:
            self.roles[txn.txn_id] = role
        return txn

    def capture_and_settle(self, snap: m.SagaSnapshot, txn: m.GatewayTxn) -> None:
        gw = self.saga.gateway
        gw.submit_for_settlement(txn.txn_id)
        self.saga.event(snap, "gateway", "capture_ok", txn_id=txn.txn_id)
        gw.settle(txn.txn_id)
        self.saga.event(snap, "webhook", "webhook:transaction_settled", txn_id=txn.txn_id, occurred_at=time.time())


@dataclass
class Scenario:
    name: str
    description: str
    setup: Callable[[Ctx], m.SagaSnapshot]
    acceptable: list[dict[str, A]]  # each dict maps role -> action; any one dict is correct
    anticipated: bool
    sim_only: bool = False  # needs a state the Braintree sandbox cannot be forced into
    # Replaces `acceptable` when some role's transaction is in the given status at decision time,
    # for gateways that skip the state the scenario aims for (sandbox PayPal settles on capture).
    acceptable_if_status: dict[str, list[dict[str, A]]] = field(default_factory=dict)

    def acceptable_for(self, statuses: dict[str, str]) -> list[dict[str, A]]:
        for status, options in self.acceptable_if_status.items():
            if status in statuses.values():
                return options
        return self.acceptable


def _start(ctx: Ctx, total: str) -> m.SagaSnapshot:
    snap = ctx.saga.new_snapshot(f"cart_{time.time_ns()}", Decimal(total))
    snap.platform_token = "ptok_canary_platform_token"
    snap.nonce = "tokencc_canary_nonce_value"
    return snap


def _order(ctx: Ctx, snap: m.SagaSnapshot, fault: str | None = None) -> None:
    ctx.saga.orders.fault = fault
    ctx.saga.create_order(snap, CANARY)
    if fault:
        # Realistic log line that echoes PII; the safe view must drop it.
        snap.events[-1].detail = f"timeout creating order for {CANARY.email} at {CANARY.address}"


def happy(ctx):
    snap = _start(ctx, "49.99")
    ctx.auth(snap, "49.99", "primary")
    _order(ctx, snap)
    return snap


def processor_decline(ctx):
    snap = _start(ctx, "2000.00")
    ctx.auth(snap, "2000.00", "primary")
    return snap


def network_unavailable(ctx):
    snap = _start(ctx, "3000.00")
    ctx.auth(snap, "3000.00", "primary")
    return snap


def order_timeout_no_order(ctx):
    snap = _start(ctx, "64.00")
    ctx.auth(snap, "64.00", "primary")
    _order(ctx, snap, "timeout_before_commit")
    return snap


def order_timeout_lost_response(ctx):
    snap = _start(ctx, "64.00")
    ctx.auth(snap, "64.00", "primary")
    _order(ctx, snap, "timeout_after_commit")
    return snap


def duplicate_click(ctx):
    snap = _start(ctx, "120.00")
    ctx.auth(snap, "120.00", "first")
    ctx.auth(snap, "120.00", "second")
    _order(ctx, snap)
    return snap


def amount_mismatch(ctx):
    snap = _start(ctx, "80.00")
    ctx.auth(snap, "80.00", "primary")
    _order(ctx, snap)
    ctx.saga.orders.change_total(snap.cart_id, Decimal("95.00"))
    ctx.saga.event(snap, "order_service", "order_total_changed")
    return snap


def cancelled_before_capture(ctx):
    snap = _start(ctx, "35.50")
    ctx.auth(snap, "35.50", "primary")
    _order(ctx, snap)
    ctx.saga.orders.cancel(snap.cart_id)
    ctx.saga.event(snap, "order_service", "order_cancelled")
    return snap


def cancelled_after_settlement(ctx):
    snap = _start(ctx, "35.50")
    txn = ctx.auth(snap, "35.50", "primary")
    _order(ctx, snap)
    ctx.capture_and_settle(snap, txn)
    ctx.saga.orders.cancel(snap.cart_id)
    ctx.saga.event(snap, "order_service", "order_cancelled")
    return snap


def stale_webhook(ctx):
    snap = _start(ctx, "72.25")
    txn = ctx.auth(snap, "72.25", "primary")
    authorized_at = time.time()
    _order(ctx, snap)
    ctx.saga.gateway.submit_for_settlement(txn.txn_id)
    ctx.saga.event(snap, "gateway", "capture_ok", txn_id=txn.txn_id)
    # The authorization webhook shows up after the capture, out of order.
    ctx.saga.event(snap, "webhook", "webhook:transaction_authorized", txn_id=txn.txn_id, occurred_at=authorized_at)
    return snap


def duplicate_one_settled(ctx):
    snap = _start(ctx, "150.00")
    first = ctx.auth(snap, "150.00", "first")
    _order(ctx, snap)
    ctx.capture_and_settle(snap, first)
    # A client retry re-authorizes the same cart after the first charge already settled.
    ctx.auth(snap, "150.00", "retry")
    return snap


def auth_expired(ctx):
    snap = _start(ctx, "58.00")
    txn = ctx.auth(snap, "58.00", "primary")
    _order(ctx, snap)
    # Capture was delayed past the authorization window.
    ctx.saga.gateway.expire_authorization(txn.txn_id)
    return snap


def settlement_declined(ctx):
    snap = _start(ctx, "44.00")
    txn = ctx.auth(snap, "44.00", "primary")
    _order(ctx, snap)
    ctx.saga.gateway.submit_for_settlement(txn.txn_id)
    ctx.saga.event(snap, "gateway", "capture_ok", txn_id=txn.txn_id)
    ctx.saga.gateway.settlement_decline(txn.txn_id)
    ctx.saga.event(snap, "webhook", "webhook:transaction_settlement_declined", txn_id=txn.txn_id,
                   occurred_at=time.time())
    return snap


def conflicting_webhook(ctx):
    snap = _start(ctx, "61.00")
    txn = ctx.auth(snap, "61.00", "primary")
    _order(ctx, snap)
    # A "voided" webhook for a transaction the gateway still reports as authorized
    # (misrouted, replayed, or from another environment).
    ctx.saga.event(snap, "webhook", "webhook:transaction_voided", txn_id=txn.txn_id, occurred_at=time.time())
    return snap


def cancelled_during_capture(ctx):
    snap = _start(ctx, "88.00")
    txn = ctx.auth(snap, "88.00", "primary")
    _order(ctx, snap)
    ctx.saga.gateway.submit_for_settlement(txn.txn_id)
    ctx.saga.event(snap, "gateway", "capture_ok", txn_id=txn.txn_id)
    ctx.saga.orders.cancel(snap.cart_id)
    ctx.saga.event(snap, "order_service", "order_cancelled")
    return snap


def both_duplicates_settled(ctx):
    snap = _start(ctx, "110.00")
    first = ctx.auth(snap, "110.00", "first")
    second = ctx.auth(snap, "110.00", "second")
    _order(ctx, snap)
    # A buggy capture path settled both authorizations.
    ctx.capture_and_settle(snap, first)
    ctx.capture_and_settle(snap, second)
    return snap


def retry_after_network_failure(ctx):
    snap = _start(ctx, "77.00")
    ctx.auth(snap, "77.00", "first")
    # The first sale call timed out on our side, but the gateway did authorize it.
    snap.events[-1].kind = "sale_timeout"
    ctx.auth(snap, "77.00", "retry")
    _order(ctx, snap)
    return snap


SCENARIOS = [
    Scenario("happy", "Authorized, order created", happy, [{"primary": A.APPROVE}], True),
    Scenario("processor_decline", "Sandbox amount 2000.00 declines", processor_decline,
             [{"primary": A.NO_ACTION}], True),
    Scenario("network_unavailable", "Sandbox amount 3000.00 fails", network_unavailable,
             [{"primary": A.NO_ACTION}], True),
    Scenario("order_timeout_no_order", "Order service timed out before commit", order_timeout_no_order,
             [{"primary": A.VOID}], True),
    Scenario("order_timeout_lost_response", "Order committed but the response was lost",
             order_timeout_lost_response, [{"primary": A.APPROVE}], True),
    Scenario("duplicate_click", "Two authorizations for one cart", duplicate_click,
             [{"first": A.APPROVE, "second": A.VOID}, {"first": A.VOID, "second": A.APPROVE}], True),
    Scenario("amount_mismatch", "Order total changed after authorization", amount_mismatch,
             [{"primary": A.VOID}, {"primary": A.ESCALATE}], True),
    Scenario("cancelled_before_capture", "Order cancelled while authorized", cancelled_before_capture,
             [{"primary": A.VOID}], True),
    Scenario("cancelled_after_settlement", "Order cancelled after settlement", cancelled_after_settlement,
             [{"primary": A.REFUND}], True),
    Scenario("stale_webhook", "Authorization webhook arrives after capture", stale_webhook,
             [{"primary": A.NO_ACTION}], False),
    Scenario("duplicate_one_settled", "Retry authorizes again after first charge settled",
             duplicate_one_settled, [{"first": A.NO_ACTION, "retry": A.VOID}], False),
    Scenario("auth_expired", "Authorization expired before capture", auth_expired,
             [{"primary": A.ESCALATE}, {"primary": A.NO_ACTION}], False, sim_only=True),
    Scenario("settlement_declined", "Captured, then settlement declined", settlement_declined,
             [{"primary": A.ESCALATE}, {"primary": A.NO_ACTION}], False),
    Scenario("conflicting_webhook", "Voided webhook but gateway says authorized", conflicting_webhook,
             [{"primary": A.APPROVE}, {"primary": A.ESCALATE}], False),
    Scenario("cancelled_during_capture", "Order cancelled after capture, before settlement",
             cancelled_during_capture, [{"primary": A.VOID}], True,
             acceptable_if_status={m.SETTLING: [{"primary": A.REFUND}]}),
    Scenario("both_duplicates_settled", "Two charges for one order both settled", both_duplicates_settled,
             [{"first": A.REFUND, "second": A.NO_ACTION}, {"first": A.NO_ACTION, "second": A.REFUND}], False),
    Scenario("retry_after_network_failure", "Sale timed out client-side but authorized; retry authorized",
             retry_after_network_failure,
             [{"first": A.APPROVE, "retry": A.VOID}, {"first": A.VOID, "retry": A.APPROVE}], True),
]

BY_NAME = {s.name: s for s in SCENARIOS}
