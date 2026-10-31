"""Checkout saga: authorize -> create order -> audit -> finish (capture / void / refund)."""

import time
import uuid
from dataclasses import dataclass
from decimal import Decimal

from . import models as m
from .auditor import AuditResult
from .gateway import Gateway, GatewayError
from .policy import Guard, GuardedDecision, execute, unguarded
from .safeview import Pseudonymizer, SafeView, build_safe_view
from .store import Store


class OrderTimeout(Exception):
    pass


class OrderService:
    """In-process stand-in for the order microservice, with fault injection."""

    def __init__(self) -> None:
        self.orders: dict[str, m.Order] = {}
        self.fault: str | None = None  # timeout_before_commit | timeout_after_commit

    def create(self, cart_id: str, total: Decimal, customer: m.Customer) -> m.Order:
        fault, self.fault = self.fault, None
        if fault == "timeout_before_commit":
            raise OrderTimeout("order service timed out before commit")
        order = m.Order(f"ord_{uuid.uuid4().hex[:10]}", cart_id, total, "created", customer)
        self.orders[cart_id] = order
        if fault == "timeout_after_commit":
            raise OrderTimeout("order service timed out after commit (response lost)")
        return order

    def lookup(self, cart_id: str) -> m.Order | None:
        return self.orders.get(cart_id)

    def cancel(self, cart_id: str) -> None:
        self.orders[cart_id].status = "cancelled"

    def change_total(self, cart_id: str, total: Decimal) -> None:
        self.orders[cart_id].total = total


@dataclass
class SagaOutcome:
    snapshot: m.SagaSnapshot
    view: SafeView
    audit: AuditResult
    decisions: list[GuardedDecision]
    pseudonymizer: Pseudonymizer


class Saga:
    def __init__(self, gateway: Gateway, orders: OrderService, store: Store, settings) -> None:
        self.gateway = gateway
        self.orders = orders
        self.store = store
        self.settings = settings

    def new_snapshot(self, cart_id: str, total: Decimal) -> m.SagaSnapshot:
        return m.SagaSnapshot(saga_id=f"saga_{uuid.uuid4().hex}", cart_id=cart_id, expected_total=total)

    def event(self, snap: m.SagaSnapshot, source: str, kind: str, *, txn_id=None, order_id=None,
              occurred_at=None, detail=None) -> None:
        snap.events.append(m.SagaEvent(time.time(), source, kind, txn_id, order_id, occurred_at, detail))

    def authorize(self, snap: m.SagaSnapshot, pm_token: str, amount: Decimal) -> m.GatewayTxn | None:
        self.event(snap, "client", "client_place_order")
        try:
            txn = self.gateway.sale(pm_token, amount)
        except GatewayError as e:
            self.event(snap, "gateway", "sale_failed", detail=str(e))
            return None
        snap.transactions.append(txn)
        kind = {
            m.AUTHORIZED: "sale_authorized",
            m.PROCESSOR_DECLINED: "sale_declined",
            m.GATEWAY_REJECTED: "sale_declined",
        }.get(txn.status, "sale_failed")
        self.event(snap, "gateway", kind, txn_id=txn.txn_id, detail=txn.processor_response_text)
        return txn

    def create_order(self, snap: m.SagaSnapshot, customer: m.Customer) -> None:
        try:
            order = self.orders.create(snap.cart_id, snap.expected_total, customer)
            self.event(snap, "order_service", "order_create_ok", order_id=order.order_id)
        except OrderTimeout as e:
            self.event(snap, "order_service", "order_create_timeout", detail=str(e))

    def refresh(self, snap: m.SagaSnapshot) -> None:
        """Re-read decision-time truth from the gateway and the order service."""
        snap.transactions = [self._refetch(t) for t in snap.transactions]
        snap.order = self.orders.lookup(snap.cart_id)
        snap.order_lookup_done = True
        kind = "order_lookup_found" if snap.order else "order_lookup_missing"
        self.event(snap, "order_service", kind, order_id=snap.order.order_id if snap.order else None)

    def audit_and_finish(self, snap: m.SagaSnapshot, recommender, guarded: bool = True) -> SagaOutcome:
        self.refresh(snap)
        pz = Pseudonymizer(self.settings.pseudonym_secret)
        view = build_safe_view(snap, pz)
        audit = recommender.recommend(view, snap)
        txns = {t.txn_id: t for t in snap.transactions}
        if guarded:
            decisions = Guard(self.settings.auditor_min_confidence).evaluate(
                audit.recommendation, txns, snap.order, pz
            )
        else:
            decisions = unguarded(audit.recommendation, txns, pz)
        execute(self.gateway, decisions)
        self.store.log_audit(view.saga_ref, audit, decisions)
        return SagaOutcome(snap, view, audit, decisions, pz)

    def _refetch(self, txn: m.GatewayTxn) -> m.GatewayTxn:
        fresh = self.gateway.find(txn.txn_id)
        # find() does not return the vaulted token; carry it over from the original record.
        fresh.payment_method_token = fresh.payment_method_token or txn.payment_method_token
        return fresh
