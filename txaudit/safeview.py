"""The LLM-safe view: the only representation of a checkout that may enter a prompt.

Design rules (these are the paper's privacy claims):
1. Allow-list, not redaction. Every field is copied explicitly from the raw record into a
   pydantic model with extra="forbid"; anything not named here cannot cross the boundary.
2. No free text. Strings are enums, fixed-format codes, or labels we generate. Processor
   response text, error messages and event details are dropped because they can echo PII.
3. Opaque references. Transaction, order and saga IDs are replaced with per-session labels
   (T1, O1, ...). The label -> real ID map stays server-side in Pseudonymizer.
4. Coarse amounts. The exact amount is replaced by a bucket plus a server-computed
   "matches order total" flag, which is the only amount fact the decision needs.
"""

import hashlib
import hmac
import json
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from . import models as m

TxnStatus = Literal[
    "authorizing",
    "authorized",
    "submitted_for_settlement",
    "settling",
    "settled",
    "settlement_pending",
    "settlement_declined",
    "settlement_confirmed",
    "voided",
    "processor_declined",
    "gateway_rejected",
    "failed",
    "authorization_expired",
    "unknown",
]
Instrument = Literal["credit_card", "paypal_account", "venmo_account", "other"]
RejectionReason = Literal[
    "avs",
    "avs_and_cvv",
    "cvv",
    "duplicate",
    "fraud",
    "risk_threshold",
    "three_d_secure",
    "token_issuance",
    "application_incomplete",
]
ResponseClass = Literal["approved", "declined", "network_error", "other"]
EventSource = Literal["gateway", "order_service", "webhook", "client", "auditor"]

EVENT_KINDS = {
    "client_place_order",
    "sale_authorized",
    "sale_declined",
    "sale_failed",
    "sale_timeout",
    "order_create_ok",
    "order_create_timeout",
    "order_lookup_found",
    "order_lookup_missing",
    "order_cancelled",
    "order_total_changed",
    "capture_ok",
    "void_ok",
    "refund_ok",
    "webhook:transaction_authorized",
    "webhook:transaction_submitted_for_settlement",
    "webhook:transaction_settled",
    "webhook:transaction_settlement_declined",
    "webhook:transaction_voided",
}

AMOUNT_BUCKETS = [
    (Decimal("10"), "<10"),
    (Decimal("50"), "10-50"),
    (Decimal("100"), "50-100"),
    (Decimal("500"), "100-500"),
    (Decimal("1000"), "500-1000"),
    (Decimal("5000"), "1000-5000"),
]

_STRICT = ConfigDict(extra="forbid", frozen=True)


class SafeTxn(BaseModel):
    model_config = _STRICT
    ref: str = Field(pattern=r"^T\d+$")
    instrument: Instrument
    status: TxnStatus
    processor_response_code: str | None = Field(default=None, pattern=r"^\d{4}$")
    processor_response_class: ResponseClass | None = None
    gateway_rejection_reason: RejectionReason | None = None
    amount_bucket: str
    amount_matches_order_total: bool | None
    created_t: float
    refunded: bool


class SafeOrder(BaseModel):
    model_config = _STRICT
    ref: str = Field(pattern=r"^O\d+$")
    status: Literal["created", "cancelled"]
    total_bucket: str


class SafeEvent(BaseModel):
    model_config = _STRICT
    t: float
    occurred_t: float | None
    source: EventSource
    kind: str
    txn_ref: str | None = Field(default=None, pattern=r"^T\d+$")
    order_ref: str | None = Field(default=None, pattern=r"^O\d+$")


class SafeView(BaseModel):
    model_config = _STRICT
    saga_ref: str = Field(pattern=r"^S[0-9a-f]{8}$")
    expected_total_bucket: str
    order_lookup_done: bool
    order: SafeOrder | None
    transactions: list[SafeTxn]
    events: list[SafeEvent]


class Pseudonymizer:
    """Per-session label assignment. resolve() is server-side only."""

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode()
        self._fwd: dict[tuple[str, str], str] = {}
        self._rev: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def ref(self, prefix: str, real_id: str) -> str:
        key = (prefix, real_id)
        if key not in self._fwd:
            n = self._counters.get(prefix, 0) + 1
            self._counters[prefix] = n
            label = f"{prefix}{n}"
            self._fwd[key] = label
            self._rev[label] = real_id
        return self._fwd[key]

    def saga_ref(self, saga_id: str) -> str:
        digest = hmac.new(self._secret, saga_id.encode(), hashlib.sha256).hexdigest()
        return f"S{digest[:8]}"

    def resolve(self, label: str) -> str | None:
        return self._rev.get(label)


def amount_bucket(amount: Decimal) -> str:
    for upper, label in AMOUNT_BUCKETS:
        if amount < upper:
            return label
    return ">=5000"


def response_class(code: str | None) -> ResponseClass | None:
    if not code or not code.isdigit():
        return None
    n = int(code)
    if 1000 <= n < 2000:
        return "approved"
    if 2000 <= n < 3000:
        return "declined"
    if n == 3000:
        return "network_error"
    return "other"


def _enum_or(value, allowed, fallback):
    return value if value in allowed.__args__ else fallback


def build_safe_view(snap: m.SagaSnapshot, pz: Pseudonymizer) -> SafeView:
    t0 = min((e.t for e in snap.events), default=0.0)
    txn_t0 = min((t.created_at for t in snap.transactions), default=0.0)
    order_total = snap.order.total if snap.order else snap.expected_total

    txns = []
    for t in sorted(snap.transactions, key=lambda x: x.created_at):
        code = t.processor_response_code if (t.processor_response_code or "").isdigit() else None
        txns.append(
            SafeTxn(
                ref=pz.ref("T", t.txn_id),
                instrument=_enum_or(t.payment_instrument, Instrument, "other"),
                status=_enum_or(t.status, TxnStatus, "unknown"),
                processor_response_code=code if code and len(code) == 4 else None,
                processor_response_class=response_class(code),
                gateway_rejection_reason=_enum_or(t.gateway_rejection_reason, RejectionReason, None),
                amount_bucket=amount_bucket(t.amount),
                amount_matches_order_total=(t.amount == order_total),
                created_t=round(t.created_at - txn_t0, 3),
                refunded=t.refunded,
            )
        )

    order = None
    if snap.order:
        order = SafeOrder(
            ref=pz.ref("O", snap.order.order_id),
            status=snap.order.status,
            total_bucket=amount_bucket(snap.order.total),
        )

    events = []
    for e in sorted(snap.events, key=lambda x: x.t):
        events.append(
            SafeEvent(
                t=round(e.t - t0, 3),
                occurred_t=None if e.occurred_at is None else round(e.occurred_at - t0, 3),
                source=e.source,
                kind=e.kind if e.kind in EVENT_KINDS else "other",
                txn_ref=pz.ref("T", e.txn_id) if e.txn_id else None,
                order_ref=pz.ref("O", e.order_id) if e.order_id else None,
            )
        )

    return SafeView(
        saga_ref=pz.saga_ref(snap.saga_id),
        expected_total_bucket=amount_bucket(snap.expected_total),
        order_lookup_done=snap.order_lookup_done,
        order=order,
        transactions=txns,
        events=events,
    )


def render(view: SafeView) -> str:
    """Deterministic JSON so identical views produce identical prompts."""
    return json.dumps(view.model_dump(mode="json"), sort_keys=True, indent=1)
