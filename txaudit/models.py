"""Raw (sensitive) domain records. Nothing in this module may be sent to the LLM directly;
the only path to a prompt is safeview.build_safe_view()."""

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum


class Action(str, Enum):
    APPROVE = "approve"  # Transaction.submit_for_settlement
    VOID = "void"  # Transaction.void (authorized / submitted_for_settlement)
    REFUND = "refund"  # Transaction.refund (settling / settled)
    NO_ACTION = "no_action"
    ESCALATE = "escalate"  # hand to a human reviewer


# Braintree transaction statuses (braintree.Transaction.Status values).
AUTHORIZED = "authorized"
SUBMITTED = "submitted_for_settlement"
SETTLING = "settling"
SETTLED = "settled"
VOIDED = "voided"
SETTLEMENT_DECLINED = "settlement_declined"
PROCESSOR_DECLINED = "processor_declined"
GATEWAY_REJECTED = "gateway_rejected"
FAILED = "failed"
AUTH_EXPIRED = "authorization_expired"


@dataclass
class Customer:
    """PII that the order service holds. Present in raw snapshots so the
    harness can prove it never reaches a prompt."""

    name: str
    email: str
    address: str
    phone: str


@dataclass
class GatewayTxn:
    txn_id: str
    status: str
    amount: Decimal
    payment_method_token: str
    payment_instrument: str  # credit_card | paypal_account | venmo_account
    processor_response_code: str | None = None
    processor_response_text: str | None = None
    gateway_rejection_reason: str | None = None
    card_bin: str | None = None
    card_last4: str | None = None
    created_at: float = 0.0
    refunded: bool = False


@dataclass
class Order:
    order_id: str
    cart_id: str
    total: Decimal
    status: str  # created | cancelled
    customer: Customer


@dataclass
class SagaEvent:
    """One observation about the checkout, in arrival order."""

    t: float  # seconds since saga start, by arrival
    source: str  # gateway | order_service | webhook | client
    kind: str  # e.g. sale_ok, sale_declined, create_order_timeout, webhook:settled
    txn_id: str | None = None
    order_id: str | None = None
    occurred_at: float | None = None  # producer timestamp, can be older than t (late webhooks)
    detail: str | None = None  # free text; never forwarded to the LLM


@dataclass
class SagaSnapshot:
    """Everything known about one checkout at decision time."""

    saga_id: str
    cart_id: str
    expected_total: Decimal
    transactions: list[GatewayTxn] = field(default_factory=list)
    order: Order | None = None
    order_lookup_done: bool = False
    events: list[SagaEvent] = field(default_factory=list)
    nonce: str | None = None
    platform_token: str | None = None
