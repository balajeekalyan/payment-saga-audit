"""Payment gateway adapters.

BraintreeGateway talks to the real Braintree sandbox. SimGateway reproduces the sandbox
semantics the experiments rely on (test amounts, fake nonces, legal state transitions)
so unit tests and dry runs need no network or credentials.
"""

import itertools
import threading
import time
import uuid
from decimal import Decimal
from typing import Protocol

from . import models as m


class GatewayError(Exception):
    pass


class RateLimited(Exception):
    """Braintree still rate-limited the call after the backoff. Deliberately not a
    GatewayError: the operation never reached the gateway, so it must not be scored as a
    rejected money movement."""


class Throttle:
    """Spaces calls at least `min_interval` seconds apart and, when the gateway answers
    with a rate-limit error, waits `backoff` seconds and retries once."""

    def __init__(self, min_interval: float, backoff: float, limited: tuple = (),
                 clock=time.monotonic, sleep=time.sleep) -> None:
        self.min_interval = min_interval
        self.backoff = backoff
        self.limited = limited
        self.clock = clock
        self.sleep = sleep
        self._last: float | None = None
        # Held through the backoff too, so other server threads don't extend the block.
        self._lock = threading.Lock()

    def call(self, fn, *args):
        with self._lock:
            for attempt in range(2):
                if self._last is not None:
                    delay = self._last + self.min_interval - self.clock()
                    if delay > 0:
                        self.sleep(delay)
                try:
                    return fn(*args)
                except self.limited as e:
                    if attempt:
                        raise RateLimited(f"still rate-limited after {self.backoff:.0f}s backoff") from e
                    self.sleep(self.backoff)
                finally:
                    # Measured from the end of the call, which is the conservative side.
                    self._last = self.clock()


class Gateway(Protocol):
    def create_customer(self) -> str: ...
    def vault(self, customer_id: str, nonce: str) -> tuple[str, str]: ...
    def sale(self, payment_method_token: str, amount: Decimal) -> m.GatewayTxn: ...
    def find(self, txn_id: str) -> m.GatewayTxn: ...
    def submit_for_settlement(self, txn_id: str) -> m.GatewayTxn: ...
    def void(self, txn_id: str) -> m.GatewayTxn: ...
    def refund(self, txn_id: str) -> m.GatewayTxn: ...
    def settle(self, txn_id: str) -> m.GatewayTxn: ...  # sandbox only
    def settlement_decline(self, txn_id: str) -> m.GatewayTxn: ...  # sandbox only
    def expire_authorization(self, txn_id: str) -> m.GatewayTxn: ...  # simulator only


# Braintree sandbox fake nonces -> payment instrument type.
FAKE_NONCES = {
    "fake-valid-nonce": "credit_card",
    "fake-valid-visa-nonce": "credit_card",
    "fake-valid-mastercard-nonce": "credit_card",
    "fake-paypal-billing-agreement-nonce": "paypal_account",
    "fake-venmo-account-nonce": "venmo_account",
}


def sandbox_outcome(amount: Decimal) -> tuple[str, str, str]:
    """Status, processor response code and text that the Braintree sandbox
    returns for a given amount (see Braintree "Testing and Go Live" docs)."""
    if Decimal("2000.00") <= amount <= Decimal("2999.99"):
        code = str(int(amount))
        return m.PROCESSOR_DECLINED, code, "Processor Declined"
    if Decimal("3000.00") <= amount <= Decimal("3000.99"):
        return m.FAILED, "3000", "Processor Network Unavailable - Try Again"
    return m.AUTHORIZED, "1000", "Approved"


class SimGateway:
    def __init__(self) -> None:
        self._txns: dict[str, m.GatewayTxn] = {}
        self._tokens: dict[str, str] = {}  # pm token -> instrument
        self._used_nonces: set[str] = set()
        self._ids = itertools.count(1)
        self.calls: list[tuple[str, str]] = []  # (operation, txn_id) for metrics

    def create_customer(self) -> str:
        return f"cust_{uuid.uuid4().hex[:10]}"

    def vault(self, customer_id: str, nonce: str) -> tuple[str, str]:
        if nonce in self._used_nonces and nonce not in FAKE_NONCES:
            raise GatewayError("Cannot use a payment_method_nonce more than once.")
        instrument = FAKE_NONCES.get(nonce, "credit_card")
        self._used_nonces.add(nonce)
        token = f"pm_{uuid.uuid4().hex[:12]}"
        self._tokens[token] = instrument
        return token, instrument

    def sale(self, payment_method_token: str, amount: Decimal) -> m.GatewayTxn:
        if payment_method_token not in self._tokens:
            raise GatewayError("Payment method token is invalid.")
        status, code, text = sandbox_outcome(amount)
        instrument = self._tokens[payment_method_token]
        txn = m.GatewayTxn(
            txn_id=f"{next(self._ids):08x}",
            status=status,
            amount=amount,
            payment_method_token=payment_method_token,
            payment_instrument=instrument,
            processor_response_code=code,
            processor_response_text=text,
            card_bin="411111" if instrument == "credit_card" else None,
            card_last4="1111" if instrument == "credit_card" else None,
            created_at=time.time(),
        )
        self._txns[txn.txn_id] = txn
        self.calls.append(("sale", txn.txn_id))
        return txn

    def find(self, txn_id: str) -> m.GatewayTxn:
        if txn_id not in self._txns:
            raise GatewayError(f"Transaction not found: {txn_id}")
        return self._txns[txn_id]

    def _move(self, op: str, txn_id: str, allowed: set[str], to: str) -> m.GatewayTxn:
        txn = self.find(txn_id)
        self.calls.append((op, txn_id))
        if txn.status not in allowed:
            raise GatewayError(f"Cannot {op} transaction in status {txn.status}")
        txn.status = to
        return txn

    def submit_for_settlement(self, txn_id: str) -> m.GatewayTxn:
        # The sandbox moves PayPal straight to settling, so it can no longer be voided.
        to = m.SETTLING if self.find(txn_id).payment_instrument == "paypal_account" else m.SUBMITTED
        return self._move("submit_for_settlement", txn_id, {m.AUTHORIZED}, to)

    def void(self, txn_id: str) -> m.GatewayTxn:
        return self._move("void", txn_id, {m.AUTHORIZED, m.SUBMITTED}, m.VOIDED)

    def refund(self, txn_id: str) -> m.GatewayTxn:
        original = self.find(txn_id)
        self.calls.append(("refund", txn_id))
        if original.status not in {m.SETTLED, m.SETTLING}:
            raise GatewayError("Cannot refund a transaction unless it is settled.")
        refund = m.GatewayTxn(
            txn_id=f"{next(self._ids):08x}",
            status=m.SUBMITTED,
            amount=original.amount,
            payment_method_token=original.payment_method_token,
            payment_instrument=original.payment_instrument,
            created_at=time.time(),
        )
        self._txns[refund.txn_id] = refund
        if original.refunded:
            raise GatewayError("Transaction has already been fully refunded.")
        # Braintree keeps the original settled and records the refund as a new transaction.
        original.refunded = True
        return refund

    def settle(self, txn_id: str) -> m.GatewayTxn:
        return self._move("settle", txn_id, {m.SUBMITTED, m.SETTLING}, m.SETTLED)

    def settlement_decline(self, txn_id: str) -> m.GatewayTxn:
        return self._move("settlement_decline", txn_id, {m.SUBMITTED, m.SETTLING}, m.SETTLEMENT_DECLINED)

    def expire_authorization(self, txn_id: str) -> m.GatewayTxn:
        return self._move("expire_authorization", txn_id, {m.AUTHORIZED}, m.AUTH_EXPIRED)


class BraintreeGateway:
    # One throttle per process: the harness builds a new gateway for every saga, and the
    # sandbox limit is per IP, not per gateway object.
    _throttle: Throttle | None = None

    def __init__(self, settings) -> None:
        import braintree

        self._bt = braintree
        env = {
            "sandbox": braintree.Environment.Sandbox,
            "production": braintree.Environment.Production,
        }[settings.bt_environment]
        self.gw = braintree.BraintreeGateway(
            braintree.Configuration(
                environment=env,
                merchant_id=settings.bt_merchant_id,
                public_key=settings.bt_public_key,
                private_key=settings.bt_private_key,
            )
        )
        self.calls: list[tuple[str, str]] = []
        if BraintreeGateway._throttle is None:
            BraintreeGateway._throttle = Throttle(
                settings.bt_min_interval_s,
                settings.bt_rate_limit_backoff_s,
                limited=(braintree.exceptions.TooManyRequestsError,),
            )

    def _call(self, fn, *args):
        return BraintreeGateway._throttle.call(fn, *args)

    def client_token(self) -> str:
        return self._call(self.gw.client_token.generate)

    def create_customer(self) -> str:
        # Deliberately no name/email: the vault customer is an opaque container.
        result = self._call(self.gw.customer.create, {})
        self._check(result)
        return result.customer.id

    def vault(self, customer_id: str, nonce: str) -> tuple[str, str]:
        """Store a single-use nonce as a reusable payment method token.

        PayPal nonces must come from the Vault flow (or Checkout with Vault) and Venmo
        nonces from a multi-use tokenization, otherwise Braintree refuses to vault them.
        """
        nonce_info = self._call(self.gw.payment_method_nonce.find, nonce)
        instrument = {
            "CreditCard": "credit_card",
            "PayPalAccount": "paypal_account",
            "VenmoAccount": "venmo_account",
        }.get(nonce_info.type, nonce_info.type)
        params = {"customer_id": customer_id, "payment_method_nonce": nonce}
        if instrument == "credit_card":
            params["options"] = {"verify_card": True}
        result = self._call(self.gw.payment_method.create, params)
        self._check(result)
        return result.payment_method.token, instrument

    def sale(self, payment_method_token: str, amount: Decimal) -> m.GatewayTxn:
        result = self._call(
            self.gw.transaction.sale,
            {
                "amount": str(amount),
                "payment_method_token": payment_method_token,
                "options": {"submit_for_settlement": False},  # auth only; capture after audit
            }
        )
        # Declines still return a transaction object; validation errors do not.
        if result.transaction is None:
            self._check(result)
        txn = self._to_txn(result.transaction, payment_method_token)
        self.calls.append(("sale", txn.txn_id))
        return txn

    def find(self, txn_id: str) -> m.GatewayTxn:
        try:
            return self._to_txn(self._call(self.gw.transaction.find, txn_id))
        except self._bt.exceptions.NotFoundError as e:
            raise GatewayError(f"Transaction not found: {txn_id}") from e

    def submit_for_settlement(self, txn_id: str) -> m.GatewayTxn:
        return self._op("submit_for_settlement", txn_id, self.gw.transaction.submit_for_settlement)

    def void(self, txn_id: str) -> m.GatewayTxn:
        return self._op("void", txn_id, self.gw.transaction.void)

    def refund(self, txn_id: str) -> m.GatewayTxn:
        return self._op("refund", txn_id, self.gw.transaction.refund)

    def settle(self, txn_id: str) -> m.GatewayTxn:
        return self._op("settle", txn_id, self.gw.testing.settle_transaction)

    def settlement_decline(self, txn_id: str) -> m.GatewayTxn:
        return self._op("settlement_decline", txn_id, self.gw.testing.settlement_decline_transaction)

    def expire_authorization(self, txn_id: str) -> m.GatewayTxn:
        # The sandbox has no API to age an authorization; scenarios using this are sim_only.
        raise GatewayError("authorization expiry cannot be forced in the Braintree sandbox")

    def _op(self, name: str, txn_id: str, fn) -> m.GatewayTxn:
        self.calls.append((name, txn_id))
        result = self._call(fn, txn_id)
        self._check(result)
        return self._to_txn(result.transaction)

    def _check(self, result) -> None:
        if not result.is_success:
            raise GatewayError(result.message)

    def _to_txn(self, t, payment_method_token: str | None = None) -> m.GatewayTxn:
        card = getattr(t, "credit_card_details", None)
        return m.GatewayTxn(
            txn_id=t.id,
            status=t.status,
            amount=Decimal(str(t.amount)),
            payment_method_token=payment_method_token or "",
            payment_instrument=t.payment_instrument_type,
            processor_response_code=t.processor_response_code,
            processor_response_text=t.processor_response_text,
            gateway_rejection_reason=t.gateway_rejection_reason,
            card_bin=getattr(card, "bin", None),
            card_last4=getattr(card, "last_4", None),
            created_at=t.created_at.timestamp() if t.created_at else time.time(),
            refunded=bool(getattr(t, "refund_ids", None)),
        )


def make_gateway(kind: str, settings):
    if kind == "sim":
        return SimGateway()
    if kind == "braintree":
        if not settings.has_braintree:
            raise SystemExit("Set BT_MERCHANT_ID, BT_PUBLIC_KEY and BT_PRIVATE_KEY in .env")
        return BraintreeGateway(settings)
    raise ValueError(kind)
