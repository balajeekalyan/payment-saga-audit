"""Last-line check on every prompt before it leaves the process.

Two independent detectors:
- exact match against every sensitive value in the raw snapshot (customer fields, real
  IDs, tokens, nonces, card BIN), so a leak of known data is caught with certainty;
- pattern match for PII/PCI shapes the snapshot did not list (PANs that pass Luhn,
  emails, phone numbers, Braintree token/nonce formats).

A hit blocks the LLM call; the saga is escalated instead (fail closed).
"""

import re
from dataclasses import dataclass

from . import models as m

PATTERNS = {
    "pan": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?<!\d)\+?\d{1,2}[ .-]?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"),
    "bt_nonce": re.compile(r"\b(?:tokencc_|fake-)[A-Za-z0-9_-]+"),
    "uuid": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
}


@dataclass
class Hit:
    detector: str
    category: str


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def sensitive_values(snap: m.SagaSnapshot) -> dict[str, list[str]]:
    vals: dict[str, list[str]] = {
        "saga_id": [snap.saga_id],
        "cart_id": [snap.cart_id],
        "nonce": [snap.nonce or ""],
        "platform_token": [snap.platform_token or ""],
        "txn_id": [t.txn_id for t in snap.transactions],
        "payment_method_token": [t.payment_method_token for t in snap.transactions],
        "card_bin": [t.card_bin or "" for t in snap.transactions],
        # Long free-text details only: short ones ("timeout") would collide with event kinds.
        "event_detail": [e.detail or "" for e in snap.events if e.detail and len(e.detail) >= 12],
    }
    if snap.order:
        c = snap.order.customer
        vals.update(
            order_id=[snap.order.order_id],
            name=[c.name],
            email=[c.email],
            address=[c.address],
            phone=[c.phone],
        )
    return {k: [v for v in vs if v and len(v) >= 4] for k, vs in vals.items()}


def scan(prompt: str, snap: m.SagaSnapshot | None = None) -> list[Hit]:
    hits: list[Hit] = []
    if snap is not None:
        for category, values in sensitive_values(snap).items():
            if any(v in prompt for v in values):
                hits.append(Hit("exact", category))
    for category, rx in PATTERNS.items():
        for match in rx.finditer(prompt):
            text = match.group(0)
            if category == "pan":
                digits = re.sub(r"\D", "", text)
                if not _luhn(digits):
                    continue
            hits.append(Hit("pattern", category))
            break
    return hits
