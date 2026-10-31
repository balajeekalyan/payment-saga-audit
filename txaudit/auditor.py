"""Recommenders: the Claude auditor and the rules-only baseline.

Both see only a SafeView and return a Recommendation. Neither executes anything;
execution goes through policy.Guard (or, for the LLM-only ablation, straight through).
"""

import json
import time
from dataclasses import dataclass, field
from typing import Literal

import anthropic
from pydantic import BaseModel, ValidationError

from . import models as m
from .pii_scan import scan
from .safeview import SafeView, render


class Decision(BaseModel):
    txn_ref: str
    action: m.Action
    confidence: float
    rationale: str
    evidence: list[str]


class Recommendation(BaseModel):
    decisions: list[Decision]
    summary: str


@dataclass
class AuditResult:
    recommendation: Recommendation | None
    recommender: str
    prompt: str = ""
    raw_response: str = ""
    error: str | None = None  # refusal, parse failure, API error, PII block
    latency_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    request_id: str | None = None
    pii_hits: list = field(default_factory=list)


OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "decisions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "txn_ref": {"type": "string"},
                    "action": {"type": "string", "enum": [a.value for a in m.Action]},
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["txn_ref", "action", "confidence", "rationale", "evidence"],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["decisions", "summary"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """\
You audit e-commerce checkout sagas that pay through Braintree and recommend how to \
finish each payment transaction. A separate policy layer validates and executes your \
recommendations; you never move money yourself.

The checkout saga: the client places an order, the server authorizes a vaulted payment \
method (Transaction.sale without capture), the order service creates the order, and the \
payment is then finished. Steps can time out, be retried, or be duplicated, and \
Braintree webhooks can arrive late or out of order.

What you receive is a privacy-preserving view. Transactions (T1, T2, ...), the order \
(O1) and the saga are opaque labels. Amounts are bucketed; amount_matches_order_total \
is computed server-side from exact values. Customer and card data are never included.

Field semantics:
- transactions[].status was fetched from the gateway at decision time and is the \
current truth. events[] is history in arrival order (t); occurred_t is when the \
producer says it happened, so a webhook with occurred_t far below t arrived late.
- order is the order service's record as of decision time. If order_lookup_done is \
true and order is null, the order does not exist, whatever earlier events suggested.
- processor_response_code follows Braintree: 1000-1999 approved, 2000-2999 declined, \
3000 processor network unavailable.

Actions, one per transaction:
- approve: capture (submit_for_settlement). Only valid on an authorized transaction.
- void: cancel an authorized or submitted_for_settlement transaction before it settles.
- refund: return funds on a settling or settled transaction.
- no_action: the transaction is already in the right state, or never succeeded.
- escalate: the evidence does not support a confident decision; a human will review.

A customer should be charged at most once per order, only for an order that exists and \
is not cancelled, and only for the order's total. Give one decision for every \
transaction in the view. Confidence is your probability, from 0 to 1, that the action \
is correct. Cite the events and fields you relied on in evidence, and explain the \
decision in rationale so an auditor can follow it.\
"""


class ClaudeAuditor:
    name = "llm"

    def __init__(self, settings, client: anthropic.Anthropic | None = None) -> None:
        self.model = settings.auditor_model
        self.effort = settings.auditor_effort
        self.client = client or anthropic.Anthropic()

    def recommend(self, view: SafeView, snap: m.SagaSnapshot | None = None) -> AuditResult:
        prompt = "Audit this checkout saga.\n\n" + render(view)
        result = AuditResult(recommendation=None, recommender=self.name, prompt=prompt)

        # Fail closed: a prompt that trips the PII scanner is never sent.
        result.pii_hits = scan(prompt, snap)
        if result.pii_hits:
            result.error = "pii_blocked"
            return result

        start = time.monotonic()
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                output_config={
                    "effort": self.effort,
                    "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
                },
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.RateLimitError as e:
            result.error = f"rate_limited: {e.message}"
            return result
        except anthropic.APIStatusError as e:
            result.error = f"api_error {e.status_code}: {e.message}"
            return result
        except anthropic.APIConnectionError as e:
            result.error = f"connection_error: {e}"
            return result
        finally:
            result.latency_s = time.monotonic() - start

        result.request_id = response._request_id
        result.input_tokens = response.usage.input_tokens
        result.output_tokens = response.usage.output_tokens

        if response.stop_reason == "refusal":
            category = response.stop_details.category if response.stop_details else None
            result.error = f"refusal: {category}"
            return result
        if response.stop_reason == "max_tokens":
            result.error = "max_tokens"
            return result

        text = next((b.text for b in response.content if b.type == "text"), "")
        result.raw_response = text
        try:
            result.recommendation = Recommendation.model_validate(json.loads(text))
        except (json.JSONDecodeError, ValidationError) as e:
            result.error = f"parse_error: {e}"
        return result


class RulesReconciler:
    """Deterministic baseline: a decision table a payments engineer would write for the
    known failure modes. It sees the same SafeView as the LLM."""

    name = "rules"

    def recommend(self, view: SafeView, snap: m.SagaSnapshot | None = None) -> AuditResult:
        start = time.monotonic()
        order = view.order
        order_live = order is not None and order.status == "created"
        authorized = [t for t in view.transactions if t.status == "authorized"]

        decisions = []
        for t in view.transactions:
            action, why = self._decide(t, order, order_live, authorized)
            decisions.append(
                Decision(txn_ref=t.ref, action=action, confidence=1.0, rationale=why, evidence=[])
            )
        rec = Recommendation(decisions=decisions, summary="rules")
        return AuditResult(
            recommendation=rec, recommender=self.name, latency_s=time.monotonic() - start
        )

    @staticmethod
    def _decide(t, order, order_live, authorized) -> tuple[m.Action, str]:
        if t.status in {"processor_declined", "gateway_rejected", "failed", "voided"}:
            return m.Action.NO_ACTION, "transaction did not succeed or is already voided"
        if t.status == "authorized":
            if not order_live:
                return m.Action.VOID, "no live order for this authorization"
            if t.amount_matches_order_total is False:
                return m.Action.VOID, "authorized amount differs from order total"
            # Duplicate authorizations: keep the earliest, void the rest.
            if len(authorized) > 1 and t.ref != authorized[0].ref:
                return m.Action.VOID, "duplicate authorization for the same cart"
            return m.Action.APPROVE, "authorized and order exists"
        if t.status == "submitted_for_settlement":
            if not order_live:
                return m.Action.VOID, "captured but order missing or cancelled"
            return m.Action.NO_ACTION, "already captured"
        if t.status in {"settling", "settled"}:
            if not order_live and not t.refunded:
                return m.Action.REFUND, "settled but order missing or cancelled"
            return m.Action.NO_ACTION, "settled for a live order"
        return m.Action.ESCALATE, f"unhandled status {t.status}"


Recommender = ClaudeAuditor | RulesReconciler
RecommenderName = Literal["llm", "rules"]
