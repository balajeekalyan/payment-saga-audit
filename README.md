ple# txaudit: privacy-preserving LLM auditor for Braintree checkout sagas

Claude audits each checkout saga and recommends approve / void / refund / no_action /
escalate. A deterministic policy guard checks every recommendation against fresh gateway
state and executes or escalates. The model only ever sees an allow-listed, pseudonymized
view with no PII or PCI data.

```
browser nonce ──> /api/vault ──> Braintree payment method token ──> platform token (ptok_…)
                                                                         │
place order ──> Transaction.sale(payment_method_token, auth only) ──> order service
                                                                         │
            refresh gateway + order state ──> SafeView ──> PII scan ──> Claude (or rules)
                                                                         │
                                   policy guard (I1–I7) ──> submit / void / refund / escalate
```

## Layout

| Path | What it is |
|---|---|
| `txaudit/safeview.py` | The LLM-safe view: allow-list models, opaque labels, amount buckets, no free text |
| `txaudit/pii_scan.py` | Fail-closed scan of every prompt (exact snapshot values + PAN/email/phone/nonce patterns) |
| `txaudit/auditor.py` | `ClaudeAuditor` (structured output, refusal fallback) and the `RulesReconciler` baseline |
| `txaudit/policy.py` | The guard: invariants I1–I7, escalation instead of substitution |
| `txaudit/gateway.py` | `BraintreeGateway` (sandbox) and `SimGateway` (same semantics, offline) |
| `txaudit/saga.py` | Checkout saga and a fault-injectable order service |
| `harness/` | Scenarios, the experiment runner, and the metrics tables |
| `server/`, `client/` | Manual demo: Hosted Fields, PayPal (vault flow), Venmo (multi-use) |
| `tests/` | Privacy, guard, auditor and harness tests (offline) |

## Setup

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows; use .venv/bin on macOS/Linux
cp .env.example .env    # fill in Braintree sandbox keys
```

Claude credentials come from `ANTHROPIC_API_KEY` or an `ant auth login` profile.

## Run

```bash
# Offline tests
.venv/Scripts/python -m pytest -q

# Experiments. Start on the simulator, then repeat on the real sandbox for the paper.
.venv/Scripts/python -m harness.run --gateway sim --arms rules,rules+guard,llm,llm+guard --trials 5
.venv/Scripts/python -m harness.run --gateway braintree --arms rules,rules+guard,llm,llm+guard --trials 10 --instruments card,paypal,venmo
.venv/Scripts/python -m harness.metrics results/run_*.jsonl

# Manual demo
.venv/Scripts/python -m uvicorn server.app:app --port 8000   # open http://localhost:8000
```

## Experiment arms

| Arm | Recommender | Guard |
|---|---|---|
| `rules` | decision table | off |
| `rules+guard` | decision table | on |
| `llm` | Claude | off (ablation: shows what the guard prevents) |
| `llm+guard` | Claude | on (proposed system) |

Each JSONL row records: correct, escalated, unsafe actions proposed / blocked / executed,
illegal gateway attempts, PII hits, latency, tokens, the exact view the model saw, and the
model's rationales (for grading explanation quality).

## Scenarios

`harness/scenarios.py`. "Anticipated" means the rules table has an explicit rule for that
failure mode; unanticipated cases are handled, if at all, by a fallback or by luck.

| Scenario | Injected fault | Correct outcome | Anticipated |
|---|---|---|---|
| happy | none | approve | yes |
| processor_decline | sandbox amount 2000.00 | no_action | yes |
| network_unavailable | sandbox amount 3000.00 | no_action | yes |
| order_timeout_no_order | order service times out before commit | void | yes |
| order_timeout_lost_response | order committed, response lost | approve | yes |
| duplicate_click | two authorizations for one cart | approve one, void the other | yes |
| amount_mismatch | order total changes after authorization | void or escalate | yes |
| cancelled_before_capture | order cancelled while authorized | void | yes |
| cancelled_after_settlement | order cancelled after settlement | refund | yes |
| cancelled_during_capture | order cancelled after capture, before settlement | void | yes |
| retry_after_network_failure | sale times out client-side but was authorized; retry authorized | approve one, void the other | yes |
| stale_webhook | authorization webhook arrives after capture | no_action | no |
| duplicate_one_settled | client retry authorizes after first charge settled | no_action + void | no |
| auth_expired | authorization expires before capture (simulator only) | escalate or no_action | no |
| settlement_declined | captured, then settlement declined | escalate or no_action | no |
| conflicting_webhook | "voided" webhook, gateway says authorized | approve or escalate | no |
| both_duplicates_settled | two charges for one order both settled | refund one, no_action other | no |

## Notes on the sandbox

- Fake nonces (`fake-valid-visa-nonce`, `fake-paypal-billing-agreement-nonce`,
  `fake-venmo-account-nonce`) let the harness skip the browser. PayPal and Venmo must be
  enabled in the sandbox Control Panel for those to vault.
- `settle` and `settlement_decline` use `gateway.testing.*`, which works only in the sandbox.
  Check that settlement decline is supported for the payment type you test with.
- The sandbox cannot force an authorization to expire, so `auth_expired` runs only on
  `--gateway sim`; the runner skips it on `braintree`.
- The decline and failure amounts follow Braintree's testing docs. Check them against the
  current docs before reporting results.
