"""Demo checkout server for the manual flows (Hosted Fields, PayPal vault, Venmo).

    uvicorn server.app:app --reload --port 8000   then open http://localhost:8000

Flow: browser nonce -> /api/vault (Braintree payment method token, mapped to a platform
token) -> /api/place-order (auth with the vaulted token, create order, audit, finish).
The browser only ever holds the platform token.
"""

import uuid
from decimal import Decimal, InvalidOperation
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from harness.scenarios import CANARY
from txaudit.auditor import ClaudeAuditor, RulesReconciler
from txaudit.config import settings
from txaudit.gateway import BraintreeGateway, GatewayError
from txaudit.saga import OrderService, Saga
from txaudit.store import Store

app = FastAPI(title="txaudit demo")
gateway = BraintreeGateway(settings) if settings.has_braintree else None
store = Store(settings.db_path)
orders = OrderService()
saga = Saga(gateway, orders, store, settings)
recommenders = {"llm": None, "rules": RulesReconciler()}
webhook_log: list[dict] = []

CLIENT = Path(__file__).resolve().parent.parent / "client" / "index.html"


def require_gateway() -> BraintreeGateway:
    if gateway is None:
        raise HTTPException(503, "Braintree sandbox credentials are not configured (.env)")
    return gateway


class VaultIn(BaseModel):
    nonce: str


class PlaceOrderIn(BaseModel):
    platform_token: str
    amount: str
    recommender: str = "llm"
    fault: str | None = None  # timeout_before_commit | timeout_after_commit, for live demos


@app.get("/")
def index():
    return FileResponse(CLIENT)


@app.get("/api/client-token")
def client_token():
    return {"client_token": require_gateway().client_token()}


@app.post("/api/vault")
def vault(body: VaultIn):
    gw = require_gateway()
    try:
        customer_id = gw.create_customer()
        pm_token, instrument = gw.vault(customer_id, body.nonce)
    except GatewayError as e:
        raise HTTPException(422, str(e))
    return {"platform_token": store.issue_platform_token(customer_id, pm_token, instrument), "instrument": instrument}


@app.post("/api/place-order")
def place_order(body: PlaceOrderIn):
    require_gateway()
    pm_token = store.resolve_platform_token(body.platform_token)
    if pm_token is None:
        raise HTTPException(404, "unknown platform token")
    try:
        amount = Decimal(body.amount).quantize(Decimal("0.01"))
    except InvalidOperation:
        raise HTTPException(422, "bad amount")

    if body.recommender == "llm" and recommenders["llm"] is None:
        recommenders["llm"] = ClaudeAuditor(settings)
    recommender = recommenders.get(body.recommender)
    if recommender is None:
        raise HTTPException(422, "recommender must be llm or rules")

    snap = saga.new_snapshot(f"cart_{uuid.uuid4().hex[:12]}", amount)
    txn = saga.authorize(snap, pm_token, amount)
    if txn is not None and txn.status == "authorized":
        orders.fault = body.fault
        saga.create_order(snap, CANARY)  # demo customer; real PII would come from the session
    outcome = saga.audit_and_finish(snap, recommender)

    rationale = {}
    if outcome.audit.recommendation:
        rationale = {d.txn_ref: d.rationale for d in outcome.audit.recommendation.decisions}
    return {
        "saga_ref": outcome.view.saga_ref,
        "order_created": snap.order is not None,
        "decisions": [
            {
                "txn_ref": d.txn_ref,
                "proposed": d.proposed.value,
                "final": d.final.value,
                "blocked_by": d.blocked_by,
                "executed": d.executed,
                "gateway_error": d.gateway_error,
                "rationale": rationale.get(d.txn_ref),
            }
            for d in outcome.decisions
        ],
        "audit_error": outcome.audit.error,
        "llm_view": outcome.view.model_dump(mode="json"),  # exactly what the model saw
    }


@app.post("/api/webhooks/braintree")
def braintree_webhook(bt_signature: str = Form(...), bt_payload: str = Form(...)):
    notification = require_gateway().gw.webhook_notification.parse(bt_signature, bt_payload)
    txn = getattr(notification, "transaction", None)
    webhook_log.append({"kind": notification.kind, "txn_id": txn.id if txn else None,
                        "timestamp": notification.timestamp.isoformat()})
    return {"ok": True}


@app.get("/api/audit/{saga_ref}")
def audit(saga_ref: str):
    return store.audit_records(saga_ref)


@app.get("/api/escalations")
def escalations():
    return store.open_escalations()
