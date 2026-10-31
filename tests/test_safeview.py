import pytest
from pydantic import ValidationError

from harness.scenarios import CANARY, SCENARIOS
from txaudit.pii_scan import scan
from txaudit.safeview import Pseudonymizer, SafeTxn, build_safe_view, render


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_no_sensitive_data_in_any_scenario_view(scenario, ctx, settings):
    snap = scenario.setup(ctx)
    ctx.saga.refresh(snap)
    prompt = render(build_safe_view(snap, Pseudonymizer(settings.pseudonym_secret)))

    assert scan(prompt, snap) == []
    for value in (CANARY.name, CANARY.email, CANARY.address, CANARY.phone, ctx.pm_token, snap.nonce,
                  snap.platform_token, snap.cart_id, snap.saga_id):
        assert value not in prompt
    for txn in snap.transactions:
        assert txn.txn_id not in prompt
        assert str(txn.amount) not in prompt


def test_labels_resolve_server_side_only(ctx, settings):
    snap = SCENARIOS[0].setup(ctx)
    ctx.saga.refresh(snap)
    pz = Pseudonymizer(settings.pseudonym_secret)
    view = build_safe_view(snap, pz)
    assert view.transactions[0].ref == "T1"
    assert pz.resolve("T1") == snap.transactions[0].txn_id
    assert pz.resolve("T9") is None


def test_view_rejects_fields_outside_allow_list():
    with pytest.raises(ValidationError):
        SafeTxn(ref="T1", instrument="credit_card", status="authorized", amount_bucket="10-50",
                amount_matches_order_total=True, created_t=0.0, refunded=False,
                customer_email="x@example.com")


def test_view_rejects_free_text_in_coded_fields():
    with pytest.raises(ValidationError):
        SafeTxn(ref="T1", instrument="credit_card", status="authorized", amount_bucket="10-50",
                amount_matches_order_total=True, created_t=0.0, refunded=False,
                processor_response_code="Declined for Zelda")
