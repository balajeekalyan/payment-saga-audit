from txaudit.pii_scan import scan


def categories(text, snap=None):
    return {h.category for h in scan(text, snap)}


def test_detects_luhn_valid_pan_only():
    assert "pan" in categories("card 4111 1111 1111 1111 declined")
    assert "pan" not in categories("order 4111111111111112")  # fails Luhn


def test_detects_email_phone_and_nonce():
    assert {"email", "phone", "bt_nonce"} <= categories(
        "jane@example.com called +1 415-555-0100 with tokencc_bc_abc123"
    )


def test_exact_match_on_snapshot_values(ctx):
    from harness.scenarios import CANARY, happy

    snap = happy(ctx)
    ctx.saga.refresh(snap)
    assert "name" in categories(f"customer {CANARY.name}", snap)
    assert "txn_id" in categories(f"txn {snap.transactions[0].txn_id}", snap)
