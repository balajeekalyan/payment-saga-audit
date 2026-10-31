from decimal import Decimal

import pytest

from txaudit import models as m
from txaudit.gateway import GatewayError, RateLimited, SimGateway, Throttle


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


class TooMany(Exception):
    pass


def make(clock, **kw):
    return Throttle(1.5, 330, limited=(TooMany,), clock=clock.clock, sleep=clock.sleep, **kw)


def test_spaces_calls_by_min_interval():
    c = FakeClock()
    t = make(c)
    t.call(lambda: None)
    c.now += 0.5  # the caller spent 0.5 s between calls
    t.call(lambda: None)
    assert c.sleeps == [1.0]


def test_no_wait_when_interval_already_elapsed():
    c = FakeClock()
    t = make(c)
    t.call(lambda: None)
    c.now += 2.0
    t.call(lambda: None)
    assert c.sleeps == []


def test_retries_once_after_backoff():
    c = FakeClock()
    t = make(c)
    attempts = []

    def fn():
        attempts.append(c.now)
        if len(attempts) == 1:
            raise TooMany()
        return "ok"

    assert t.call(fn) == "ok"
    assert len(attempts) == 2
    assert attempts[1] - attempts[0] >= 330


def test_second_rate_limit_raises_rate_limited():
    c = FakeClock()
    t = make(c)

    def fn():
        raise TooMany()

    with pytest.raises(RateLimited):
        t.call(fn)


def test_other_errors_pass_through_without_retry():
    c = FakeClock()
    t = make(c)
    calls = []

    def fn():
        calls.append(1)
        raise ValueError("not found")

    with pytest.raises(ValueError):
        t.call(fn)
    assert calls == [1]


@pytest.mark.parametrize("nonce, after_capture", [
    ("fake-valid-visa-nonce", m.SUBMITTED),
    ("fake-venmo-account-nonce", m.SUBMITTED),
    ("fake-paypal-billing-agreement-nonce", m.SETTLING),  # observed in the sandbox, run 2026-10-27
])
def test_sim_capture_matches_sandbox_per_instrument(nonce, after_capture):
    gw = SimGateway()
    token, _ = gw.vault(gw.create_customer(), nonce)
    txn = gw.sale(token, Decimal("88.00"))
    assert gw.submit_for_settlement(txn.txn_id).status == after_capture
    if after_capture == m.SETTLING:
        with pytest.raises(GatewayError):
            gw.void(txn.txn_id)
        gw.refund(txn.txn_id)
    assert gw.settle(txn.txn_id).status == m.SETTLED
