import pytest

from harness.scenarios import Ctx
from txaudit.config import Settings
from txaudit.gateway import SimGateway
from txaudit.saga import OrderService, Saga
from txaudit.store import Store


@pytest.fixture
def settings():
    return Settings(pseudonym_secret="test-secret", auditor_min_confidence=0.7)


@pytest.fixture
def ctx(settings):
    gw = SimGateway()
    saga = Saga(gw, OrderService(), Store(), settings)
    pm_token, _ = gw.vault(gw.create_customer(), "fake-valid-visa-nonce")
    return Ctx(saga, pm_token)
