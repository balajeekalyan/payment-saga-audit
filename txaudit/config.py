import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    bt_environment: str = os.getenv("BT_ENVIRONMENT", "sandbox")
    bt_merchant_id: str = os.getenv("BT_MERCHANT_ID", "")
    bt_public_key: str = os.getenv("BT_PUBLIC_KEY", "")
    bt_private_key: str = os.getenv("BT_PRIVATE_KEY", "")
    bt_min_interval_s: float = float(os.getenv("BT_MIN_INTERVAL_S", "1.5"))
    bt_rate_limit_backoff_s: float = float(os.getenv("BT_RATE_LIMIT_BACKOFF_S", "330"))
    auditor_model: str = os.getenv("AUDITOR_MODEL", "claude-opus-5-5")
    auditor_effort: str = os.getenv("AUDITOR_EFFORT", "medium")
    auditor_min_confidence: float = float(os.getenv("AUDITOR_MIN_CONFIDENCE", "0.7"))
    pseudonym_secret: str = os.getenv("PSEUDONYM_SECRET", "change-me")
    db_path: str = os.getenv("TXAUDIT_DB", "txaudit.db")

    @property
    def has_braintree(self) -> bool:
        return all([self.bt_merchant_id, self.bt_public_key, self.bt_private_key])


settings = Settings()
