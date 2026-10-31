"""SQLite persistence: platform token map, audit log and escalation queue."""

import json
import secrets
import sqlite3
import time
from dataclasses import asdict

SCHEMA = """
CREATE TABLE IF NOT EXISTS platform_tokens (
    platform_token TEXT PRIMARY KEY,
    bt_customer_id TEXT NOT NULL,
    bt_payment_method_token TEXT NOT NULL,
    instrument TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    saga_ref TEXT NOT NULL,
    recommender TEXT NOT NULL,
    prompt TEXT,
    response TEXT,
    decisions TEXT NOT NULL,
    error TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS escalations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    saga_ref TEXT NOT NULL,
    txn_ref TEXT NOT NULL,
    txn_id TEXT,  -- real Braintree ID, for the human reviewer only
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def issue_platform_token(self, customer_id: str, pm_token: str, instrument: str) -> str:
        """The platform token is what our own services and the browser hold; only this
        table can turn it back into a Braintree payment method token."""
        token = "ptok_" + secrets.token_urlsafe(18)
        self.db.execute(
            "INSERT INTO platform_tokens VALUES (?, ?, ?, ?, ?)",
            (token, customer_id, pm_token, instrument, time.time()),
        )
        self.db.commit()
        return token

    def resolve_platform_token(self, token: str) -> str | None:
        row = self.db.execute(
            "SELECT bt_payment_method_token FROM platform_tokens WHERE platform_token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def log_audit(self, saga_ref: str, result, decisions) -> None:
        self.db.execute(
            "INSERT INTO audit_log (saga_ref, recommender, prompt, response, decisions, error, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                saga_ref,
                result.recommender,
                result.prompt,
                result.raw_response,
                # Labels and actions only; real IDs stay out of the log as well.
                json.dumps([{**asdict(d), "txn_id": None} for d in decisions], default=str),
                result.error,
                time.time(),
            ),
        )
        for d in decisions:
            if d.final.value == "escalate":
                self.db.execute(
                    "INSERT INTO escalations (saga_ref, txn_ref, txn_id, reason, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (saga_ref, d.txn_ref, d.txn_id, d.blocked_by or result.error or "model_escalated", time.time()),
                )
        self.db.commit()

    def audit_records(self, saga_ref: str) -> list[dict]:
        rows = self.db.execute("SELECT * FROM audit_log WHERE saga_ref = ? ORDER BY id", (saga_ref,))
        return [dict(r) for r in rows]

    def open_escalations(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM escalations WHERE status = 'open' ORDER BY id")
        return [dict(r) for r in rows]
