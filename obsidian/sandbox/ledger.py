"""Dual-ledger state and hash-chained audit log for the clean-room simulation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

from oppwa_guard import ensure_schema

from obsidian.config import to_usd_equivalent


@dataclass
class SwitchSettlementRecord:
    """Authoritative payment record held by the mock OPPWA-style gateway."""

    checkout_id: str
    payment_id: str
    entity_id: str
    merchant_transaction_id: str
    settled_amount: float
    settled_currency: str
    settled_usd_equiv: float
    status_code: str
    status_description: str
    paid: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    )


@dataclass
class MerchantOrderRecord:
    """Downstream Merchant / Aggregator order and wallet fulfillment state."""

    order_id: str
    checkout_id: str
    invoice_amount_usd: float
    invoice_currency: str = "USD"
    fulfilled_count: int = 0
    credited_usd_total: float = 0.0
    status: str = "PENDING"


@dataclass
class NaiveLogEntry:
    """Standard unhardened web application log line (shows what naive logs miss)."""

    timestamp: str
    http_status: int
    endpoint: str
    message: str


@dataclass
class ForensicLogEntry:
    """Tamper-evident audit event; each entry hashes the previous one."""

    seq_id: int
    timestamp: str
    severity: str  # NOMINAL, WARNING, CRITICAL, BLOCKED
    event_code: str
    vector: str
    detail: str
    incident: bool
    prev_hash: str
    entry_hash: str


class CleanRoomLedger:
    """Central state store for the 127.0.0.1 clean-room simulation."""

    def __init__(self) -> None:
        self.hardened_mode: bool = False
        self.switch_settlements: dict[str, SwitchSettlementRecord] = {}
        self.merchant_orders: dict[str, MerchantOrderRecord] = {}
        # Vulnerable merchant: an in-memory set checked and updated non-atomically.
        self.processed_idempotency_keys: set[str] = set()
        # Hardened merchant: a primary-key constraint (oppwa_guard.claim_payment).
        self.payments_db = sqlite3.connect(":memory:")
        ensure_schema(self.payments_db)

        self.naive_logs: list[NaiveLogEntry] = []
        self.forensic_logs: list[ForensicLogEntry] = []
        self._last_hash: str = "0" * 64
        self._seq_counter: int = 0

        # Cumulative financial telemetry
        self.total_switch_settled_usd: float = 0.0
        self.total_merchant_credited_usd: float = 0.0
        self.blocked_attack_value_usd: float = 0.0
        self.open_incidents: int = 0

        self.record_forensic(
            severity="NOMINAL",
            event_code="SANDBOX_INITIALIZED",
            vector="LOCAL_LOOPBACK_127.0.0.1",
            detail="OBSIDIAN-SWITCH Clean-Room Engine initialized. Zero external packets permitted.",
            incident=False,
        )

    def reset(self) -> None:
        """Reset all ledgers and logs while preserving current security posture mode."""
        mode = self.hardened_mode
        self.payments_db.close()
        self.__init__()  # type: ignore[misc]
        self.hardened_mode = mode
        mode_label = "HARDENED (ENFORCED)" if mode else "VULNERABLE (UNPATCHED)"
        self.record_forensic(
            severity="NOMINAL",
            event_code="LEDGER_RESET",
            vector="SYSTEM_CONTROL",
            detail=f"Ledgers purged. Active Merchant Guardrail Mode: {mode_label}",
            incident=False,
        )

    def toggle_hardened_mode(self) -> bool:
        """Switch between VULNERABLE and HARDENED downstream merchant implementation."""
        self.hardened_mode = not self.hardened_mode
        mode_label = "HARDENED [GUARDRAILS ACTIVE]" if self.hardened_mode else "VULNERABLE [BASELINE]"
        self.record_naive(
            200,
            "/admin/config",
            f"Merchant security configuration switched to {mode_label}",
        )
        self.record_forensic(
            severity="NOMINAL" if self.hardened_mode else "WARNING",
            event_code="GUARDRAIL_POSTURE_CHANGED",
            vector="CONFIG_TOGGLE",
            detail=f"Downstream merchant verification posture set to {mode_label}",
            incident=False,
        )
        return self.hardened_mode

    @property
    def net_divergence_usd(self) -> float:
        """Difference between what the Merchant credited/shipped and what the Switch settled."""
        return round(self.total_merchant_credited_usd - self.total_switch_settled_usd, 2)

    def record_naive(self, http_status: int, endpoint: str, message: str) -> NaiveLogEntry:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        entry = NaiveLogEntry(
            timestamp=ts,
            http_status=http_status,
            endpoint=endpoint,
            message=message,
        )
        self.naive_logs.append(entry)
        return entry

    def record_forensic(
        self,
        severity: str,
        event_code: str,
        vector: str,
        detail: str,
        incident: bool = False,
    ) -> ForensicLogEntry:
        self._seq_counter += 1
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        payload = json.dumps(
            {
                "seq": self._seq_counter,
                "ts": ts,
                "sev": severity,
                "code": event_code,
                "vec": vector,
                "detail": detail,
                "prev": self._last_hash,
            },
            sort_keys=True,
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entry = ForensicLogEntry(
            seq_id=self._seq_counter,
            timestamp=ts,
            severity=severity,
            event_code=event_code,
            vector=vector,
            detail=detail,
            incident=incident,
            prev_hash=self._last_hash[:12],
            entry_hash=digest[:16],
        )
        self._last_hash = digest
        if incident:
            self.open_incidents += 1
        self.forensic_logs.append(entry)
        return entry

    def register_switch_checkout(
        self,
        checkout_id: str,
        payment_id: str,
        entity_id: str,
        merchant_transaction_id: str,
        settled_amount: float,
        settled_currency: str,
        paid: bool = True,
    ) -> SwitchSettlementRecord:
        usd_eq = to_usd_equivalent(settled_amount, settled_currency) if paid else 0.0
        rec = SwitchSettlementRecord(
            checkout_id=checkout_id,
            payment_id=payment_id,
            entity_id=entity_id,
            merchant_transaction_id=merchant_transaction_id,
            settled_amount=settled_amount,
            settled_currency=settled_currency.upper(),
            settled_usd_equiv=usd_eq,
            status_code="000.000.000" if paid else "000.200.000",
            status_description="Transaction succeeded" if paid else "transaction pending",
            paid=paid,
        )
        self.switch_settlements[checkout_id] = rec
        if paid:
            self.total_switch_settled_usd = round(self.total_switch_settled_usd + usd_eq, 2)
        return rec


# Singleton clean-room ledger instance
LEDGER = CleanRoomLedger()

