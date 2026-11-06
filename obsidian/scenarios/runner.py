"""Runs the three clean-room scenarios against the in-process sandbox."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass

import httpx
from oppwa_guard.webhook import encrypt_notification_for_testing

from obsidian.config import CLEANROOM_WEBHOOK_KEY_HEX, SANDBOX_BASE_URL
from obsidian.sandbox.ledger import LEDGER
from obsidian.sandbox.mock_switch import app, payment_status_body


@dataclass
class ScenarioResult:
    """Summary of one scenario run."""

    scenario_id: str
    title: str
    mode: str
    order_id: str
    checkout_id: str
    switch_settled_display: str
    merchant_credited_display: str
    financial_impact_display: str
    compromised: bool
    summary: str


def _client() -> httpx.AsyncClient:
    """In-process ASGI client. No socket is opened."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=SANDBOX_BASE_URL)


def _mode() -> str:
    return "HARDENED" if LEDGER.hardened_mode else "VULNERABLE"


async def _open_checkout(
    client: httpx.AsyncClient, order_id: str, amount: str, currency: str, invoice_usd: float, paid: bool
) -> str:
    resp = await client.post(
        "/v1/checkouts",
        json={
            "amount": amount,
            "currency": currency,
            "paymentType": "DB",
            "merchantTransactionId": order_id,
            "paid": paid,
        },
    )
    resp.raise_for_status()
    checkout_id = str(resp.json()["id"])
    order = await client.post(
        "/merchant/orders/create",
        json={"order_id": order_id, "invoice_amount_usd": invoice_usd, "checkout_id": checkout_id},
    )
    order.raise_for_status()
    return checkout_id


async def run_scenario_01_currency_swap() -> ScenarioResult:
    """SCN-01: a USD 1,000 order paid through a checkout the shopper opened in ZWG."""
    order_id = f"ORD-USD-{uuid.uuid4().hex[:4].upper()}"
    invoice_usd = 1000.00
    async with _client() as client:
        checkout_id = await _open_checkout(client, order_id, "1000.00", "ZWG", invoice_usd, paid=True)
        resp = await client.post(
            "/merchant/checkout/verify-currency",
            json={"order_id": order_id, "checkout_id": checkout_id},
        )
        resp.raise_for_status()
        data = resp.json()
    settled_usd = LEDGER.switch_settlements[checkout_id].settled_usd_equiv
    settled = f"1,000.00 ZWG (${settled_usd:,.2f} USD)"
    base = {
        "scenario_id": "SCN-01",
        "title": "Currency swap (USD order, ZWG payment)",
        "mode": _mode(),
        "order_id": order_id,
        "checkout_id": checkout_id,
        "switch_settled_display": settled,
    }
    if data["outcome"] == "VULNERABLE_FULFILLED":
        return ScenarioResult(
            **base,
            merchant_credited_display=f"${invoice_usd:,.2f} USD (FULFILLED)",
            financial_impact_display=f"-${data['net_loss_usd']:,.2f} USD LOSS",
            compromised=True,
            summary=(
                f"Merchant checked result.code only. ${invoice_usd:,.2f} USD of goods released "
                f"for {settled}."
            ),
        )
    return ScenarioResult(
        **base,
        merchant_credited_display="$0.00 USD (HELD)",
        financial_impact_display=f"+${data['prevented_loss_usd']:,.2f} USD LOSS PREVENTED",
        compromised=False,
        summary="verify_payment() compared currency and amount with the order: ZWG != USD.",
    )


async def run_scenario_02_webhook_race(concurrency: int = 12) -> ScenarioResult:
    """SCN-02: one USD 250 payment notification delivered `concurrency` times at once."""
    assert 1 < concurrency <= 64, "concurrency must be a small burst"
    order_id = f"ORD-RACE-{uuid.uuid4().hex[:4].upper()}"
    deposit_usd = 250.00
    async with _client() as client:
        checkout_id = await _open_checkout(client, order_id, "250.00", "USD", deposit_usd, paid=True)
        rec = LEDGER.switch_settlements[checkout_id]
        sealed = encrypt_notification_for_testing(
            CLEANROOM_WEBHOOK_KEY_HEX, {"type": "PAYMENT", "payload": payment_status_body(rec)}
        )
        headers = {"X-Initialization-Vector": sealed["iv"], "X-Authentication-Tag": sealed["tag"]}
        responses = await asyncio.gather(
            *(
                client.post(
                    "/merchant/webhooks/payment-notification", content=sealed["body"], headers=headers
                )
                for _ in range(concurrency)
            )
        )
    for r in responses:
        r.raise_for_status()
    order = LEDGER.merchant_orders[order_id]
    credited = order.credited_usd_total
    settled = f"${deposit_usd:,.2f} USD (1 payment)"
    base = {
        "scenario_id": "SCN-02",
        "title": f"Duplicate notifications ({concurrency} at once)",
        "mode": _mode(),
        "order_id": order_id,
        "checkout_id": checkout_id,
        "switch_settled_display": settled,
    }
    if order.fulfilled_count > 1:
        return ScenarioResult(
            **base,
            merchant_credited_display=f"${credited:,.2f} USD ({order.fulfilled_count}x CREDITED)",
            financial_impact_display=f"-${credited - deposit_usd:,.2f} USD OVER-CREDITED",
            compromised=True,
            summary=(
                f"{concurrency} deliveries passed the 'already processed?' check before any of "
                f"them recorded the payment. One payment credited {order.fulfilled_count} times."
            ),
        )
    return ScenarioResult(
        **base,
        merchant_credited_display=f"${credited:,.2f} USD (1x)",
        financial_impact_display=f"+${(concurrency - 1) * deposit_usd:,.2f} USD DUPLICATES BLOCKED",
        compromised=False,
        summary=(
            f"claim_payment() uses a primary-key insert in the crediting transaction: "
            f"1 delivery credited, {concurrency - 1} ignored."
        ),
    )


async def run_scenario_03_resource_path_spoof() -> ScenarioResult:
    """SCN-03: an unpaid USD 1,500 order, and the shopper edits resourcePath on the return URL."""
    order_id = f"ORD-PATH-{uuid.uuid4().hex[:4].upper()}"
    invoice_usd = 1500.00
    tampered_path = "/v1/attacker-mock-paid"
    async with _client() as client:
        checkout_id = await _open_checkout(client, order_id, "1500.00", "USD", invoice_usd, paid=False)
        resp = await client.get(
            "/merchant/checkout/shopper-return",
            params={"order_id": order_id, "resourcePath": tampered_path},
        )
        resp.raise_for_status()
        data = resp.json()
    base = {
        "scenario_id": "SCN-03",
        "title": "Edited resourcePath on return URL",
        "mode": _mode(),
        "order_id": order_id,
        "checkout_id": checkout_id,
        "switch_settled_display": "$0.00 USD (UNPAID, 000.200.000 PENDING)",
    }
    if data["outcome"] == "VULNERABLE_SPOOF_ACCEPTED":
        return ScenarioResult(
            **base,
            merchant_credited_display=f"${invoice_usd:,.2f} USD (FULFILLED)",
            financial_impact_display=f"-${invoice_usd:,.2f} USD UNPAID ORDER SHIPPED",
            compromised=True,
            summary=(
                f"Merchant fetched payment status from the browser-supplied path '{tampered_path}' "
                "and believed the answer."
            ),
        )
    return ScenarioResult(
        **base,
        merchant_credited_display="$0.00 USD (HELD)",
        financial_impact_display=f"+${invoice_usd:,.2f} USD LOSS PREVENTED",
        compromised=False,
        summary=(
            "Status fetched for the checkout id stored server-side (still pending); the edited "
            "path was logged as tampering."
        ),
    )
