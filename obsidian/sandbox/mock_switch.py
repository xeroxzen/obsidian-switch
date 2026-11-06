"""Local clean-room OPPWA-style gateway and a merchant that can run vulnerable or hardened.

Runs in-process over an ASGI transport. Nothing here opens a socket or contacts a real
gateway. The gateway side follows the public OPPWA API shape: ``POST /v1/checkouts``,
``GET /v1/checkouts/{id}/payment``, and AES-256-GCM encrypted webhook notifications.
"""

from __future__ import annotations

import asyncio
import uuid
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Request
from oppwa_guard import (
    ExpectedPayment,
    NotificationError,
    Verdict,
    claim_payment,
    decrypt_notification,
    payment_payload,
    resource_path_matches,
    verify_payment,
)
from pydantic import BaseModel

from obsidian.config import CLEANROOM_MERCHANT_ENTITY_ID, CLEANROOM_WEBHOOK_KEY_HEX
from obsidian.sandbox.ledger import LEDGER, MerchantOrderRecord, SwitchSettlementRecord

app = FastAPI(
    title="OBSIDIAN-SWITCH clean-room sandbox",
    description="In-process payment gateway and merchant integration simulator.",
    version="1.1.0",
)

VULNERABLE_SUCCESS_CODE = "000.000.000"


class CheckoutCreateRequest(BaseModel):
    entityId: str = CLEANROOM_MERCHANT_ENTITY_ID
    amount: str
    currency: str = "USD"
    paymentType: str = "DB"
    merchantTransactionId: str
    paid: bool = True  # simulation control: whether the shopper completes payment


class OrderCreateRequest(BaseModel):
    order_id: str
    invoice_amount_usd: float
    checkout_id: str


class CurrencyVerifyRequest(BaseModel):
    order_id: str
    checkout_id: str


# ============================================================================
# GATEWAY (authoritative)
# ============================================================================


def payment_status_body(rec: SwitchSettlementRecord) -> dict[str, object]:
    return {
        "id": rec.payment_id,
        "paymentType": "DB",
        "amount": f"{rec.settled_amount:.2f}",
        "currency": rec.settled_currency,
        "merchantTransactionId": rec.merchant_transaction_id,
        "ndc": rec.checkout_id,
        "result": {"code": rec.status_code, "description": rec.status_description},
    }


@app.post("/v1/checkouts")
async def create_checkout(req: CheckoutCreateRequest) -> dict[str, object]:
    checkout_id = f"{uuid.uuid4().hex[:24].upper()}.sbx01"
    rec = LEDGER.register_switch_checkout(
        checkout_id=checkout_id,
        payment_id=uuid.uuid4().hex,
        entity_id=req.entityId,
        merchant_transaction_id=req.merchantTransactionId,
        settled_amount=float(req.amount),
        settled_currency=req.currency,
        paid=req.paid,
    )
    return {
        "id": rec.checkout_id,
        "result": {"code": "000.200.100", "description": "successfully created checkout"},
    }


@app.get("/v1/checkouts/{checkout_id}/payment")
async def get_payment_status(checkout_id: str) -> dict[str, object]:
    rec = LEDGER.switch_settlements.get(checkout_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="checkout not found")
    return payment_status_body(rec)


@app.get("/v1/attacker-mock-paid")
async def attacker_controlled_status() -> dict[str, object]:
    """Stands in for a URL the shopper chose. It returns whatever the attacker wants."""
    return {
        "id": "ATTACKER0000000000000000000000000",
        "paymentType": "DB",
        "amount": "1500.00",
        "currency": "USD",
        "result": {"code": "000.000.000", "description": "Transaction succeeded"},
    }


# ============================================================================
# MERCHANT (toggleable vulnerable <-> hardened)
# ============================================================================


def _expected(order: MerchantOrderRecord) -> ExpectedPayment:
    return ExpectedPayment(
        merchant_transaction_id=order.order_id,
        amount=Decimal(f"{order.invoice_amount_usd:.2f}"),
        currency=order.invoice_currency,
    )


def _credit(order: MerchantOrderRecord, amount_usd: float) -> None:
    order.fulfilled_count += 1
    order.credited_usd_total = round(order.credited_usd_total + amount_usd, 2)
    LEDGER.total_merchant_credited_usd = round(LEDGER.total_merchant_credited_usd + amount_usd, 2)


def _block(
    order: MerchantOrderRecord, prevented_usd: float, http: int, endpoint: str, event: str, verdict_text: str
) -> None:
    LEDGER.blocked_attack_value_usd = round(LEDGER.blocked_attack_value_usd + prevented_usd, 2)
    LEDGER.record_naive(http, endpoint, f"Order {order.order_id} not fulfilled: {verdict_text}")
    LEDGER.record_forensic(
        severity="BLOCKED",
        event_code=event,
        vector="OPPWA_GUARD_VERIFY_PAYMENT",
        detail=f"Order {order.order_id} (${order.invoice_amount_usd:,.2f} USD) held: {verdict_text}.",
    )


@app.post("/merchant/orders/create")
async def create_merchant_order(req: OrderCreateRequest) -> dict[str, str]:
    order = MerchantOrderRecord(
        order_id=req.order_id,
        checkout_id=req.checkout_id,
        invoice_amount_usd=req.invoice_amount_usd,
        invoice_currency="USD",
    )
    LEDGER.merchant_orders[req.order_id] = order
    return {"status": "CREATED", "order_id": order.order_id}


@app.post("/merchant/checkout/verify-currency")
async def merchant_verify_payment(req: CurrencyVerifyRequest) -> dict[str, object]:
    """SCN-01: the shopper's checkout was created in ZWG for an order priced in USD."""
    order = LEDGER.merchant_orders.get(req.order_id)
    switch_rec = LEDGER.switch_settlements.get(req.checkout_id)
    if order is None or switch_rec is None:
        raise HTTPException(status_code=404, detail="order or checkout missing")
    status = payment_status_body(switch_rec)

    if not LEDGER.hardened_mode:
        if switch_rec.status_code != VULNERABLE_SUCCESS_CODE:
            return {"outcome": "NOT_PAID", "order_id": order.order_id}
        _credit(order, order.invoice_amount_usd)
        order.status = "PAID_FULFILLED"
        loss_usd = round(order.invoice_amount_usd - switch_rec.settled_usd_equiv, 2)
        LEDGER.record_naive(
            200,
            "/merchant/checkout/verify-currency",
            f"Order {order.order_id} PAID (code={switch_rec.status_code}). Dispatching goods.",
        )
        LEDGER.record_forensic(
            severity="CRITICAL",
            event_code="CURRENCY_MISMATCH_FULFILLED",
            vector="RESULT_CODE_ONLY_CHECK",
            detail=(
                f"Order {order.order_id} priced at ${order.invoice_amount_usd:,.2f} USD fulfilled "
                f"against {switch_rec.settled_amount:,.2f} {switch_rec.settled_currency} "
                f"(${switch_rec.settled_usd_equiv:,.2f} USD). Loss: ${loss_usd:,.2f} USD."
            ),
            incident=True,
        )
        return {
            "outcome": "VULNERABLE_FULFILLED",
            "switch_settled_usd_equiv": switch_rec.settled_usd_equiv,
            "net_loss_usd": loss_usd,
        }

    verdict = verify_payment(_expected(order), status)
    if not verdict.accepted:
        shortfall = round(order.invoice_amount_usd - switch_rec.settled_usd_equiv, 2)
        _block(order, shortfall, 403, "/merchant/checkout/verify-currency", "PAYMENT_MISMATCH_BLOCKED", verdict.detail)
        return {
            "outcome": "HARDENED_BLOCKED",
            "reason": verdict.reason.value if verdict.reason else "",
            "prevented_loss_usd": shortfall,
        }
    _credit(order, order.invoice_amount_usd)
    order.status = "PAID_FULFILLED"
    return {"outcome": "VERIFIED_OK"}


@app.post("/merchant/webhooks/payment-notification")
async def merchant_payment_notification(request: Request) -> dict[str, object]:
    """SCN-02: the same payment notification arrives several times at once."""
    body = await request.body()
    try:
        notification = decrypt_notification(
            CLEANROOM_WEBHOOK_KEY_HEX,
            request.headers.get("X-Initialization-Vector", ""),
            request.headers.get("X-Authentication-Tag", ""),
            body,
        )
        payment = payment_payload(notification)
    except NotificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    order_id = payment.get("merchantTransactionId")
    order = LEDGER.merchant_orders.get(order_id) if isinstance(order_id, str) else None
    payment_id = payment.get("id")
    if order is None or not isinstance(payment_id, str):
        raise HTTPException(status_code=404, detail="unknown order")
    amount = float(str(payment.get("amount", "0")))

    if not LEDGER.hardened_mode:
        return await _vulnerable_credit(order, payment_id, amount)

    verdict = verify_payment(_expected(order), payment)
    if not verdict.accepted:
        _block(order, amount, 200, "/merchant/webhooks/payment-notification", "NOTIFICATION_MISMATCH", verdict.detail)
        return {"outcome": "HARDENED_REJECTED"}
    return _hardened_credit(order, verdict, amount)


async def _vulnerable_credit(order: MerchantOrderRecord, payment_id: str, amount: float) -> dict[str, object]:
    """Check-then-act on an in-memory set, with an await (a DB round trip) in between."""
    if payment_id in LEDGER.processed_idempotency_keys:
        return {"outcome": "DUPLICATE_IGNORED"}
    await asyncio.sleep(0.015)  # the read-then-write gap: a DB query, an HTTP call, a log flush
    LEDGER.processed_idempotency_keys.add(payment_id)
    _credit(order, amount)
    order.status = f"CREDITED_x{order.fulfilled_count}"
    LEDGER.record_naive(
        200,
        "/merchant/webhooks/payment-notification",
        f"Payment {payment_id[:12]} processed. Wallet credited +${amount:,.2f} USD.",
    )
    if order.fulfilled_count > 1:
        LEDGER.record_forensic(
            severity="CRITICAL",
            event_code="DUPLICATE_NOTIFICATION_CREDITED",
            vector="NON_ATOMIC_IDEMPOTENCY_CHECK",
            detail=(
                f"Credit #{order.fulfilled_count} for payment {payment_id[:12]} on {order.order_id}. "
                f"Over-credited +${amount:,.2f} USD."
            ),
            incident=order.fulfilled_count == 2,
        )
    return {"outcome": "CREDITED", "execution_number": order.fulfilled_count}


def _hardened_credit(order: MerchantOrderRecord, verdict: Verdict, amount: float) -> dict[str, object]:
    assert verdict.payment_id is not None, "accepted verdicts always carry a payment id"
    with LEDGER.payments_db:
        if not claim_payment(LEDGER.payments_db, verdict.payment_id):
            LEDGER.blocked_attack_value_usd = round(LEDGER.blocked_attack_value_usd + amount, 2)
            LEDGER.record_naive(
                200,
                "/merchant/webhooks/payment-notification",
                f"Duplicate notification for payment {verdict.payment_id[:12]} ignored.",
            )
            LEDGER.record_forensic(
                severity="BLOCKED",
                event_code="DUPLICATE_NOTIFICATION_IGNORED",
                vector="UNIQUE_CONSTRAINT_CLAIM",
                detail=f"Payment {verdict.payment_id[:12]} already claimed. Prevented +${amount:,.2f} USD.",
            )
            return {"outcome": "HARDENED_DUPLICATE_IGNORED"}
        _credit(order, amount)
    order.status = "CREDITED_ONCE"
    LEDGER.record_naive(
        200,
        "/merchant/webhooks/payment-notification",
        f"Payment {verdict.payment_id[:12]} verified and credited once (+${amount:,.2f} USD).",
    )
    return {"outcome": "HARDENED_CREDITED_ONCE"}


@app.get("/merchant/checkout/shopper-return")
async def merchant_shopper_return(order_id: str, resourcePath: str) -> dict[str, object]:
    """SCN-03: the shopper edits resourcePath on the return URL of an unpaid checkout."""
    order = LEDGER.merchant_orders.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")

    if not LEDGER.hardened_mode:
        status = await _fetch_status_from_browser_path(resourcePath)
        result = status.get("result")
        code = result.get("code") if isinstance(result, dict) else None
        if code != VULNERABLE_SUCCESS_CODE:
            return {"outcome": "NOT_PAID"}
        _credit(order, order.invoice_amount_usd)
        order.status = "PAID_VIA_SPOOFED_PATH"
        LEDGER.record_naive(
            200,
            "/merchant/checkout/shopper-return",
            f"Shopper return verified via resourcePath={resourcePath} -> {code}. "
            f"Order {order.order_id} fulfilled.",
        )
        LEDGER.record_forensic(
            severity="CRITICAL",
            event_code="RESOURCE_PATH_BYPASS",
            vector="STATUS_FETCHED_FROM_BROWSER_PATH",
            detail=(
                f"Order {order.order_id} (${order.invoice_amount_usd:,.2f} USD) fulfilled via "
                f"resourcePath='{resourcePath}' while checkout {order.checkout_id} is unpaid."
            ),
            incident=True,
        )
        return {"outcome": "VULNERABLE_SPOOF_ACCEPTED"}

    if not resource_path_matches(resourcePath, order.checkout_id):
        LEDGER.record_forensic(
            severity="WARNING",
            event_code="RESOURCE_PATH_TAMPERING",
            vector="BROWSER_PATH_MISMATCH",
            detail=f"Order {order.order_id}: browser sent resourcePath='{resourcePath}'. Ignored.",
        )
    rec = LEDGER.switch_settlements[order.checkout_id]  # built from the stored id, never the URL
    verdict = verify_payment(_expected(order), payment_status_body(rec))
    if not verdict.accepted:
        _block(
            order,
            order.invoice_amount_usd,
            402,
            "/merchant/checkout/shopper-return",
            "UNPAID_ORDER_HELD",
            verdict.detail,
        )
        return {"outcome": "HARDENED_NOT_PAID", "prevented_loss_usd": order.invoice_amount_usd}
    _credit(order, order.invoice_amount_usd)
    return {"outcome": "HARDENED_VERIFIED_OK"}


async def _fetch_status_from_browser_path(resource_path: str) -> dict[str, object]:
    """The vulnerable pattern: GET whatever path the browser supplied."""
    if resource_path == "/v1/attacker-mock-paid":
        return await attacker_controlled_status()
    parts = resource_path.strip("/").split("/")
    if len(parts) == 4 and parts[0] == "v1" and parts[1] == "checkouts":
        return await get_payment_status(parts[2])
    return {}
