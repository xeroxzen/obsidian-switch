"""Integration review checklist and passive email-spoofing checks.

The checklist items are things to *check* in an integration review. They are not
observations about any named organisation. Email posture comes from spoofscore, which
reads public DNS only.
"""

from __future__ import annotations

from dataclasses import dataclass

from spoofscore import Assessment, DomainNotFound, LookupFailed, check_domain


@dataclass(frozen=True)
class ChecklistItem:
    item_id: str
    risk_rating: str  # CRITICAL, HIGH, MEDIUM
    area: str
    title: str
    what_to_check: str
    fix: str


def integration_review_checklist() -> list[ChecklistItem]:
    return [
        ChecklistItem(
            "CHK-01", "CRITICAL", "Payment verification",
            "Fulfilment checks more than the result code",
            "Does the handler compare currency, amount and merchantTransactionId from the "
            "payment status with the order record, or only result.code?",
            "Fulfil only when code, currency, amount and order reference all match "
            "(oppwa_guard.verify_payment).",
        ),
        ChecklistItem(
            "CHK-02", "CRITICAL", "Return URL handling",
            "Status is fetched for the stored checkout id",
            "Is the status request built from resourcePath/id in the browser's return URL?",
            "Build the path from the checkout id saved when the checkout was created.",
        ),
        ChecklistItem(
            "CHK-03", "HIGH", "Notifications",
            "Each payment is credited exactly once",
            "Can a retried notification, or the redirect and the webhook arriving together, "
            "credit the same payment twice?",
            "Claim the payment id with a unique constraint inside the crediting transaction.",
        ),
        ChecklistItem(
            "CHK-04", "HIGH", "Secrets",
            "Gateway credentials are not in source control",
            "Search the organisation's own repositories and API workspaces for entityId, "
            "bearer tokens and webhook keys.",
            "Rotate anything found; add secret scanning to CI.",
        ),
        ChecklistItem(
            "CHK-05", "HIGH", "Email",
            "Payment and dispute email can't be forged",
            "Does the domain publish an enforcing DMARC policy (p=reject or p=quarantine)?",
            "Run spoofscore; move from p=none to p=reject once reports are clean.",
        ),
        ChecklistItem(
            "CHK-06", "MEDIUM", "Production config",
            "Production never accepts test-mode results",
            "Would the live handler fulfil on 000.100.110 (integrator test mode)?",
            "Treat test-mode codes in production as a misconfiguration alarm.",
        ),
        ChecklistItem(
            "CHK-07", "MEDIUM", "Incident readiness",
            "Payment anomalies raise an alert, not just a 200 log line",
            "Would anyone notice an order credited twice or fulfilled at the wrong currency "
            "within a day? Under the Cyber and Data Protection Act, a breach affecting "
            "personal data must be reported to POTRAZ within 24 hours.",
            "Log verification failures as security events and alert on them.",
        ),
    ]


def mail_posture(domain: str) -> Assessment | str:
    """Return the assessment, or a short reason the domain couldn't be checked."""
    try:
        return check_domain(domain)
    except ValueError as exc:
        return str(exc)
    except DomainNotFound:
        return "domain does not exist"
    except LookupFailed:
        return "DNS lookup failed; result unknown"
