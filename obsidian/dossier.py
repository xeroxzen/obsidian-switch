"""Writes a printable HTML report: email posture, vulnerable run, hardened run, checklist."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from obsidian.intel.passive_osint import integration_review_checklist, mail_posture
from obsidian.sandbox.ledger import LEDGER
from obsidian.scenarios.runner import (
    ScenarioResult,
    run_scenario_01_currency_swap,
    run_scenario_02_webhook_race,
    run_scenario_03_resource_path_spoof,
)


async def _run_all() -> list[ScenarioResult]:
    return [
        await run_scenario_01_currency_swap(),
        await run_scenario_02_webhook_race(concurrency=12),
        await run_scenario_03_resource_path_spoof(),
    ]


def _mail_rows(domains: list[str]) -> str:
    rows = ""
    for domain in domains:
        result = mail_posture(domain)
        if isinstance(result, str):
            rows += (
                f"<tr><td class='mono bold'>{escape(domain)}</td><td class='muted'>UNKNOWN</td>"
                f"<td></td><td>{escape(result)}</td></tr>"
            )
            continue
        css = {"exposed": "crimson", "partial": "amber", "protected": "emerald"}[result.verdict]
        findings = "<br>".join(
            f"<strong>{escape(f.severity)}</strong>: {escape(f.title)}<br>"
            f"<span class='muted'>Fix: {escape(f.fix)}</span>"
            for f in result.findings
        ) or "None"
        rows += (
            f"<tr><td class='mono bold'>{escape(domain)}</td>"
            f"<td class='{css} bold'>{result.verdict.upper()}</td>"
            f"<td class='mono cyan'>{escape(result.dmarc_record or 'none in effect')}</td><td>{findings}</td></tr>"
        )
    return rows


def _scenario_rows(results: list[ScenarioResult], css: str) -> str:
    return "".join(
        f"<tr><td class='mono {css}'>{escape(r.scenario_id)}</td>"
        f"<td><strong>{escape(r.title)}</strong><br><span class='muted'>{escape(r.summary)}</span></td>"
        f"<td class='mono cyan'>{escape(r.switch_settled_display)}</td>"
        f"<td class='mono {css}'>{escape(r.merchant_credited_display)}</td>"
        f"<td class='mono {css} bold'>{escape(r.financial_impact_display)}</td></tr>"
        for r in results
    )


def _incident_rows() -> str:
    return "".join(
        f"<tr><td class='mono muted'>#{f.seq_id:03d}<br>{escape(f.timestamp)}</td>"
        f"<td><span class='badge-crimson'>{escape(f.event_code)}</span></td>"
        f"<td>{escape(f.detail)}</td>"
        f"<td class='mono cyan'>{escape(f.prev_hash)} &rarr; {escape(f.entry_hash)}</td></tr>"
        for f in LEDGER.forensic_logs
        if f.severity == "CRITICAL"
    )


def _checklist_rows() -> str:
    return "".join(
        f"<tr><td class='mono amber'>{escape(i.item_id)}<br><strong>{escape(i.risk_rating)}</strong></td>"
        f"<td class='cyan'>{escape(i.area)}</td>"
        f"<td><strong>{escape(i.title)}</strong><br><span class='muted'>{escape(i.what_to_check)}</span></td>"
        f"<td class='emerald'>{escape(i.fix)}</td></tr>"
        for i in integration_review_checklist()
    )


async def generate_executive_html_dossier(output_path: Path, domains: list[str]) -> Path:
    """Run vulnerable and hardened passes and write a printable HTML report.

    ``domains`` is optional; include only domains whose owner you are reporting to.
    """
    LEDGER.reset()
    LEDGER.hardened_mode = False
    vuln_results = await _run_all()
    vuln_divergence = LEDGER.net_divergence_usd
    incident_rows = _incident_rows()

    LEDGER.reset()
    LEDGER.hardened_mode = True
    hard_results = await _run_all()
    prevented = LEDGER.blocked_attack_value_usd
    LEDGER.hardened_mode = False

    mail_section = ""
    if domains:
        mail_section = f"""
<h2>Email spoofing posture (public DNS)</h2>
<table><thead><tr>
<th>Domain</th><th>Verdict</th><th>DMARC in effect</th><th>Findings &amp; fixes</th>
</tr></thead>
<tbody>{_mail_rows(domains)}</tbody></table>"""

    html = REPORT_TEMPLATE.format(
        style=STYLE,
        ts_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        vuln_divergence=f"{vuln_divergence:,.2f}",
        prevented=f"{prevented:,.2f}",
        mail_section=mail_section,
        vuln_rows=_scenario_rows(vuln_results, "crimson"),
        incident_rows=incident_rows,
        hard_rows=_scenario_rows(hard_results, "emerald"),
        checklist_rows=_checklist_rows(),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Payment Integration Risk Report</title>
{style}
</head>
<body>

<div class="banner">
    <div>
        <h1>Payment integration risk: what a typical merchant integration loses, and the fix</h1>
        <div class="muted">Generated {ts_utc}</div>
    </div>
</div>

<div class="attestation">
    <strong>Method.</strong> Sections 2 to 4 are a simulation: a mock OPPWA-style gateway and
    merchant running in one process on the author's machine, modelled on the public OPPWA API.
    They show how each class of bug loses money. They are not findings about any organisation's
    systems. The email section, where present, uses public DNS records only.
</div>

<div class="kpi-grid">
    <div class="kpi-card">
        <div class="kpi-label">Lost by the unprotected merchant (3 scenarios)</div>
        <div class="kpi-val crimson">${vuln_divergence} USD</div>
        <div class="muted">Every request logged as HTTP 200</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">Prevented with the fixes</div>
        <div class="kpi-val emerald">${prevented} USD</div>
        <div class="muted">Same attacks, merchant using oppwa-guard</div>
    </div>
</div>
{mail_section}

<h2>2. Unprotected merchant</h2>
<table><thead><tr>
<th>ID</th><th>Scenario</th><th>Gateway settled</th><th>Merchant released</th><th>Impact</th>
</tr></thead>
<tbody>{vuln_rows}</tbody></table>

<h2>3. What the audit log recorded while the app log said HTTP 200</h2>
<p class="muted">Each entry includes the hash of the one before, so edits or deletions are
detectable. Whether an incident is reportable depends on what it touched: under the Cyber and
Data Protection Act, a breach affecting personal data must be reported to POTRAZ within 24 hours.</p>
<table><thead><tr><th>Seq / UTC</th><th>Event</th><th>Detail</th><th>Chain</th></tr></thead>
<tbody>{incident_rows}</tbody></table>

<h2>4. Same attacks, merchant using the fixes</h2>
<table><thead><tr>
<th>ID</th><th>Scenario</th><th>Gateway settled</th><th>Merchant released</th><th>Outcome</th>
</tr></thead>
<tbody>{hard_rows}</tbody></table>

<h2>5. Integration review checklist</h2>
<table><thead><tr><th>ID / Risk</th><th>Area</th><th>Check</th><th>Fix</th></tr></thead>
<tbody>{checklist_rows}</tbody></table>

<h2>6. The fix in code</h2>
<pre>
from oppwa_guard import ExpectedPayment, claim_payment, status_path, verify_payment

# 1. Fetch status for the checkout id YOU stored, never the browser's resourcePath   (SCN-03)
response = gateway.get(status_path(order.checkout_id), params={{"entityId": ENTITY_ID}})

# 2. Accept only if code, currency, amount and order reference all match             (SCN-01)
verdict = verify_payment(ExpectedPayment(order.id, order.amount, order.currency), response.json())

# 3. Credit inside one transaction, guarded by a unique constraint                   (SCN-02)
if verdict.accepted:
    with conn:
        if claim_payment(conn, verdict.payment_id):
            credit_order(conn, order.id)
</pre>

</body>
</html>
"""


STYLE = """<style>
    :root {
        --bg: #080a0e;
        --panel: #0f131a;
        --border: #1f2937;
        --amber: #ffb000;
        --crimson: #ff2a54;
        --emerald: #00ff9d;
        --cyan: #00d4ff;
        --text: #e6edf3;
        --muted: #8892b0;
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        padding: 32px;
        background: var(--bg);
        color: var(--text);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        line-height: 1.5;
    }
    .banner {
        background: #141923;
        border: 2px solid var(--amber);
        padding: 16px 24px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .banner h1 {
        margin: 0;
        font-size: 20px;
        letter-spacing: 1.5px;
        color: var(--amber);
        font-family: "SFMono-Regular", Consolas, monospace;
    }
    .attestation {
        background: #0d1520;
        border-left: 4px solid var(--cyan);
        padding: 12px 18px;
        margin-bottom: 24px;
        font-size: 13px;
        color: var(--text);
    }
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-bottom: 28px;
    }
    .kpi-card {
        background: var(--panel);
        border: 1px solid var(--border);
        padding: 16px;
    }
    .kpi-label {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--muted);
    }
    .kpi-val {
        font-size: 24px;
        font-weight: 700;
        margin-top: 6px;
        font-family: "SFMono-Regular", Consolas, monospace;
    }
    h2 {
        font-size: 15px;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        color: var(--cyan);
        border-bottom: 1px solid var(--border);
        padding-bottom: 8px;
        margin-top: 32px;
        font-family: "SFMono-Regular", Consolas, monospace;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 24px;
        background: var(--panel);
        font-size: 13px;
    }
    th, td {
        border: 1px solid var(--border);
        padding: 10px 12px;
        text-align: left;
        vertical-align: top;
    }
    th {
        background: #141b26;
        color: var(--amber);
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        text-transform: uppercase;
    }
    .mono { font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; }
    .bold { font-weight: 700; }
    .amber { color: var(--amber); }
    .crimson { color: var(--crimson); }
    .emerald { color: var(--emerald); }
    .cyan { color: var(--cyan); }
    .muted { color: var(--muted); font-size: 12px; }
    .badge-crimson {
        background: #2a0a12;
        color: var(--crimson);
        border: 1px solid var(--crimson);
        padding: 2px 6px;
        font-family: monospace;
        font-size: 11px;
        font-weight: 700;
    }
    pre {
        background: #06080c;
        border: 1px solid var(--border);
        padding: 16px;
        overflow-x: auto;
        font-family: "SFMono-Regular", Consolas, monospace;
        font-size: 12px;
        color: var(--emerald);
    }
    @media print {
        body { background: #ffffff; color: #111111; padding: 12px; }
        .kpi-card, table, .banner, .attestation, pre { background: #ffffff; border-color: #cccccc; color: #111111; }
        th { background: #f0f0f0; color: #111111; }
    }
</style>"""
