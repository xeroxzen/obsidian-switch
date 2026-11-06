"""Scripted terminal demo (--demo): checklist, vulnerable run, hardened run."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from obsidian.intel.passive_osint import integration_review_checklist
from obsidian.sandbox.ledger import LEDGER
from obsidian.scenarios.runner import (
    run_scenario_01_currency_swap,
    run_scenario_02_webhook_race,
    run_scenario_03_resource_path_spoof,
)

GOTHIC_BANNER = r"""[bold #ffb000]
  ██████╗ ██████╗ ███████╗██╗██████╗ ██╗ █████╗ ███╗   ██╗      ███████╗██╗    ██╗██╗████████╗ ██████╗██╗  ██╗
 ██╔═══██╗██╔══██╗██╔════╝██║██╔══██╗██║██╔══██╗████╗  ██║      ██╔════╝██║    ██║██║╚══██╔══╝██╔════╝██║  ██║
 ██║   ██║██████╔╝███████╗██║██║  ██║██║███████║██╔██╗ ██║█████╗███████╗██║ █╗ ██║██║   ██║   ██║     ███████║
 ██║   ██║██╔══██╗╚════██║██║██║  ██║██║██╔══██║██║╚██╗██║╚════╝╚════██║██║███╗██║██║   ██║   ██║     ██╔══██║
 ╚██████╔╝██████╔╝███████║██║██████╔╝██║██║  ██║██║ ╚████║      ███████║╚███╔███╔╝██║   ██║   ╚██████╗██║  ██║
  ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝      ╚══════╝ ╚══╝╚══╝ ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝[/]
[bold #00d4ff]  PAYMENT INTEGRATION CLEAN-ROOM SIMULATOR v1.1[/]
[bold #6c7a89]  IN-PROCESS SANDBOX // NO NETWORK TRAFFIC // MODELLED ON THE PUBLIC OPPWA API[/]
"""


async def run_gothic_cli_demo() -> None:
    """Execute the full executive demonstration across Vulnerable, Hardened, and OSINT modules."""
    console = Console()
    console.print(GOTHIC_BANNER)

    # =========================================================================
    # PHASE 1: INTEGRATION REVIEW CHECKLIST
    # =========================================================================
    osint_table = Table(
        title="[bold #ffb000]◈ PHASE I: WHAT A PAYMENT INTEGRATION REVIEW CHECKS[/]",
        box=box.HEAVY_EDGE,
        border_style="#1f2937",
        header_style="bold #00d4ff on #141b26",
        show_lines=True,
    )
    osint_table.add_column("ID", style="bold #ffb000", width=12)
    osint_table.add_column("RISK", width=10)
    osint_table.add_column("AREA", style="#00d4ff", width=20)
    osint_table.add_column("CHECK & FIX", width=68)

    for item in integration_review_checklist():
        risk_style = "bold #ff2a54" if item.risk_rating == "CRITICAL" else "bold #ffb000"
        osint_table.add_row(
            item.item_id,
            Text(item.risk_rating, style=risk_style),
            item.area,
            f"[bold #e6edf3]{item.title}[/]\n"
            f"[#8892b0]Check:[/] {item.what_to_check}\n"
            f"[#00ff9d]Fix:[/] {item.fix}",
        )
    console.print(osint_table)
    console.print()

    # =========================================================================
    # PHASE 2: CLEAN-ROOM SIMULATION — UNPATCHED / VULNERABLE DOWNSTREAM MODE
    # =========================================================================
    LEDGER.reset()
    LEDGER.hardened_mode = False

    r1_vuln = await run_scenario_01_currency_swap()
    r2_vuln = await run_scenario_02_webhook_race(concurrency=12)
    r3_vuln = await run_scenario_03_resource_path_spoof()

    vuln_table = Table(
        title="[bold #ff2a54]◈ PHASE II: CLEAN-ROOM SIMULATION — UNPATCHED DOWNSTREAM MERCHANT [VULNERABLE MODE][/]",
        box=box.HEAVY_EDGE,
        border_style="#ff2a54",
        header_style="bold #ffb000 on #1f1118",
        show_lines=True,
    )
    vuln_table.add_column("SCENARIO", style="bold #ffb000", width=10)
    vuln_table.add_column("ATTACK VECTOR", style="bold #e6edf3", width=28)
    vuln_table.add_column("GATEWAY SETTLED (TRUTH)", style="#00d4ff", width=24)
    vuln_table.add_column("MERCHANT FULFILLED", style="bold #ff2a54", width=24)
    vuln_table.add_column("SETTLEMENT DIVERGENCE", style="bold #ff2a54", width=24)

    for r in (r1_vuln, r2_vuln, r3_vuln):
        vuln_table.add_row(
            r.scenario_id,
            r.title,
            r.switch_settled_display,
            r.merchant_credited_display,
            r.financial_impact_display,
        )
    console.print(vuln_table)

    console.print(
        Panel(
            f"[bold #00d4ff]Gateway settled:[/] ${LEDGER.total_switch_settled_usd:,.2f} USD   │   "
            f"[bold #ff2a54]Merchant Credited/Released:[/] ${LEDGER.total_merchant_credited_usd:,.2f} USD   │   "
            f"[bold #ff2a54]NET SETTLEMENT DEFICIT: -${LEDGER.net_divergence_usd:,.2f} USD[/]\n"
            f"[bold #ffb000]INCIDENTS NEEDING TRIAGE:[/] {LEDGER.open_incidents}. "
            "The merchant's own logs show only HTTP 200 for each of them.",
            title="[bold #ff2a54]UNPATCHED LEDGER RECONCILIATION SUMMARY[/]",
            border_style="#ff2a54",
        )
    )

    # Show Dual-Log Comparison (Why Naive Logs Fail vs. OBSIDIAN Hash-Chained Telemetry)
    log_comp = Table(
        title="[bold #00d4ff]◈ SAME EVENTS, TWO LOGS: TYPICAL APP LOG vs. HASH-CHAINED AUDIT LOG[/]",
        box=box.HEAVY_EDGE,
        border_style="#1f2937",
        header_style="bold #00d4ff on #141b26",
        show_lines=True,
    )
    log_comp.add_column("STANDARD / NAIVE MERCHANT LOG (SEES '200 OK')", width=52)
    log_comp.add_column("HASH-CHAINED AUDIT LOG", width=62)

    naive_sample = [
        f"[#00ff9d]HTTP {e.http_status}[/] {e.endpoint}\n[#8892b0]{e.message}[/]"
        for e in LEDGER.naive_logs[:3]
    ]
    forensic_criticals = [
        e for e in LEDGER.forensic_logs if e.severity == "CRITICAL"
    ]
    for idx, f_entry in enumerate(forensic_criticals[:3]):
        left_txt = naive_sample[idx] if idx < len(naive_sample) else ""
        right_txt = (
            f"[bold #ff2a54][{f_entry.event_code}][/] [bold #ffb000](INCIDENT)[/]\n"
            f"{f_entry.detail}\n"
            f"[#00d4ff]SHA256 Chain: {f_entry.prev_hash} ➔ {f_entry.entry_hash}[/]"
        )
        log_comp.add_row(left_txt, right_txt)

    console.print(log_comp)
    console.print()

    # =========================================================================
    # PHASE 3: CLEAN-ROOM SIMULATION — HARDENED GUARDRAILS ACTIVE
    # =========================================================================
    LEDGER.reset()
    LEDGER.hardened_mode = True

    r1_hard = await run_scenario_01_currency_swap()
    r2_hard = await run_scenario_02_webhook_race(concurrency=12)
    r3_hard = await run_scenario_03_resource_path_spoof()

    hard_table = Table(
        title="[bold #00ff9d]◈ PHASE III: SAME ATTACKS, MERCHANT USING oppwa-guard [HARDENED MODE][/]",
        box=box.HEAVY_EDGE,
        border_style="#00ff9d",
        header_style="bold #00ff9d on #0d211a",
        show_lines=True,
    )
    hard_table.add_column("SCENARIO", style="bold #00ff9d", width=10)
    hard_table.add_column("GUARDRAIL CONTROL APPLIED", style="bold #e6edf3", width=34)
    hard_table.add_column("GATEWAY SETTLED", style="#00d4ff", width=22)
    hard_table.add_column("MERCHANT CREDITED", style="bold #00ff9d", width=22)
    hard_table.add_column("PROTECTION OUTCOME", style="bold #00ff9d", width=22)

    for r in (r1_hard, r2_hard, r3_hard):
        hard_table.add_row(
            r.scenario_id,
            r.summary,
            r.switch_settled_display,
            r.merchant_credited_display,
            r.financial_impact_display,
        )
    console.print(hard_table)

    console.print(
        Panel(
            f"[bold #00ff9d]■ NOTHING RELEASED WITHOUT A MATCHING PAYMENT:[/] "
            f"gateway settled ${LEDGER.total_switch_settled_usd:,.2f} USD, "
            f"merchant credited ${LEDGER.total_merchant_credited_usd:,.2f} USD. "
            f"The difference is the ZWG payment, held for refund or top-up.   │   "
            f"[bold #00d4ff]Losses prevented: ${LEDGER.blocked_attack_value_usd:,.2f} USD[/]",
            border_style="#00ff9d",
        )
    )

