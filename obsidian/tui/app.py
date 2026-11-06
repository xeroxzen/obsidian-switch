"""OBSIDIAN-SWITCH interactive terminal UI."""

from __future__ import annotations

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, RichLog, Static

from obsidian.intel.passive_osint import integration_review_checklist
from obsidian.sandbox.ledger import LEDGER
from obsidian.scenarios.runner import (
    ScenarioResult,
    run_scenario_01_currency_swap,
    run_scenario_02_webhook_race,
    run_scenario_03_resource_path_spoof,
)


class ObsidianSwitchTUI(App[None]):
    """Clean-room payment integration simulator."""

    TITLE = "OBSIDIAN-SWITCH"
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("1", "scenario_01", "[1] USD/ZWG Desync", show=True),
        Binding("2", "scenario_02", "[2] 12x Duplicate Notification", show=True),
        Binding("3", "scenario_03", "[3] ResourcePath Bypass", show=True),
        Binding("4", "passive_osint", "[4] Review Checklist", show=True),
        Binding("h", "toggle_hardened", "[H] Toggle Guardrails", show=True),
        Binding("e", "export_dossier", "[E] Export HTML Report", show=True),
        Binding("r", "reset_ledgers", "[R] Purge Ledgers", show=True),
        Binding("q", "quit", "[Q] Exit Console", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._rendered_naive_count = 0
        self._rendered_forensic_count = 0

    def compose(self) -> ComposeResult:
        yield Static(
            "██ OBSIDIAN-SWITCH v1.1 // PAYMENT INTEGRATION CLEAN-ROOM SIMULATOR // IN-PROCESS, NO NETWORK ██",
            id="top-classification-bar",
        )

        with Horizontal(id="hud-bar"):
            yield Static(id="hud-posture", classes="hud-card")
            yield Static(id="hud-switch", classes="hud-card")
            yield Static(id="hud-merchant", classes="hud-card")
            yield Static(id="hud-divergence", classes="hud-card")

        with Horizontal(id="control-bar"):
            yield Button("[1] SCN-01: USD/ZWG SWAP", id="btn-scn1", classes="tactical-btn")
            yield Button("[2] SCN-02: 12x DUPLICATE NOTIFY", id="btn-scn2", classes="tactical-btn")
            yield Button("[3] SCN-03: PATH INJECTION", id="btn-scn3", classes="tactical-btn")
            yield Button("[4] REVIEW CHECKLIST", id="btn-osint", classes="tactical-btn")
            yield Button("[H] TOGGLE HARDENED", id="btn-hard", classes="tactical-btn")
            yield Button("[R] RESET LEDGER", id="btn-reset", classes="tactical-btn")

        with Vertical(id="ledger-container"):
            yield Static(
                "◈ LIVE RECONCILIATION [GATEWAY vs. MERCHANT]",
                classes="pane-title",
            )
            yield DataTable(id="ledger-table", zebra_stripes=True)

        with Horizontal(id="dual-log-container"):
            with Vertical(classes="log-pane"):
                yield Static(
                    "◈ STANDARD / NAIVE MERCHANT LOGS (BLIND TO LOGIC EXPLOITS)",
                    classes="pane-title",
                )
                yield RichLog(id="naive-log", highlight=True, markup=True, wrap=True)

            with Vertical(classes="log-pane"):
                yield Static(
                    "◈ HASH-CHAINED AUDIT LOG (SEES WHAT THE APP LOG MISSES)",
                    classes="pane-title",
                )
                yield RichLog(id="forensic-log", highlight=True, markup=True, wrap=True)

        yield Static(
            "Simulation only: an in-process mock gateway and merchant. No traffic is sent to any real system.",
            id="status-strip",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#ledger-table", DataTable)
        table.add_columns(
            "SCN",
            "GUARDRAIL MODE",
            "ORDER ID",
            "GATEWAY SETTLED (AUTHORITATIVE)",
            "MERCHANT CREDITED / FULFILLED",
            "NET FINANCIAL IMPACT",
            "VERDICT",
        )
        self._refresh_hud()
        self._sync_log_panes()

        naive_widget = self.query_one("#naive-log", RichLog)
        naive_widget.write(
            "[bold #6c7a89]// Standard application log stream ready. Waiting for checkout callbacks...[/]"
        )

    def _refresh_hud(self) -> None:
        posture_widget = self.query_one("#hud-posture", Static)
        switch_widget = self.query_one("#hud-switch", Static)
        merchant_widget = self.query_one("#hud-merchant", Static)
        div_widget = self.query_one("#hud-divergence", Static)

        if LEDGER.hardened_mode:
            posture_text = (
                "[bold #6c7a89]DOWNSTREAM GUARDRAIL POSTURE[/]\n"
                "[bold #00ff9d]■ HARDENED // oppwa-guard[/]\n"
                "[#8892b0]Full verify + stored path + unique claim[/]"
            )
        else:
            posture_text = (
                "[bold #6c7a89]DOWNSTREAM GUARDRAIL POSTURE[/]\n"
                "[bold #ff2a54]▲ VULNERABLE // UNPATCHED[/]\n"
                "[#ffb000]Status-Code Only / Non-Atomic DB[/]"
            )
        posture_widget.update(posture_text)

        switch_widget.update(
            "[bold #6c7a89]GATEWAY SETTLED[/]\n"
            f"[bold #00d4ff]${LEDGER.total_switch_settled_usd:,.2f} USD[/]\n"
            f"[#8892b0]Active Checkouts: {len(LEDGER.switch_settlements)}[/]"
        )

        merchant_widget.update(
            "[bold #6c7a89]MERCHANT CREDITED / RELEASED[/]\n"
            f"[bold #e6edf3]${LEDGER.total_merchant_credited_usd:,.2f} USD[/]\n"
            f"[#8892b0]Orders Processed: {len(LEDGER.merchant_orders)}[/]"
        )

        divergence = LEDGER.net_divergence_usd
        if divergence > 0.001:
            div_text = (
                "[bold #6c7a89]DIVERGENCE & INCIDENTS[/]\n"
                f"[bold #ff2a54]-${divergence:,.2f} USD LEAKAGE[/]\n"
                f"[bold #ffb000]⚡ INCIDENTS NEEDING TRIAGE: {LEDGER.open_incidents}[/]"
            )
        else:
            div_text = (
                "[bold #6c7a89]DIVERGENCE & INCIDENTS[/]\n"
                "[bold #00ff9d]NO UNPAID GOODS RELEASED[/]\n"
                f"[#00d4ff]Losses prevented: ${LEDGER.blocked_attack_value_usd:,.2f} USD[/]"
            )
        div_widget.update(div_text)

    def _sync_log_panes(self) -> None:
        naive_widget = self.query_one("#naive-log", RichLog)
        forensic_widget = self.query_one("#forensic-log", RichLog)

        while self._rendered_naive_count < len(LEDGER.naive_logs):
            entry = LEDGER.naive_logs[self._rendered_naive_count]
            self._rendered_naive_count += 1
            color = "#00ff9d" if entry.http_status == 200 else "#ffb000"
            naive_widget.write(
                f"[#6c7a89]{entry.timestamp}[/] [{color}]HTTP {entry.http_status}[/] "
                f"[bold #d8dee9]{entry.endpoint}[/] — {entry.message}"
            )

        while self._rendered_forensic_count < len(LEDGER.forensic_logs):
            f_entry = LEDGER.forensic_logs[self._rendered_forensic_count]
            self._rendered_forensic_count += 1
            if f_entry.severity == "CRITICAL":
                sev_badge = "[bold #ff2a54][CRITICAL // LOSS][/]"
            elif f_entry.severity == "BLOCKED":
                sev_badge = "[bold #00ff9d][GUARDRAIL BLOCKED][/]"
            elif f_entry.severity == "WARNING":
                sev_badge = "[bold #ffb000][POSTURE WARNING][/]"
            else:
                sev_badge = "[bold #00d4ff][NOMINAL TELEMETRY][/]"

            sla_tag = (
                " [bold #ff2a54 on #2a0a12] INCIDENT: TRIAGE REQUIRED [/]" if f_entry.incident else ""
            )
            forensic_widget.write(
                f"[#6c7a89]#{f_entry.seq_id:03d} {f_entry.timestamp}[/] {sev_badge} "
                f"[bold #ffb000]{f_entry.event_code}[/]{sla_tag}\n"
                f"  [#8892b0]├─ Vector:[/] {f_entry.vector}\n"
                f"  [#8892b0]├─ Detail:[/] [#e6edf3]{f_entry.detail}[/]\n"
                f"  [#8892b0]└─ Chain :[/] [#00d4ff]{f_entry.prev_hash} ➔ {f_entry.entry_hash}[/]"
            )

    def _append_scenario_row(self, res: ScenarioResult) -> None:
        table = self.query_one("#ledger-table", DataTable)
        mode_styled = (
            Text("HARDENED", style="bold #00ff9d")
            if res.mode == "HARDENED"
            else Text("VULNERABLE", style="bold #ff2a54")
        )
        impact_styled = (
            Text(res.financial_impact_display, style="bold #ff2a54")
            if res.compromised
            else Text(res.financial_impact_display, style="bold #00ff9d")
        )
        verdict_styled = (
            Text("EXPLOITED (SILENT IN NAIVE LOGS)", style="bold #ff2a54")
            if res.compromised
            else Text("MITIGATED & LOGGED", style="bold #00ff9d")
        )
        table.add_row(
            res.scenario_id,
            mode_styled,
            res.order_id,
            res.switch_settled_display,
            res.merchant_credited_display,
            impact_styled,
            verdict_styled,
        )
        table.scroll_end(animate=False)

    async def action_scenario_01(self) -> None:
        res = await run_scenario_01_currency_swap()
        self._append_scenario_row(res)
        self._refresh_hud()
        self._sync_log_panes()

    async def action_scenario_02(self) -> None:
        res = await run_scenario_02_webhook_race(concurrency=12)
        self._append_scenario_row(res)
        self._refresh_hud()
        self._sync_log_panes()

    async def action_scenario_03(self) -> None:
        res = await run_scenario_03_resource_path_spoof()
        self._append_scenario_row(res)
        self._refresh_hud()
        self._sync_log_panes()

    async def action_passive_osint(self) -> None:
        forensic_widget = self.query_one("#forensic-log", RichLog)
        forensic_widget.write("\n[bold #ffb000]═══ PAYMENT INTEGRATION REVIEW CHECKLIST ═══[/]")
        for item in integration_review_checklist():
            badge_color = "#ff2a54" if item.risk_rating == "CRITICAL" else "#ffb000"
            forensic_widget.write(
                f"[bold {badge_color}][{item.item_id} // {item.risk_rating}][/] "
                f"[bold #e6edf3]{item.title}[/]\n"
                f"  [#8892b0]├─ Area :[/] [#00d4ff]{item.area}[/]\n"
                f"  [#8892b0]├─ Check:[/] {item.what_to_check}\n"
                f"  [#8892b0]└─ Fix  :[/] [#00ff9d]{item.fix}[/]"
            )

    def action_toggle_hardened(self) -> None:
        LEDGER.toggle_hardened_mode()
        self._refresh_hud()
        self._sync_log_panes()

    async def action_export_dossier(self) -> None:
        from pathlib import Path

        from obsidian.dossier import generate_executive_html_dossier

        out_path = Path("reports/OBSIDIAN_REPORT.html").resolve()
        await generate_executive_html_dossier(out_path, [])
        forensic_widget = self.query_one("#forensic-log", RichLog)
        forensic_widget.write(
            f"\n[bold #00ff9d]✔ REPORT EXPORTED:[/] [bold #00d4ff]{out_path}[/]\n"
        )
        self._refresh_hud()
        self._sync_log_panes()

    def action_reset_ledgers(self) -> None:
        LEDGER.reset()
        self._rendered_naive_count = 0
        self._rendered_forensic_count = 0
        table = self.query_one("#ledger-table", DataTable)
        table.clear()
        self.query_one("#naive-log", RichLog).clear()
        self.query_one("#forensic-log", RichLog).clear()
        self._refresh_hud()
        self._sync_log_panes()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-scn1":
            await self.action_scenario_01()
        elif btn_id == "btn-scn2":
            await self.action_scenario_02()
        elif btn_id == "btn-scn3":
            await self.action_scenario_03()
        elif btn_id == "btn-osint":
            await self.action_passive_osint()
        elif btn_id == "btn-hard":
            self.action_toggle_hardened()
        elif btn_id == "btn-reset":
            self.action_reset_ledgers()

