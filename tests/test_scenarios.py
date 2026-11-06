from __future__ import annotations

import asyncio
from pathlib import Path

from obsidian.dossier import generate_executive_html_dossier
from obsidian.sandbox.ledger import LEDGER
from obsidian.scenarios.runner import (
    run_scenario_01_currency_swap,
    run_scenario_02_webhook_race,
    run_scenario_03_resource_path_spoof,
)
from obsidian.tui.app import ObsidianSwitchTUI


async def _run_all(hardened: bool) -> None:
    LEDGER.reset()
    LEDGER.hardened_mode = hardened
    await run_scenario_01_currency_swap()
    await run_scenario_02_webhook_race(concurrency=12)
    await run_scenario_03_resource_path_spoof()


def test_vulnerable_merchant_loses_and_hardened_prevents_the_same_amount() -> None:
    asyncio.run(_run_all(hardened=False))
    loss = LEDGER.net_divergence_usd
    assert loss == 5214.91
    assert LEDGER.open_incidents == 3

    asyncio.run(_run_all(hardened=True))
    assert LEDGER.blocked_attack_value_usd == loss
    assert LEDGER.open_incidents == 0
    assert LEDGER.total_merchant_credited_usd == 250.00


def test_audit_log_chain_links() -> None:
    asyncio.run(_run_all(hardened=False))
    entries = LEDGER.forensic_logs
    assert len(entries) > 1
    for prev, cur in zip(entries, entries[1:], strict=False):
        assert cur.prev_hash == prev.entry_hash[:12]


def test_report_escapes_and_omits_mail_section_by_default(tmp_path: Path) -> None:
    out = asyncio.run(generate_executive_html_dossier(tmp_path / "r.html", []))
    html = out.read_text(encoding="utf-8")
    assert "Email spoofing posture" not in html
    assert "5,214.91" in html


def test_tui_runs_every_action() -> None:
    async def drive() -> None:
        LEDGER.reset()
        LEDGER.hardened_mode = False
        app = ObsidianSwitchTUI()
        async with app.run_test() as pilot:
            for key in ("1", "2", "3", "4", "h", "1", "2", "3", "r"):
                await pilot.press(key)
                await pilot.pause()

    asyncio.run(drive())
