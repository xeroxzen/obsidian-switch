"""Entrypoint: interactive TUI, scripted CLI demo, email posture check, or HTML report."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from obsidian.cli_demo import run_gothic_cli_demo
from obsidian.intel.passive_osint import mail_posture

VERDICT_STYLE = {"exposed": "bold #ff2a54", "partial": "bold #ffb000", "protected": "bold #00ff9d"}


def print_mail_posture(domains: list[str]) -> None:
    table = Table(
        title="[bold #ffb000]EMAIL SPOOFING POSTURE (public DNS only)[/]",
        box=box.HEAVY_EDGE,
        border_style="#1f2937",
        header_style="bold #00d4ff on #141b26",
        show_lines=True,
    )
    table.add_column("DOMAIN", style="bold #e6edf3", no_wrap=True)
    table.add_column("VERDICT", no_wrap=True)
    table.add_column("DMARC IN EFFECT", ratio=2)
    table.add_column("FINDINGS", ratio=3)
    for domain in domains:
        result = mail_posture(domain)
        if isinstance(result, str):
            table.add_row(escape(domain), "[#6c7a89]UNKNOWN[/]", "", escape(result))
            continue
        findings = "\n".join(escape(f"[{f.severity}] {f.title}") for f in result.findings) or "None"
        table.add_row(
            escape(domain),
            f"[{VERDICT_STYLE[result.verdict]}]{result.verdict.upper()}[/]",
            escape(result.dmarc_record) if result.dmarc_record else "[#ff2a54]none[/]",
            findings,
        )
    Console().print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="obsidian-switch",
        description="Clean-room payment integration simulator (in-process, no network).",
    )
    parser.add_argument("--demo", action="store_true", help="Print the full scripted demo and exit.")
    parser.add_argument(
        "--mail-posture",
        nargs="+",
        metavar="DOMAIN",
        help="Check SPF/DMARC posture of domains you are authorised to discuss.",
    )
    parser.add_argument(
        "--export-dossier",
        nargs="?",
        const="reports/OBSIDIAN_REPORT.html",
        metavar="OUTPUT_HTML",
        help="Write an HTML report (default: reports/OBSIDIAN_REPORT.html).",
    )
    parser.add_argument(
        "--dossier-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Include this domain's email posture in the report (repeatable).",
    )
    args = parser.parse_args()

    if args.export_dossier:
        from obsidian.dossier import generate_executive_html_dossier

        out_file = Path(args.export_dossier).resolve()
        asyncio.run(generate_executive_html_dossier(out_file, args.dossier_domain))
        Console().print(f"[bold #00ff9d]Report written:[/] [bold #00d4ff]{out_file}[/]")
        return
    if args.mail_posture:
        print_mail_posture(args.mail_posture)
        return
    if args.demo:
        asyncio.run(run_gothic_cli_demo())
        return

    from obsidian.tui.app import ObsidianSwitchTUI

    ObsidianSwitchTUI().run()


if __name__ == "__main__":
    main()
