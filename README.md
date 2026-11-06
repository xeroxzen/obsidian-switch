# OBSIDIAN-SWITCH

A clean-room simulator that shows how three common payment-integration bugs lose a merchant money while its logs show nothing but `HTTP 200`, and how the same attacks fail once the integration uses [`oppwa-guard`](https://github.com/xeroxzen/oppwa-guard).

Everything runs in one process: a mock OPPWA-style gateway and a mock merchant, connected through an in-process ASGI transport. No socket is opened and no real gateway is contacted. The gateway follows the shape of the public OPPWA API (`POST /v1/checkouts`, `GET /v1/checkouts/{id}/payment`, AES-256-GCM webhook notifications, documented result codes).

## What it shows

| Scenario | Bug in the merchant | Unprotected result | Fix (`oppwa-guard`) |
|---|---|---|---|
| SCN-01 Currency swap | Fulfils on `result.code` alone | USD 1,000 order released for ZWG 1,000 (about USD 35): **USD 964.91 lost** | `verify_payment` compares currency, amount and order reference |
| SCN-02 Duplicate notifications | "Already processed?" check and the write are separate steps | One USD 250 payment credited 12 times: **USD 2,750 lost** | `claim_payment`: a unique-constraint insert in the crediting transaction |
| SCN-03 Edited `resourcePath` | Fetches payment status from the path in the browser's return URL | Unpaid USD 1,500 order shipped: **USD 1,500 lost** | `status_path` built from the stored checkout id |

The ZWG/USD rate is an illustrative constant in `obsidian/config.py`.

## Run

```bash
uv sync
uv run obsidian-switch                      # interactive TUI
uv run obsidian-switch --demo               # scripted walkthrough in the terminal
uv run obsidian-switch --export-dossier     # printable HTML report in reports/
uv run obsidian-switch --mail-posture example.co.zw   # SPF/DMARC check via spoofscore
uv run pytest                               # regression tests, including a headless TUI run
```

`--export-dossier` includes an email section only for domains you pass with `--dossier-domain`. Include a domain only in a report you're giving to its owner.

### TUI keys

| Key | Action |
|---|---|
| `1` `2` `3` | Run SCN-01, SCN-02, SCN-03 |
| `4` | Show the integration review checklist |
| `h` | Toggle vulnerable / hardened merchant |
| `e` | Export the HTML report |
| `r` | Reset |
| `q` | Quit |

## Presenter script (3 minutes)

1. **Frame it (0:00).** "This is a simulation on my laptop. It doesn't touch your systems or anyone else's. It shows three mistakes I see in payment integrations generally, and what each one costs."
2. **Show the loss (0:30).** Press `1`, `2`, `3`. "On the left is what the merchant's normal logs say: success, every time. On the right is the same activity in an audit log. USD 5,214 has gone, and nobody would notice until reconciliation, if then."
3. **Show the fix (1:30).** Press `h`, then `1`, `2`, `3`. "Same attacks. Each one is stopped by a few lines of verification: check the payment matches the order, never trust the browser's path, and credit each payment exactly once at the database level. The library is open source."
4. **The ask (2:30).** "I'd like to spend a week reviewing your payment integration against this checklist, at a fixed price, and give you a written report with the fixes."

## Claims to avoid

- Don't say these bugs exist in a specific organisation's systems unless you've reviewed those systems with written permission.
- The Cyber and Data Protection Act requires reporting a breach that affects personal data to POTRAZ within 24 hours. A payment-logic loss is not automatically a reportable personal-data breach. The simulator flags *incidents needing triage*, not statutory deadlines.
