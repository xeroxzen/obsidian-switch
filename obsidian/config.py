"""Clean-room configuration, throwaway secrets, and currency constants."""

from dataclasses import dataclass

# STRICT SAFETY LOCK: Sandbox binds exclusively to local loopback interface
SANDBOX_HOST = "127.0.0.1"
SANDBOX_PORT = 8765
SANDBOX_BASE_URL = f"http://{SANDBOX_HOST}:{SANDBOX_PORT}"

# Clean-Room Ephemeral Secrets (Never used outside 127.0.0.1 sandbox)
CLEANROOM_MERCHANT_ENTITY_ID = "8ac7a4c8901f2b3d019020a1b99c0442"
CLEANROOM_BEARER_TOKEN = "OGFjN2E0Yzg5MDFmMmIzZDAxOTAyMGExYjk5YzA0NDJ8U0FOREJPWF9LRVk="
# 256-bit AES-GCM webhook key, hex encoded, as OPPWA issues them. Clean-room only.
CLEANROOM_WEBHOOK_KEY_HEX = "6f6273696469616e2d636c65616e726f6f6d2d776562686f6f6b2d6b65792121"

# Exchange rate used for clean-room multi-currency settlement comparison
# 1 USD = 28.50 ZWG (illustrative interbank reference rate for simulation)
ZWG_PER_USD_RATE = 28.50


def to_usd_equivalent(amount: float, currency: str) -> float:
    """Convert a transaction amount into USD equivalent for ledger reconciliation."""
    curr = currency.upper().strip()
    if curr == "USD":
        return round(amount, 2)
    if curr == "ZWG":
        return round(amount / ZWG_PER_USD_RATE, 2)
    return round(amount, 2)


@dataclass
class TacticalPalette:
    """Terminal colour scheme."""

    OBSIDIAN_BG = "#0a0c10"
    PANEL_BG = "#0f131a"
    SLATE_BORDER = "#1f2633"
    PHOSPHOR_AMBER = "#ffb000"
    TACTICAL_CRIMSON = "#ff2a54"
    CRYPTO_EMERALD = "#00ff9d"
    CYAN_TELEMETRY = "#00d4ff"
    MUTED_STEEL = "#6c7a89"
    BONE_WHITE = "#e6edf3"

