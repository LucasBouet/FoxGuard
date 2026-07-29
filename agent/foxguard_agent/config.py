"""Agent configuration (environment driven)."""

from __future__ import annotations

import functools
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FOXGUARD_AGENT_",
        env_file="/etc/foxguard/agent.env",
        extra="ignore",
    )

    api_url: str = "http://127.0.0.1:8000"
    api_token: SecretStr = Field(description="Must match FOXGUARD_AGENT_API_TOKEN.")
    poll_interval_seconds: float = Field(default=10.0, ge=1.0)
    request_timeout_seconds: float = 15.0

    nft_path: str = "nft"
    nft_table_name: str = "foxguard"
    wg_path: str = "wg"
    manage_wireguard: bool = Field(
        default=True,
        description="Sync WireGuard peers as well as nftables. Turn off if wg is managed elsewhere.",
    )

    state_dir: Path = Path("/var/lib/foxguard")
    #: Render and validate but never apply. Useful for a first dry deployment.
    dry_run: bool = False
    log_level: str = "INFO"

    @property
    def last_good_path(self) -> Path:
        return self.state_dir / "last-good.nft"


@functools.lru_cache
def get_agent_settings() -> AgentSettings:
    return AgentSettings()
