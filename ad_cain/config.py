"""Configuration management for AD-Cain."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""

    server: str = ""
    port: int = 389
    use_ssl: bool = False
    username: str = ""
    password: str = ""
    timeout: int = 30
    page_size: int = 1000

    @classmethod
    def from_env(cls) -> LDAPConfig:
        """Load configuration from environment variables."""
        return cls(
            server=os.getenv("AD_CAIN_SERVER", ""),
            port=int(os.getenv("AD_CAIN_PORT", "389")),
            use_ssl=os.getenv("AD_CAIN_SSL", "").lower() in ("1", "true", "yes"),
            username=os.getenv("AD_CAIN_USER", ""),
            password=os.getenv("AD_CAIN_PASS", ""),
            timeout=int(os.getenv("AD_CAIN_TIMEOUT", "30")),
            page_size=int(os.getenv("AD_CAIN_PAGE_SIZE", "1000")),
        )

    def merge_cli(self, **kwargs) -> LDAPConfig:
        """Override config values with CLI-provided arguments (non-None only)."""
        for key, value in kwargs.items():
            if value is not None and hasattr(self, key):
                setattr(self, key, value)
        return self


@dataclass
class ExportConfig:
    """Export-specific settings."""

    include_gpos: bool = True
    include_trusts: bool = True
    sysvol_path: str | None = None
    output_path: str = "ad_state.json"


@dataclass
class ImportConfig:
    """Import-specific settings."""

    state_file: str = ""
    sysvol_path: str | None = None
    dry_run: bool = False
    skip_users: bool = False
    skip_groups: bool = False
    skip_computers: bool = False
    skip_gpos: bool = False
    skip_trusts: bool = False
    default_password: str = "ChangeMe123!"
