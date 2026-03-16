"""Pydantic model for Active Directory Computer accounts."""

from __future__ import annotations
from pydantic import BaseModel, Field


class ADComputer(BaseModel):
    """Represents an AD Computer object."""

    distinguished_name: str
    sam_account_name: str
    dns_name: str = ""
    description: str = ""
    enabled: bool = True
    user_account_control: int = 4096
    operating_system: str = ""
    operating_system_version: str = ""
    location: str = ""
    managed_by: str = ""
    created_at: str = ""
    modified_at: str = ""
