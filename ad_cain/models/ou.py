"""Pydantic model for Active Directory Organizational Units."""

from __future__ import annotations
from pydantic import BaseModel, Field


class ADOU(BaseModel):
    """Represents an AD Organizational Unit."""

    distinguished_name: str
    name: str
    description: str = ""
    managed_by: str = ""
    ou_guid: str = ""
    protected_from_deletion: bool = False
    created_at: str = ""
    modified_at: str = ""

    class Config:
        populate_by_name = True
