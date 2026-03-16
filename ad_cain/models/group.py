"""Pydantic model for Active Directory Groups."""

from __future__ import annotations
from pydantic import BaseModel, Field


class GroupMember(BaseModel):
    """A member reference within a group."""

    distinguished_name: str
    member_type: str = "user"  # user | group | computer


class ADGroup(BaseModel):
    """Represents an AD Security or Distribution Group."""

    distinguished_name: str
    sam_account_name: str
    group_scope: str = "Global"      # Global | DomainLocal | Universal
    group_type: str = "Security"     # Security | Distribution
    description: str = ""
    email: str = ""
    managed_by: str = ""
    members: list[GroupMember] = Field(default_factory=list)
    member_of: list[str] = Field(default_factory=list)
    created_at: str = ""
    modified_at: str = ""
