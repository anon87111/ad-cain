"""Pydantic model for Active Directory Users."""

from __future__ import annotations
from pydantic import BaseModel, Field


class PasswordPolicy(BaseModel):
    """User password metadata (never stores actual passwords)."""

    last_set: str = ""
    never_expires: bool = False
    must_change_at_logon: bool = False
    account_expires: str | None = None


class ADUser(BaseModel):
    """Represents an AD User object."""

    distinguished_name: str
    sam_account_name: str
    user_principal_name: str = ""
    first_name: str = ""
    last_name: str = ""
    display_name: str = ""
    email: str = ""
    description: str = ""
    enabled: bool = True
    user_account_control: int = 512
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    group_memberships: list[str] = Field(default_factory=list)
    manager: str = ""
    telephone: str = ""
    department: str = ""
    company: str = ""
    title: str = ""
    office: str = ""
    attributes: dict[str, str] = Field(default_factory=dict)
    created_at: str = ""
    modified_at: str = ""
