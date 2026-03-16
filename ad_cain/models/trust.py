"""Pydantic model for Active Directory Domain Trusts."""

from __future__ import annotations
from pydantic import BaseModel


class ADTrust(BaseModel):
    """Represents an AD domain trust relationship."""

    trusted_domain: str
    trust_direction: str = ""   # Inbound | Outbound | Bidirectional
    trust_type: str = ""        # External | Forest | ParentChild | CrossLink
    transitive: bool = False
    selective_authentication: bool = False
    sid_filtering: bool = True
    flat_name: str = ""
    trust_attributes: int = 0
    created_at: str = ""
