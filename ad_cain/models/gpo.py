"""Pydantic model for Active Directory Group Policy Objects."""

from __future__ import annotations
from pydantic import BaseModel, Field


class GPOLink(BaseModel):
    """A GPO link to an OU or domain."""

    target_dn: str
    enforced: bool = False
    enabled: bool = True
    link_order: int = 0


class GPTFile(BaseModel):
    """A file from the GPO template in SYSVOL."""

    path: str
    size: int = 0
    checksum: str = ""
    content_base64: str = ""


class GPTContent(BaseModel):
    """Group Policy Template content from SYSVOL."""

    user_version: int = 0
    machine_version: int = 0
    files: list[GPTFile] = Field(default_factory=list)


class ADGPO(BaseModel):
    """Represents an AD Group Policy Object."""

    display_name: str
    guid: str
    distinguished_name: str
    gpc_version: int = 0
    gpt_version: int = 0
    flags: int = 0
    links: list[GPOLink] = Field(default_factory=list)
    gpt_content: GPTContent = Field(default_factory=GPTContent)
    created_at: str = ""
    modified_at: str = ""
