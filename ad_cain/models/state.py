"""Central state container for AD-Cain snapshots."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from ad_cain.models.ou import ADOU
from ad_cain.models.user import ADUser
from ad_cain.models.group import ADGroup
from ad_cain.models.computer import ADComputer
from ad_cain.models.gpo import ADGPO
from ad_cain.models.trust import ADTrust
from ad_cain.utils.json_encoder import ADCainEncoder, decode_hook


class ExportMetadata(BaseModel):
    """Metadata about the export run."""

    export_tool_version: str = "1.0.0"
    python_version: str = ""
    export_duration_seconds: float = 0.0
    total_ous: int = 0
    total_users: int = 0
    total_groups: int = 0
    total_computers: int = 0
    total_gpos: int = 0
    total_trusts: int = 0
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class StateContainer(BaseModel):
    """Top-level container holding the full AD lab snapshot."""

    version: str = "1.0"
    timestamp: str = ""
    source_domain: str = ""
    source_forest: str = ""
    source_dc: str = ""

    ous: list[ADOU] = Field(default_factory=list)
    users: list[ADUser] = Field(default_factory=list)
    groups: list[ADGroup] = Field(default_factory=list)
    computers: list[ADComputer] = Field(default_factory=list)
    gpos: list[ADGPO] = Field(default_factory=list)
    trusts: list[ADTrust] = Field(default_factory=list)

    metadata: ExportMetadata = Field(default_factory=ExportMetadata)

    def stamp(self) -> None:
        """Set the timestamp to now (UTC ISO-8601)."""
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def update_counts(self) -> None:
        """Recalculate metadata totals from current lists."""
        self.metadata.total_ous = len(self.ous)
        self.metadata.total_users = len(self.users)
        self.metadata.total_groups = len(self.groups)
        self.metadata.total_computers = len(self.computers)
        self.metadata.total_gpos = len(self.gpos)
        self.metadata.total_trusts = len(self.trusts)

    # -- serialisation ----------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        """Serialize the full state to a JSON string."""
        self.update_counts()
        return json.dumps(self.model_dump(), indent=indent, cls=ADCainEncoder)

    @classmethod
    def from_json(cls, text: str) -> StateContainer:
        """Deserialize a JSON string into a StateContainer."""
        data = json.loads(text, object_hook=decode_hook)
        return cls.model_validate(data)

    def save(self, path: str | Path) -> None:
        """Write state to a JSON file."""
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> StateContainer:
        """Load state from a JSON file."""
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_json(text)
