"""Restoration sequence orchestrator — coordinates the full import."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ldap3 import Connection

from ad_cain.models.state import StateContainer
from ad_cain.config import ImportConfig
from ad_cain.logger import get_logger
from ad_cain.restoration.ous import restore_ous
from ad_cain.restoration.users import restore_users
from ad_cain.restoration.computers import restore_computers
from ad_cain.restoration.groups import restore_groups
from ad_cain.restoration.gpos import restore_gpos
from ad_cain.restoration.trusts import restore_trusts

log = get_logger("restoration.sequence")


@dataclass
class RestoreResult:
    """Summary of a restoration run."""

    ous_created: int = 0
    users_created: int = 0
    computers_created: int = 0
    groups_created: int = 0
    gpos_created: int = 0
    trusts_logged: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_created(self) -> int:
        return (
            self.ous_created + self.users_created + self.computers_created
            + self.groups_created + self.gpos_created
        )


class RestorationSequence:
    """Orchestrates object creation in correct dependency order."""

    def __init__(self, conn: Connection, base_dn: str, config: ImportConfig):
        self.conn = conn
        self.base_dn = base_dn
        self.config = config
        self._dn_map: dict[str, str] = {}

    def execute(self, state: StateContainer) -> RestoreResult:
        """Run the full restoration sequence."""
        start = time.monotonic()
        result = RestoreResult()
        source_base = _guess_source_base(state)

        log.info("Starting restoration to %s (source: %s)", self.base_dn, source_base)

        # 1. OUs
        ou_map = restore_ous(self.conn, self.base_dn, state.ous, source_base)
        self._dn_map.update(ou_map)
        result.ous_created = len(ou_map)

        # 2. Users
        if not self.config.skip_users:
            user_map = restore_users(
                self.conn, self.base_dn, state.users, source_base,
                self.config.default_password,
            )
            self._dn_map.update(user_map)
            result.users_created = len(user_map)

        # 3. Computers
        if not self.config.skip_computers:
            comp_map = restore_computers(
                self.conn, self.base_dn, state.computers, source_base,
            )
            self._dn_map.update(comp_map)
            result.computers_created = len(comp_map)

        # 4. Groups (with memberships)
        if not self.config.skip_groups:
            grp_map = restore_groups(
                self.conn, self.base_dn, state.groups, source_base, self._dn_map,
            )
            self._dn_map.update(grp_map)
            result.groups_created = len(grp_map)

        # 5. GPOs
        if not self.config.skip_gpos and state.gpos:
            gpo_map = restore_gpos(
                self.conn, self.base_dn, state.gpos, source_base,
                self.config.sysvol_path,
            )
            self._dn_map.update(gpo_map)
            result.gpos_created = len(gpo_map)

        # 6. Trusts (manual)
        if not self.config.skip_trusts and state.trusts:
            trust_info = restore_trusts(state.trusts)
            result.trusts_logged = len(trust_info)

        result.duration_seconds = round(time.monotonic() - start, 2)
        log.info(
            "Restoration complete — %d objects created in %.1fs",
            result.total_created,
            result.duration_seconds,
        )
        return result


def _guess_source_base(state: StateContainer) -> str:
    """Derive the source base DN from the domain name in state."""
    domain = state.source_domain
    if not domain:
        return ""
    parts = domain.split(".")
    return ",".join(f"DC={p}" for p in parts)
