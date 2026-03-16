"""Export orchestrator — coordinates full AD state extraction."""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone

from ldap3 import Connection

from ad_cain.models.state import StateContainer
from ad_cain.config import ExportConfig
from ad_cain.logger import get_logger
from ad_cain.extraction.ous import extract_all_ous
from ad_cain.extraction.users import extract_all_users
from ad_cain.extraction.computers import extract_all_computers
from ad_cain.extraction.groups import extract_all_groups
from ad_cain.extraction.trusts import extract_all_trusts
from ad_cain.extraction.gpos import extract_all_gpos
from ad_cain.extraction.dependencies import validate_dependencies
from ad_cain.utils.dn_utils import domain_from_dn
from ad_cain.utils.errors import ExportError

log = get_logger("exporter")


def run_export(
    conn: Connection,
    base_dn: str,
    dc_name: str,
    config: ExportConfig,
) -> StateContainer:
    """Execute a full AD state export and return a StateContainer."""
    start = time.monotonic()
    log.info("Starting export from %s", base_dn)

    state = StateContainer(
        source_domain=domain_from_dn(base_dn),
        source_dc=dc_name,
    )
    state.stamp()

    try:
        state.ous = extract_all_ous(conn, base_dn)
        state.users = extract_all_users(conn, base_dn)
        state.computers = extract_all_computers(conn, base_dn)
        state.groups = extract_all_groups(conn, base_dn)

        if config.include_trusts:
            state.trusts = extract_all_trusts(conn, base_dn)

        if config.include_gpos:
            state.gpos = extract_all_gpos(conn, base_dn, config.sysvol_path)

    except Exception as exc:
        raise ExportError(f"Export failed: {exc}") from exc

    # Dependency validation
    warnings = validate_dependencies(state)
    state.metadata.warnings = warnings
    state.metadata.python_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    state.metadata.export_duration_seconds = round(time.monotonic() - start, 2)
    state.update_counts()

    log.info(
        "Export complete — %d OUs, %d users, %d groups, %d computers, %d GPOs, %d trusts (%.1fs)",
        len(state.ous), len(state.users), len(state.groups),
        len(state.computers), len(state.gpos), len(state.trusts),
        state.metadata.export_duration_seconds,
    )
    return state
