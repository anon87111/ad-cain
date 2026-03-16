"""Import orchestrator — coordinates full AD state restoration."""

from __future__ import annotations

from pathlib import Path

from ldap3 import Connection

from ad_cain.models.state import StateContainer
from ad_cain.config import ImportConfig
from ad_cain.logger import get_logger
from ad_cain.restoration.sequence import RestorationSequence, RestoreResult
from ad_cain.utils.errors import RestorationError

log = get_logger("importer")


def run_import(
    conn: Connection,
    base_dn: str,
    config: ImportConfig,
) -> RestoreResult:
    """Load a state file and restore it to the target DC."""
    log.info("Loading state file: %s", config.state_file)

    try:
        state = StateContainer.load(config.state_file)
    except Exception as exc:
        raise RestorationError(f"Failed to load state file: {exc}") from exc

    log.info(
        "State loaded — %d OUs, %d users, %d groups, %d computers, %d GPOs, %d trusts",
        len(state.ous), len(state.users), len(state.groups),
        len(state.computers), len(state.gpos), len(state.trusts),
    )

    if config.dry_run:
        log.info("DRY RUN — no changes will be made.")
        return RestoreResult(
            ous_created=len(state.ous),
            users_created=len(state.users),
            computers_created=len(state.computers),
            groups_created=len(state.groups),
            gpos_created=len(state.gpos),
            trusts_logged=len(state.trusts),
            warnings=["Dry run — counts represent what WOULD be created."],
        )

    seq = RestorationSequence(conn, base_dn, config)
    return seq.execute(state)
