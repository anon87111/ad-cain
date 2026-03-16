"""Restore Domain Trust relationships (informational — trusts require manual setup)."""

from __future__ import annotations

from ad_cain.models.trust import ADTrust
from ad_cain.logger import get_logger

log = get_logger("restoration.trusts")


def restore_trusts(trusts: list[ADTrust]) -> list[dict]:
    """Log trust information for manual recreation.

    Domain trusts require shared secrets and bidirectional configuration,
    so they cannot be fully automated via LDAP alone. This function
    outputs the trust configuration for the operator to recreate manually.
    """
    results: list[dict] = []
    for trust in trusts:
        info = {
            "trusted_domain": trust.trusted_domain,
            "direction": trust.trust_direction,
            "type": trust.trust_type,
            "transitive": trust.transitive,
            "status": "manual_action_required",
        }
        log.info(
            "Trust requires manual setup: %s (%s, %s, transitive=%s)",
            trust.trusted_domain,
            trust.trust_direction,
            trust.trust_type,
            trust.transitive,
        )
        results.append(info)

    if trusts:
        log.warning(
            "%d trust(s) require manual recreation — see output for details.",
            len(trusts),
        )
    return results
