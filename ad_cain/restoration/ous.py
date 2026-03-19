"""Restore Organizational Units to a target DC."""

from __future__ import annotations

from ldap3 import Connection

from ad_cain.models.ou import ADOU
from ad_cain.logger import get_logger
from ad_cain.utils.dn_utils import dn_depth, parent_dn, rebase_dn

log = get_logger("restoration.ous")


def restore_ous(
    conn: Connection,
    base_dn: str,
    ous: list[ADOU],
    source_base_dn: str,
) -> dict[str, str]:
    """Create OUs in dependency order. Returns {old_dn: new_dn} mapping."""
    dn_map: dict[str, str] = {}
    sorted_ous = sorted(ous, key=lambda o: dn_depth(o.distinguished_name))

    for ou in sorted_ous:
        new_dn = rebase_dn(ou.distinguished_name, source_base_dn, base_dn)
        new_parent = parent_dn(new_dn)

        attrs = {
            "objectClass": ["top", "organizationalUnit"],
            "ou": ou.name,
        }
        if ou.description:
            attrs["description"] = ou.description

        try:
            conn.add(new_dn, attributes=attrs)
            if conn.result["result"] == 0:
                dn_map[ou.distinguished_name] = new_dn
                log.info("Created OU: %s", new_dn)
            elif conn.result["result"] == 68:  # already exists
                dn_map[ou.distinguished_name] = new_dn
                log.warning("OU already exists, skipping: %s", new_dn)
            else:
                log.error("Failed to create OU %s: %s", new_dn, conn.result["description"])
        except Exception as exc:
            if "entryAlreadyExists" in str(exc):
                dn_map[ou.distinguished_name] = new_dn
                log.warning("OU already exists, skipping: %s", new_dn)
            else:
                log.error("Error creating OU %s: %s", new_dn, exc)

    log.info("Restored %d / %d OUs", len(dn_map), len(ous))
    return dn_map
