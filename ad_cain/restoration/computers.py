"""Restore Computer accounts to a target DC."""

from __future__ import annotations

from ldap3 import Connection

from ad_cain.models.computer import ADComputer
from ad_cain.logger import get_logger
from ad_cain.utils.dn_utils import rebase_dn, rdn_value

log = get_logger("restoration.computers")


def restore_computers(
    conn: Connection,
    base_dn: str,
    computers: list[ADComputer],
    source_base_dn: str,
) -> dict[str, str]:
    """Create computer accounts. Returns {old_dn: new_dn} mapping."""
    dn_map: dict[str, str] = {}

    for comp in computers:
        new_dn = rebase_dn(comp.distinguished_name, source_base_dn, base_dn)
        cn = rdn_value(comp.distinguished_name)

        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": cn,
            "sAMAccountName": comp.sam_account_name,
            "userAccountControl": str(comp.user_account_control),
        }
        if comp.dns_name:
            attrs["dNSHostName"] = comp.dns_name
        if comp.description:
            attrs["description"] = comp.description
        if comp.operating_system:
            attrs["operatingSystem"] = comp.operating_system
        if comp.operating_system_version:
            attrs["operatingSystemVersion"] = comp.operating_system_version
        if comp.location:
            attrs["location"] = comp.location

        try:
            conn.add(new_dn, attributes=attrs)
            if conn.result["result"] == 0:
                dn_map[comp.distinguished_name] = new_dn
                log.info("Created computer: %s", new_dn)
            elif conn.result["result"] == 68:
                dn_map[comp.distinguished_name] = new_dn
                log.warning("Computer already exists, skipping: %s", new_dn)
            else:
                log.error("Failed to create computer %s: %s", new_dn, conn.result["description"])
        except Exception as exc:
            if "entryAlreadyExists" in str(exc):
                dn_map[comp.distinguished_name] = new_dn
                log.warning("Computer already exists, skipping: %s", new_dn)
            else:
                log.error("Error creating computer %s: %s", new_dn, exc)

    log.info("Restored %d / %d computers", len(dn_map), len(computers))
    return dn_map
