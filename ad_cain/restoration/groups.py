"""Restore Group objects and memberships to a target DC."""

from __future__ import annotations

from ldap3 import Connection, MODIFY_ADD

from ad_cain.models.group import ADGroup
from ad_cain.logger import get_logger
from ad_cain.utils.dn_utils import rebase_dn, rdn_value

log = get_logger("restoration.groups")

_GROUP_SCOPE_BITS = {
    "Global": 0x00000002,
    "DomainLocal": 0x00000004,
    "Universal": 0x00000008,
}


def restore_groups(
    conn: Connection,
    base_dn: str,
    groups: list[ADGroup],
    source_base_dn: str,
    dn_map: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create groups and populate memberships. Returns {old_dn: new_dn}."""
    dn_map = dn_map or {}
    group_dn_map: dict[str, str] = {}

    # Phase 1: create all groups (without members)
    for grp in groups:
        new_dn = rebase_dn(grp.distinguished_name, source_base_dn, base_dn)
        cn = rdn_value(grp.distinguished_name)

        scope_bit = _GROUP_SCOPE_BITS.get(grp.group_scope, 0x00000002)
        if grp.group_type == "Security":
            scope_bit |= 0x80000000
        # groupType is a signed 32-bit int in AD
        group_type = scope_bit if scope_bit < 0x80000000 else scope_bit - (1 << 32)

        attrs = {
            "objectClass": ["top", "group"],
            "cn": cn,
            "sAMAccountName": grp.sam_account_name,
            "groupType": str(group_type),
        }
        if grp.description:
            attrs["description"] = grp.description
        if grp.email:
            attrs["mail"] = grp.email

        try:
            conn.add(new_dn, attributes=attrs)
            if conn.result["result"] == 0:
                group_dn_map[grp.distinguished_name] = new_dn
                log.info("Created group: %s", new_dn)
            elif conn.result["result"] == 68:
                group_dn_map[grp.distinguished_name] = new_dn
                log.warning("Group already exists, skipping: %s", new_dn)
            else:
                log.error("Failed to create group %s: %s", new_dn, conn.result["description"])
        except Exception as exc:
            log.error("Error creating group %s: %s", new_dn, exc)

    # Merge into master dn_map
    dn_map.update(group_dn_map)

    # Phase 2: populate memberships
    for grp in groups:
        new_group_dn = group_dn_map.get(grp.distinguished_name)
        if not new_group_dn:
            continue

        for member in grp.members:
            new_member_dn = dn_map.get(
                member.distinguished_name,
                rebase_dn(member.distinguished_name, source_base_dn, base_dn),
            )
            try:
                conn.modify(new_group_dn, {
                    "member": [(MODIFY_ADD, [new_member_dn])]
                })
                if conn.result["result"] == 0:
                    log.debug("Added %s to %s", new_member_dn, new_group_dn)
                elif conn.result["result"] == 68:
                    log.debug("Member already in group: %s -> %s", new_member_dn, new_group_dn)
                else:
                    log.warning("Could not add member %s to %s: %s",
                                new_member_dn, new_group_dn, conn.result["description"])
            except Exception as exc:
                log.warning("Error adding member %s to %s: %s",
                            new_member_dn, new_group_dn, exc)

    log.info("Restored %d / %d groups", len(group_dn_map), len(groups))
    return group_dn_map
