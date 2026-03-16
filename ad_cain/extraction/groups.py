"""Extract Group objects from Active Directory."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE

from ad_cain.models.group import ADGroup, GroupMember
from ad_cain.logger import get_logger
from ad_cain.utils.ldap_utils import get_attr, get_attr_list

log = get_logger("extraction.groups")

GROUP_ATTRS = [
    "distinguishedName", "sAMAccountName", "groupType", "description",
    "mail", "managedBy", "member", "memberOf",
    "whenCreated", "whenChanged",
]

# AD groupType bitmask constants
_GROUP_SCOPE = {
    0x00000002: "Global",
    0x00000004: "DomainLocal",
    0x00000008: "Universal",
}


def _decode_group_type(group_type: int) -> tuple[str, str]:
    """Return (scope, kind) from groupType bitmask."""
    is_security = bool(group_type & 0x80000000)
    scope_bits = group_type & 0x0000000E
    scope = _GROUP_SCOPE.get(scope_bits, "Global")
    kind = "Security" if is_security else "Distribution"
    return scope, kind


def _classify_member(conn: Connection, member_dn: str) -> str:
    """Determine if a member DN is a user, group, or computer."""
    try:
        conn.search(
            search_base=member_dn,
            search_filter="(objectClass=*)",
            attributes=["objectClass"],
        )
        if conn.entries:
            classes = [str(c).lower() for c in conn.entries[0].objectClass.values]
            if "computer" in classes:
                return "computer"
            if "group" in classes:
                return "group"
    except Exception:
        pass
    return "user"


def extract_all_groups(conn: Connection, base_dn: str) -> list[ADGroup]:
    """Search and return all groups with members."""
    log.info("Extracting groups from %s", base_dn)
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=group)",
        search_scope=SUBTREE,
        attributes=GROUP_ATTRS,
        paged_size=1000,
    )
    groups: list[ADGroup] = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        dn = str(entry.entry_dn)
        gt = int(get_attr(attrs, "groupType", 0x80000002))
        scope, kind = _decode_group_type(gt)

        raw_members = get_attr_list(attrs, "member")
        members: list[GroupMember] = []
        for m_dn in raw_members:
            m_type = _classify_member(conn, m_dn)
            members.append(GroupMember(distinguished_name=m_dn, member_type=m_type))

        group = ADGroup(
            distinguished_name=dn,
            sam_account_name=get_attr(attrs, "sAMAccountName", ""),
            group_scope=scope,
            group_type=kind,
            description=get_attr(attrs, "description", ""),
            email=get_attr(attrs, "mail", ""),
            managed_by=get_attr(attrs, "managedBy", ""),
            members=members,
            member_of=get_attr_list(attrs, "memberOf"),
            created_at=str(get_attr(attrs, "whenCreated", "")),
            modified_at=str(get_attr(attrs, "whenChanged", "")),
        )
        groups.append(group)
    log.info("Extracted %d groups", len(groups))
    return groups
