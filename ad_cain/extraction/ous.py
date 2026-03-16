"""Extract Organizational Units from Active Directory."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE

from ad_cain.models.ou import ADOU
from ad_cain.logger import get_logger
from ad_cain.utils.ldap_utils import get_attr, filetime_to_datetime
from ad_cain.utils.dn_utils import dn_depth

log = get_logger("extraction.ous")

OU_ATTRS = [
    "distinguishedName", "name", "description", "managedBy",
    "objectGUID", "whenCreated", "whenChanged",
    "isCriticalSystemObject",
]


def extract_all_ous(conn: Connection, base_dn: str) -> list[ADOU]:
    """Search and return all OUs sorted by depth (root-first)."""
    log.info("Extracting OUs from %s", base_dn)
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=organizationalUnit)",
        search_scope=SUBTREE,
        attributes=OU_ATTRS,
        paged_size=1000,
    )
    ous: list[ADOU] = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        dn = str(entry.entry_dn)
        ou = ADOU(
            distinguished_name=dn,
            name=get_attr(attrs, "name", ""),
            description=get_attr(attrs, "description", ""),
            managed_by=get_attr(attrs, "managedBy", ""),
            ou_guid=str(get_attr(attrs, "objectGUID", "")),
            created_at=str(get_attr(attrs, "whenCreated", "")),
            modified_at=str(get_attr(attrs, "whenChanged", "")),
        )
        ous.append(ou)
    # Sort root-first for correct creation order
    ous.sort(key=lambda o: dn_depth(o.distinguished_name))
    log.info("Extracted %d OUs", len(ous))
    return ous
