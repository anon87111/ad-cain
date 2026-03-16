"""Extract Computer accounts from Active Directory."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE

from ad_cain.models.computer import ADComputer
from ad_cain.logger import get_logger
from ad_cain.utils.ldap_utils import get_attr

log = get_logger("extraction.computers")

COMPUTER_ATTRS = [
    "distinguishedName", "sAMAccountName", "dNSHostName", "description",
    "userAccountControl", "operatingSystem", "operatingSystemVersion",
    "location", "managedBy", "whenCreated", "whenChanged",
]


def extract_all_computers(conn: Connection, base_dn: str) -> list[ADComputer]:
    """Search and return all computer accounts."""
    log.info("Extracting computers from %s", base_dn)
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=computer)",
        search_scope=SUBTREE,
        attributes=COMPUTER_ATTRS,
        paged_size=1000,
    )
    computers: list[ADComputer] = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        dn = str(entry.entry_dn)
        uac = int(get_attr(attrs, "userAccountControl", 4096))
        comp = ADComputer(
            distinguished_name=dn,
            sam_account_name=get_attr(attrs, "sAMAccountName", ""),
            dns_name=get_attr(attrs, "dNSHostName", ""),
            description=get_attr(attrs, "description", ""),
            enabled=not bool(uac & 0x0002),
            user_account_control=uac,
            operating_system=get_attr(attrs, "operatingSystem", ""),
            operating_system_version=get_attr(attrs, "operatingSystemVersion", ""),
            location=get_attr(attrs, "location", ""),
            managed_by=get_attr(attrs, "managedBy", ""),
            created_at=str(get_attr(attrs, "whenCreated", "")),
            modified_at=str(get_attr(attrs, "whenChanged", "")),
        )
        computers.append(comp)
    log.info("Extracted %d computers", len(computers))
    return computers
