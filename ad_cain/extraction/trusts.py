"""Extract Domain Trust relationships from Active Directory."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE

from ad_cain.models.trust import ADTrust
from ad_cain.logger import get_logger
from ad_cain.utils.ldap_utils import get_attr

log = get_logger("extraction.trusts")

TRUST_ATTRS = [
    "distinguishedName", "trustPartner", "trustDirection", "trustType",
    "trustAttributes", "flatName", "whenCreated",
]

_TRUST_DIRECTION = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

_TRUST_TYPE = {
    1: "Downlevel",
    2: "Uplevel",
    3: "MIT",
    4: "DCE",
}


def extract_all_trusts(conn: Connection, base_dn: str) -> list[ADTrust]:
    """Search and return all domain trust objects."""
    log.info("Extracting trusts from %s", base_dn)
    search_base = f"CN=System,{base_dn}"
    conn.search(
        search_base=search_base,
        search_filter="(objectClass=trustedDomain)",
        search_scope=SUBTREE,
        attributes=TRUST_ATTRS,
        paged_size=1000,
    )
    trusts: list[ADTrust] = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        direction_val = int(get_attr(attrs, "trustDirection", 0))
        type_val = int(get_attr(attrs, "trustType", 2))
        trust_attrs = int(get_attr(attrs, "trustAttributes", 0))

        trust = ADTrust(
            trusted_domain=get_attr(attrs, "trustPartner", ""),
            trust_direction=_TRUST_DIRECTION.get(direction_val, "Unknown"),
            trust_type=_TRUST_TYPE.get(type_val, "Unknown"),
            transitive=bool(trust_attrs & 0x00000001),
            selective_authentication=bool(trust_attrs & 0x00000020),
            sid_filtering=not bool(trust_attrs & 0x00000004),
            flat_name=get_attr(attrs, "flatName", ""),
            trust_attributes=trust_attrs,
            created_at=str(get_attr(attrs, "whenCreated", "")),
        )
        trusts.append(trust)
    log.info("Extracted %d trusts", len(trusts))
    return trusts
