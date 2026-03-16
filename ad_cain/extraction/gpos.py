"""Extract Group Policy Objects from Active Directory and SYSVOL."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from ldap3 import Connection, SUBTREE

from ad_cain.models.gpo import ADGPO, GPOLink, GPTFile, GPTContent
from ad_cain.logger import get_logger
from ad_cain.utils.ldap_utils import get_attr, get_attr_list

log = get_logger("extraction.gpos")

GPC_ATTRS = [
    "distinguishedName", "displayName", "name", "gPCFileSysPath",
    "versionNumber", "flags", "whenCreated", "whenChanged",
]


def _parse_gplink(gplink_str: str) -> list[dict]:
    """Parse the gPLink attribute string into structured links.

    Format: [LDAP://CN={GUID},...;status][LDAP://...;status]
    Status: 0=enabled, 1=disabled, 2=enforced
    """
    links = []
    if not gplink_str:
        return links
    import re
    for match in re.finditer(r"\[LDAP://([^;]+);(\d+)\]", gplink_str, re.IGNORECASE):
        dn = match.group(1)
        status = int(match.group(2))
        links.append({
            "dn": dn,
            "enabled": status != 1,
            "enforced": status == 2,
        })
    return links


def _read_gpt_files(sysvol_root: str, gpo_guid: str) -> GPTContent:
    """Read all GPT files for a GPO from SYSVOL."""
    # Normalise GUID format: {XXXXXXXX-...}
    guid = gpo_guid.strip("{}").upper()
    guid_braced = f"{{{guid}}}"
    gpt_base = Path(sysvol_root)

    # Try common SYSVOL layouts
    candidates = [
        gpt_base / "Policies" / guid_braced,
        gpt_base / guid_braced,
    ]
    gpt_path = None
    for c in candidates:
        if c.is_dir():
            gpt_path = c
            break

    content = GPTContent()
    if gpt_path is None:
        log.warning("GPT directory not found for %s", guid_braced)
        return content

    files: list[GPTFile] = []
    for fpath in gpt_path.rglob("*"):
        if fpath.is_file():
            raw = fpath.read_bytes()
            rel = str(fpath.relative_to(gpt_path))
            sha = hashlib.sha256(raw).hexdigest()
            files.append(GPTFile(
                path=rel,
                size=len(raw),
                checksum=f"sha256:{sha}",
                content_base64=base64.b64encode(raw).decode("ascii"),
            ))
    content.files = files

    # Try to read GPT.INI for version info
    gpt_ini = gpt_path / "GPT.INI"
    if gpt_ini.is_file():
        import configparser
        cp = configparser.ConfigParser()
        cp.read(str(gpt_ini))
        ver = cp.getint("General", "Version", fallback=0)
        content.user_version = ver >> 16
        content.machine_version = ver & 0xFFFF

    return content


def extract_all_gpos(
    conn: Connection,
    base_dn: str,
    sysvol_root: str | None = None,
) -> list[ADGPO]:
    """Extract all GPOs from LDAP and optionally SYSVOL."""
    log.info("Extracting GPOs from %s", base_dn)
    policies_dn = f"CN=Policies,CN=System,{base_dn}"
    conn.search(
        search_base=policies_dn,
        search_filter="(objectClass=groupPolicyContainer)",
        search_scope=SUBTREE,
        attributes=GPC_ATTRS,
        paged_size=1000,
    )

    # Collect raw GPO containers
    raw_gpos: list[dict] = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        raw_gpos.append({
            "dn": str(entry.entry_dn),
            "display_name": get_attr(attrs, "displayName", ""),
            "guid": get_attr(attrs, "name", ""),
            "version": int(get_attr(attrs, "versionNumber", 0)),
            "flags": int(get_attr(attrs, "flags", 0)),
            "created_at": str(get_attr(attrs, "whenCreated", "")),
            "modified_at": str(get_attr(attrs, "whenChanged", "")),
        })

    # Collect GPO links from domain and OUs
    gpo_links: dict[str, list[GPOLink]] = {}
    link_targets = [base_dn]
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=organizationalUnit)",
        search_scope=SUBTREE,
        attributes=["distinguishedName", "gPLink"],
        paged_size=1000,
    )
    for entry in conn.entries:
        link_targets.append(str(entry.entry_dn))

    # Also read gPLink from domain root
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=domainDNS)",
        attributes=["gPLink"],
    )
    for target_dn in link_targets:
        conn.search(
            search_base=target_dn,
            search_filter="(objectClass=*)",
            attributes=["gPLink"],
        )
        if conn.entries:
            gplink_raw = get_attr(
                conn.entries[0].entry_attributes_as_dict, "gPLink", ""
            )
            for link in _parse_gplink(gplink_raw or ""):
                gpo_dn = link["dn"]
                if gpo_dn not in gpo_links:
                    gpo_links[gpo_dn] = []
                gpo_links[gpo_dn].append(GPOLink(
                    target_dn=target_dn,
                    enforced=link["enforced"],
                    enabled=link["enabled"],
                ))

    # Build ADGPO objects
    gpos: list[ADGPO] = []
    for raw in raw_gpos:
        guid = raw["guid"]
        links = gpo_links.get(raw["dn"], [])
        gpt = GPTContent()
        if sysvol_root:
            gpt = _read_gpt_files(sysvol_root, guid)

        ver = raw["version"]
        gpo = ADGPO(
            display_name=raw["display_name"],
            guid=guid,
            distinguished_name=raw["dn"],
            gpc_version=ver,
            gpt_version=(gpt.user_version << 16) | gpt.machine_version,
            flags=raw["flags"],
            links=links,
            gpt_content=gpt,
            created_at=raw["created_at"],
            modified_at=raw["modified_at"],
        )
        gpos.append(gpo)

    log.info("Extracted %d GPOs", len(gpos))
    return gpos
