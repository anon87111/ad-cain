"""Restore Group Policy Objects to a target DC and SYSVOL."""

from __future__ import annotations

import base64
from pathlib import Path

from ldap3 import Connection, MODIFY_REPLACE

from ad_cain.models.gpo import ADGPO
from ad_cain.logger import get_logger
from ad_cain.utils.dn_utils import rebase_dn

log = get_logger("restoration.gpos")


def restore_gpos(
    conn: Connection,
    base_dn: str,
    gpos: list[ADGPO],
    source_base_dn: str,
    sysvol_root: str | None = None,
) -> dict[str, str]:
    """Restore GPOs (GPC in LDAP + GPT files in SYSVOL). Returns {old_dn: new_dn}."""
    dn_map: dict[str, str] = {}
    policies_dn = f"CN=Policies,CN=System,{base_dn}"

    for gpo in gpos:
        guid = gpo.guid
        new_dn = f"CN={guid},{policies_dn}"

        attrs = {
            "objectClass": ["top", "container", "groupPolicyContainer"],
            "cn": guid,
            "displayName": gpo.display_name,
            "versionNumber": str(gpo.gpc_version),
            "flags": str(gpo.flags),
            "gPCFileSysPath": f"\\\\{base_dn.replace(',DC=', '.').replace('DC=', '')}\\SysVol\\{base_dn.replace(',DC=', '.').replace('DC=', '')}\\Policies\\{guid}",
        }

        try:
            conn.add(new_dn, attributes=attrs)
            if conn.result["result"] == 0:
                dn_map[gpo.distinguished_name] = new_dn
                log.info("Created GPO container: %s", new_dn)
            elif conn.result["result"] == 68:
                dn_map[gpo.distinguished_name] = new_dn
                log.warning("GPO already exists, skipping: %s", new_dn)
            else:
                log.error("Failed to create GPO %s: %s", new_dn, conn.result["description"])
                continue
        except Exception as exc:
            log.error("Error creating GPO %s: %s", new_dn, exc)
            continue

        # Write GPT files to SYSVOL
        if sysvol_root and gpo.gpt_content.files:
            _write_gpt_files(sysvol_root, guid, gpo)

        # Create GPO links
        for link in gpo.links:
            new_target = rebase_dn(link.target_dn, source_base_dn, base_dn)
            _create_gpo_link(conn, new_dn, new_target, link.enforced, link.enabled)

    log.info("Restored %d / %d GPOs", len(dn_map), len(gpos))
    return dn_map


def _write_gpt_files(sysvol_root: str, guid: str, gpo: ADGPO) -> None:
    """Write GPO template files to the SYSVOL directory."""
    guid_braced = guid if guid.startswith("{") else f"{{{guid}}}"
    gpt_base = Path(sysvol_root) / "Policies" / guid_braced

    for gpt_file in gpo.gpt_content.files:
        target = gpt_base / gpt_file.path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = base64.b64decode(gpt_file.content_base64)
            target.write_bytes(content)
            log.debug("Wrote GPT file: %s", target)
        except Exception as exc:
            log.warning("Failed to write GPT file %s: %s", target, exc)


def _create_gpo_link(
    conn: Connection,
    gpo_dn: str,
    target_dn: str,
    enforced: bool,
    enabled: bool,
) -> None:
    """Add a GPO link to a target OU or domain."""
    status = 0
    if not enabled:
        status = 1
    if enforced:
        status = 2

    link_entry = f"[LDAP://{gpo_dn};{status}]"

    # Read existing gPLink, append ours
    conn.search(
        search_base=target_dn,
        search_filter="(objectClass=*)",
        attributes=["gPLink"],
    )
    existing = ""
    if conn.entries:
        existing = str(conn.entries[0].entry_attributes_as_dict.get("gPLink", [""])[0] or "")

    new_gplink = existing + link_entry

    try:
        conn.modify(target_dn, {
            "gPLink": [(MODIFY_REPLACE, [new_gplink])]
        })
        if conn.result["result"] == 0:
            log.debug("Linked GPO to %s", target_dn)
        else:
            log.warning("Could not link GPO to %s: %s", target_dn, conn.result["description"])
    except Exception as exc:
        log.warning("Error linking GPO to %s: %s", target_dn, exc)
