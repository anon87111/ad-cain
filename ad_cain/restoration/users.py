"""Restore User objects to a target DC."""

from __future__ import annotations

from ldap3 import Connection, MODIFY_REPLACE

from ad_cain.models.user import ADUser
from ad_cain.logger import get_logger
from ad_cain.utils.dn_utils import rebase_dn, parent_dn, rdn_value

log = get_logger("restoration.users")


def restore_users(
    conn: Connection,
    base_dn: str,
    users: list[ADUser],
    source_base_dn: str,
    default_password: str = "ChangeMe123!",
) -> dict[str, str]:
    """Create user accounts. Returns {old_dn: new_dn} mapping."""
    dn_map: dict[str, str] = {}

    for user in users:
        new_dn = rebase_dn(user.distinguished_name, source_base_dn, base_dn)
        cn = rdn_value(user.distinguished_name)

        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": cn,
            "sAMAccountName": user.sam_account_name,
        }
        if user.user_principal_name:
            attrs["userPrincipalName"] = user.user_principal_name
        if user.first_name:
            attrs["givenName"] = user.first_name
        if user.last_name:
            attrs["sn"] = user.last_name
        if user.display_name:
            attrs["displayName"] = user.display_name
        if user.email:
            attrs["mail"] = user.email
        if user.description:
            attrs["description"] = user.description
        if user.telephone:
            attrs["telephoneNumber"] = user.telephone
        if user.department:
            attrs["department"] = user.department
        if user.company:
            attrs["company"] = user.company
        if user.title:
            attrs["title"] = user.title
        if user.office:
            attrs["physicalDeliveryOfficeName"] = user.office

        # Set UAC to normal account + disabled (we enable after setting password)
        attrs["userAccountControl"] = "514"

        try:
            conn.add(new_dn, attributes=attrs)
            if conn.result["result"] == 0:
                dn_map[user.distinguished_name] = new_dn
                log.info("Created user: %s", new_dn)

                # Attempt to set password and enable
                _set_password_and_enable(conn, new_dn, default_password, user)
            elif conn.result["result"] == 68:
                dn_map[user.distinguished_name] = new_dn
                log.warning("User already exists, skipping: %s", new_dn)
            else:
                log.error("Failed to create user %s: %s", new_dn, conn.result["description"])
        except Exception as exc:
            if "entryAlreadyExists" in str(exc):
                dn_map[user.distinguished_name] = new_dn
                log.warning("User already exists, skipping: %s", new_dn)
            else:
                log.error("Error creating user %s: %s", new_dn, exc)

    log.info("Restored %d / %d users", len(dn_map), len(users))
    return dn_map


def _set_password_and_enable(
    conn: Connection,
    user_dn: str,
    password: str,
    user: ADUser,
) -> None:
    """Set password and optionally enable the account."""
    try:
        # AD requires the password as a UTF-16LE encoded, quoted string
        encoded_pw = f'"{password}"'.encode("utf-16-le")
        conn.modify(user_dn, {"unicodePwd": [(MODIFY_REPLACE, [encoded_pw])]})
        if conn.result["result"] != 0:
            log.warning("Could not set password for %s (requires LDAPS): %s",
                        user_dn, conn.result["description"])
            return

        # Enable account if it was enabled in source
        if user.enabled:
            uac = str(user.user_account_control & ~0x0002)  # clear disabled bit
            conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]})
    except Exception as exc:
        log.warning("Password/enable failed for %s: %s", user_dn, exc)
