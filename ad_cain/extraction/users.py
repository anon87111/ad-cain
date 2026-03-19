"""Extract User objects from Active Directory."""

from __future__ import annotations

from ldap3 import Connection, SUBTREE

from ad_cain.models.user import ADUser, PasswordPolicy
from ad_cain.logger import get_logger
from ad_cain.utils.ldap_utils import get_attr, get_attr_list, to_datetime

log = get_logger("extraction.users")

USER_ATTRS = [
    "distinguishedName", "sAMAccountName", "userPrincipalName",
    "givenName", "sn", "displayName", "mail", "description",
    "userAccountControl", "pwdLastSet", "accountExpires",
    "memberOf", "manager", "telephoneNumber", "department",
    "company", "title", "physicalDeliveryOfficeName",
    "whenCreated", "whenChanged",
]


def extract_all_users(conn: Connection, base_dn: str) -> list[ADUser]:
    """Search and return all domain users."""
    log.info("Extracting users from %s", base_dn)
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        search_scope=SUBTREE,
        attributes=USER_ATTRS,
        paged_size=1000,
    )
    users: list[ADUser] = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        dn = str(entry.entry_dn)

        uac = int(get_attr(attrs, "userAccountControl", 512))
        enabled = not bool(uac & 0x0002)

        pwd_last_set = get_attr(attrs, "pwdLastSet", None)
        pwd_dt = to_datetime(pwd_last_set)
        acct_expires_raw = get_attr(attrs, "accountExpires", None)
        acct_expires_dt = to_datetime(acct_expires_raw)

        user = ADUser(
            distinguished_name=dn,
            sam_account_name=get_attr(attrs, "sAMAccountName", ""),
            user_principal_name=get_attr(attrs, "userPrincipalName", ""),
            first_name=get_attr(attrs, "givenName", ""),
            last_name=get_attr(attrs, "sn", ""),
            display_name=get_attr(attrs, "displayName", ""),
            email=get_attr(attrs, "mail", ""),
            description=get_attr(attrs, "description", ""),
            enabled=enabled,
            user_account_control=uac,
            password_policy=PasswordPolicy(
                last_set=pwd_dt.isoformat() if pwd_dt else "",
                never_expires=bool(uac & 0x10000),
                must_change_at_logon=(pwd_last_set == 0 or pwd_last_set is None),
                account_expires=acct_expires_dt.isoformat() if acct_expires_dt else None,
            ),
            group_memberships=get_attr_list(attrs, "memberOf"),
            manager=get_attr(attrs, "manager", ""),
            telephone=get_attr(attrs, "telephoneNumber", ""),
            department=get_attr(attrs, "department", ""),
            company=get_attr(attrs, "company", ""),
            title=get_attr(attrs, "title", ""),
            office=get_attr(attrs, "physicalDeliveryOfficeName", ""),
            created_at=str(get_attr(attrs, "whenCreated", "")),
            modified_at=str(get_attr(attrs, "whenChanged", "")),
        )
        users.append(user)
    log.info("Extracted %d users", len(users))
    return users
