"""LDAP attribute conversion utilities."""

from __future__ import annotations

from datetime import datetime, timezone

# Windows FILETIME epoch offset (ticks between 1601-01-01 and 1970-01-01)
_FILETIME_EPOCH_DIFF = 116_444_736_000_000_000
_TICKS_PER_SECOND = 10_000_000


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME (100-ns ticks since 1601) to datetime."""
    if filetime <= 0 or filetime == 0x7FFFFFFFFFFFFFFF:
        return None
    unix_ts = (filetime - _FILETIME_EPOCH_DIFF) / _TICKS_PER_SECOND
    try:
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, ValueError):
        return None


def datetime_to_filetime(dt: datetime) -> int:
    """Convert datetime to Windows FILETIME."""
    unix_ts = dt.timestamp()
    return int(unix_ts * _TICKS_PER_SECOND + _FILETIME_EPOCH_DIFF)


def uac_flags(uac_value: int) -> dict[str, bool]:
    """Decode userAccountControl bitmask into readable flags."""
    flags = {
        "ACCOUNT_DISABLED": bool(uac_value & 0x0002),
        "HOMEDIR_REQUIRED": bool(uac_value & 0x0008),
        "LOCKOUT": bool(uac_value & 0x0010),
        "PASSWD_NOTREQD": bool(uac_value & 0x0020),
        "PASSWD_CANT_CHANGE": bool(uac_value & 0x0040),
        "NORMAL_ACCOUNT": bool(uac_value & 0x0200),
        "WORKSTATION_TRUST": bool(uac_value & 0x1000),
        "SERVER_TRUST": bool(uac_value & 0x2000),
        "DONT_EXPIRE_PASSWD": bool(uac_value & 0x10000),
        "SMARTCARD_REQUIRED": bool(uac_value & 0x40000),
        "TRUSTED_FOR_DELEGATION": bool(uac_value & 0x80000),
        "NOT_DELEGATED": bool(uac_value & 0x100000),
        "USE_DES_KEY_ONLY": bool(uac_value & 0x200000),
        "PREAUTH_NOT_REQUIRED": bool(uac_value & 0x400000),
        "PASSWORD_EXPIRED": bool(uac_value & 0x800000),
    }
    return flags


def to_datetime(val) -> datetime | None:
    """Coerce an LDAP time value to datetime.

    ldap3 may return datetime objects, FILETIME ints, or strings
    depending on server schema and connection settings.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    try:
        ival = int(val)
        return filetime_to_datetime(ival)
    except (TypeError, ValueError):
        pass
    if isinstance(val, str) and val:
        try:
            return datetime.fromisoformat(val)
        except ValueError:
            pass
    return None


def get_attr(entry: dict, name: str, default=None):
    """Safely extract a single-value attribute from an LDAP entry."""
    val = entry.get(name)
    if val is None:
        return default
    if isinstance(val, list):
        return val[0] if val else default
    return val


def get_attr_list(entry: dict, name: str) -> list:
    """Safely extract a multi-value attribute as a list."""
    val = entry.get(name)
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]
