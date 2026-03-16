"""Distinguished Name parsing and manipulation utilities."""

from __future__ import annotations

import re


def parse_dn(dn: str) -> list[tuple[str, str]]:
    """Parse a DN into a list of (attribute, value) tuples.

    Example:
        >>> parse_dn("CN=John,OU=Users,DC=lab,DC=example,DC=com")
        [('CN', 'John'), ('OU', 'Users'), ('DC', 'lab'), ('DC', 'example'), ('DC', 'com')]
    """
    components: list[tuple[str, str]] = []
    for part in _split_dn(dn):
        attr, _, value = part.partition("=")
        components.append((attr.strip().upper(), value.strip()))
    return components


def parent_dn(dn: str) -> str:
    """Return the parent DN (strip the first component).

    Example:
        >>> parent_dn("CN=John,OU=Users,DC=lab,DC=example,DC=com")
        'OU=Users,DC=lab,DC=example,DC=com'
    """
    parts = _split_dn(dn)
    if len(parts) <= 1:
        return ""
    return ",".join(parts[1:])


def dn_depth(dn: str) -> int:
    """Return the depth of a DN (number of components)."""
    return len(_split_dn(dn))


def rdn(dn: str) -> str:
    """Return the Relative DN (first component)."""
    parts = _split_dn(dn)
    return parts[0] if parts else ""


def rdn_value(dn: str) -> str:
    """Return just the value of the RDN."""
    first = rdn(dn)
    _, _, value = first.partition("=")
    return value.strip()


def domain_from_dn(dn: str) -> str:
    """Extract the domain name from DC components.

    Example:
        >>> domain_from_dn("CN=John,OU=Users,DC=lab,DC=example,DC=com")
        'lab.example.com'
    """
    components = parse_dn(dn)
    dc_parts = [v for attr, v in components if attr == "DC"]
    return ".".join(dc_parts)


def rebase_dn(dn: str, old_base: str, new_base: str) -> str:
    """Replace the base portion of a DN with a new base.

    Useful when importing objects into a different domain.
    """
    if dn.lower().endswith(old_base.lower()):
        relative = dn[: len(dn) - len(old_base)].rstrip(",")
        return f"{relative},{new_base}" if relative else new_base
    return dn


def _split_dn(dn: str) -> list[str]:
    """Split a DN respecting escaped commas."""
    return re.split(r"(?<!\\),", dn)
