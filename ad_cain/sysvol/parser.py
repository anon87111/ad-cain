"""Parse GPO policy files (INI, XML) for inspection."""

from __future__ import annotations

import configparser
from io import StringIO

from ad_cain.logger import get_logger

log = get_logger("sysvol.parser")


def parse_gpt_ini(content: str) -> dict:
    """Parse a GPT.INI file and return General section values."""
    cp = configparser.ConfigParser()
    cp.read_string(content)
    result = {}
    if cp.has_section("General"):
        for key, val in cp.items("General"):
            result[key] = val
    return result


def parse_registry_pol(data: bytes) -> list[dict]:
    """Parse a Registry.pol binary file into registry entries.

    Registry.pol format: header (PReg\x01\x00\x00\x00) followed by
    [key;value;type;size;data] entries in UTF-16LE.
    """
    entries: list[dict] = []
    if len(data) < 8:
        return entries

    # Verify header
    header = data[:4]
    if header != b"PReg":
        log.warning("Invalid Registry.pol header: %r", header)
        return entries

    # Parse entries between [ and ] delimiters
    pos = 8
    text = data[8:]
    try:
        decoded = text.decode("utf-16-le", errors="replace")
    except Exception:
        return entries

    for block in decoded.split("["):
        block = block.strip().rstrip("]")
        if not block:
            continue
        parts = block.split(";")
        if len(parts) >= 2:
            entries.append({
                "key": parts[0],
                "value": parts[1] if len(parts) > 1 else "",
                "raw_parts": parts,
            })

    return entries
