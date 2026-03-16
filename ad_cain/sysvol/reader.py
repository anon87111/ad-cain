"""Read GPO template files from a SYSVOL share."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from ad_cain.models.gpo import GPTFile, GPTContent
from ad_cain.logger import get_logger

log = get_logger("sysvol.reader")


def read_gpt(sysvol_root: str, gpo_guid: str) -> GPTContent:
    """Read all GPT files for a given GPO GUID from SYSVOL.

    Args:
        sysvol_root: Root path of the SYSVOL share (e.g., /mnt/sysvol/domain).
        gpo_guid: GPO GUID string (with or without braces).

    Returns:
        GPTContent with files and version information.
    """
    guid = gpo_guid.strip("{}").upper()
    guid_braced = f"{{{guid}}}"
    base = Path(sysvol_root)

    candidates = [
        base / "Policies" / guid_braced,
        base / guid_braced,
    ]
    gpt_dir = next((c for c in candidates if c.is_dir()), None)

    content = GPTContent()
    if gpt_dir is None:
        log.warning("GPT directory not found for %s in %s", guid_braced, sysvol_root)
        return content

    files: list[GPTFile] = []
    for fpath in sorted(gpt_dir.rglob("*")):
        if not fpath.is_file():
            continue
        raw = fpath.read_bytes()
        rel = str(fpath.relative_to(gpt_dir))
        sha = hashlib.sha256(raw).hexdigest()
        files.append(GPTFile(
            path=rel,
            size=len(raw),
            checksum=f"sha256:{sha}",
            content_base64=base64.b64encode(raw).decode("ascii"),
        ))
    content.files = files

    # Parse GPT.INI for version
    gpt_ini = gpt_dir / "GPT.INI"
    if gpt_ini.is_file():
        import configparser
        cp = configparser.ConfigParser()
        cp.read(str(gpt_ini))
        ver = cp.getint("General", "Version", fallback=0)
        content.user_version = ver >> 16
        content.machine_version = ver & 0xFFFF

    log.info("Read %d files for GPO %s", len(files), guid_braced)
    return content
