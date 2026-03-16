"""Write GPO template files to a SYSVOL share."""

from __future__ import annotations

import base64
from pathlib import Path

from ad_cain.models.gpo import ADGPO
from ad_cain.logger import get_logger

log = get_logger("sysvol.writer")


def write_gpt(sysvol_root: str, gpo: ADGPO) -> int:
    """Write all GPT files for a GPO to SYSVOL.

    Args:
        sysvol_root: Root path of the SYSVOL share.
        gpo: ADGPO model containing gpt_content with files.

    Returns:
        Number of files written.
    """
    guid = gpo.guid.strip("{}").upper()
    guid_braced = f"{{{guid}}}"
    gpt_base = Path(sysvol_root) / "Policies" / guid_braced

    written = 0
    for gpt_file in gpo.gpt_content.files:
        target = gpt_base / gpt_file.path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = base64.b64decode(gpt_file.content_base64)
            target.write_bytes(content)
            written += 1
            log.debug("Wrote: %s", target)
        except Exception as exc:
            log.warning("Failed to write %s: %s", target, exc)

    log.info("Wrote %d / %d files for GPO %s", written, len(gpo.gpt_content.files), guid_braced)
    return written
