"""Custom JSON encoder for AD-Cain state files."""

from __future__ import annotations

import base64
import json
from datetime import datetime, date


class ADCainEncoder(json.JSONEncoder):
    """JSON encoder that handles bytes, datetime, and sets."""

    def default(self, obj):
        if isinstance(obj, bytes):
            return {"__bytes__": base64.b64encode(obj).decode("ascii")}
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        if isinstance(obj, set):
            return sorted(obj)
        return super().default(obj)


def decode_hook(obj: dict):
    """Object hook for json.loads to restore bytes from base64."""
    if "__bytes__" in obj:
        return base64.b64decode(obj["__bytes__"])
    return obj


def dumps(data, **kwargs) -> str:
    """Serialize to JSON with AD-Cain encoder."""
    kwargs.setdefault("indent", 2)
    kwargs.setdefault("cls", ADCainEncoder)
    return json.dumps(data, **kwargs)


def loads(text: str, **kwargs):
    """Deserialize JSON with AD-Cain decoder."""
    kwargs.setdefault("object_hook", decode_hook)
    return json.loads(text, **kwargs)
