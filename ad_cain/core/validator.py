"""Validate AD-Cain state files against the expected schema."""

from __future__ import annotations

from pathlib import Path

from ad_cain.models.state import StateContainer
from ad_cain.logger import get_logger
from ad_cain.utils.errors import SchemaValidationError

log = get_logger("validator")

REQUIRED_TOP_KEYS = {"version", "timestamp", "source_domain", "ous", "users", "groups", "computers"}


def validate_state_file(path: str | Path) -> StateContainer:
    """Load and validate a state file. Returns the StateContainer on success."""
    path = Path(path)

    if not path.exists():
        raise SchemaValidationError(f"State file not found: {path}")

    if not path.suffix == ".json":
        log.warning("State file does not have .json extension: %s", path.name)

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise SchemaValidationError("State file is empty.")

    # Attempt Pydantic validation
    errors: list[str] = []
    try:
        import json
        raw = json.loads(text)
    except Exception as exc:
        raise SchemaValidationError(f"Invalid JSON: {exc}") from exc

    # Check required keys
    missing = REQUIRED_TOP_KEYS - set(raw.keys())
    if missing:
        errors.append(f"Missing required keys: {', '.join(sorted(missing))}")

    # Check version
    version = raw.get("version", "")
    if version not in ("1.0",):
        errors.append(f"Unsupported state file version: {version!r}")

    # Validate with Pydantic
    try:
        state = StateContainer.from_json(text)
    except Exception as exc:
        errors.append(f"Model validation failed: {exc}")
        raise SchemaValidationError(
            "State file failed validation.",
            validation_errors=errors,
        ) from exc

    if errors:
        raise SchemaValidationError(
            "State file has validation warnings.",
            validation_errors=errors,
        )

    # Cross-reference checks
    warnings = _cross_reference_check(state)
    if warnings:
        for w in warnings:
            log.warning(w)

    log.info("State file is valid: %s", path.name)
    return state


def _cross_reference_check(state: StateContainer) -> list[str]:
    """Check for dangling references between objects."""
    warnings: list[str] = []
    all_dns = set()

    for ou in state.ous:
        all_dns.add(ou.distinguished_name)
    for user in state.users:
        all_dns.add(user.distinguished_name)
    for comp in state.computers:
        all_dns.add(comp.distinguished_name)
    for grp in state.groups:
        all_dns.add(grp.distinguished_name)

    # Check group member references
    for grp in state.groups:
        for member in grp.members:
            if member.distinguished_name not in all_dns:
                warnings.append(
                    f"Group '{grp.sam_account_name}' references unknown member: "
                    f"{member.distinguished_name}"
                )

    # Check user manager references
    for user in state.users:
        if user.manager and user.manager not in all_dns:
            warnings.append(
                f"User '{user.sam_account_name}' references unknown manager: {user.manager}"
            )

    return warnings
