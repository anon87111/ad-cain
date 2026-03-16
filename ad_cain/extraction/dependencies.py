"""Dependency resolution and ordering for AD objects."""

from __future__ import annotations

from ad_cain.models.state import StateContainer
from ad_cain.logger import get_logger
from ad_cain.utils.dn_utils import dn_depth

log = get_logger("extraction.dependencies")


CREATION_ORDER = ["ous", "users", "computers", "groups", "gpos", "trusts"]


def sort_ous_by_depth(state: StateContainer) -> None:
    """Sort OUs in-place so parents come before children."""
    state.ous.sort(key=lambda o: dn_depth(o.distinguished_name))


def detect_circular_groups(state: StateContainer) -> list[list[str]]:
    """Detect circular group memberships. Returns list of cycles."""
    membership: dict[str, set[str]] = {}
    for grp in state.groups:
        membership[grp.distinguished_name] = {
            m.distinguished_name for m in grp.members if m.member_type == "group"
        }

    cycles: list[list[str]] = []
    visited: set[str] = set()

    def dfs(node: str, path: list[str], on_stack: set[str]):
        if node in on_stack:
            cycle_start = path.index(node)
            cycles.append(path[cycle_start:] + [node])
            return
        if node in visited:
            return
        visited.add(node)
        on_stack.add(node)
        path.append(node)
        for child in membership.get(node, set()):
            dfs(child, path, on_stack)
        path.pop()
        on_stack.discard(node)

    for group_dn in membership:
        if group_dn not in visited:
            dfs(group_dn, [], set())

    if cycles:
        log.warning("Detected %d circular group membership(s)", len(cycles))
    return cycles


def validate_dependencies(state: StateContainer) -> list[str]:
    """Run dependency checks and return a list of warnings."""
    warnings: list[str] = []
    sort_ous_by_depth(state)
    cycles = detect_circular_groups(state)
    for cycle in cycles:
        warnings.append(f"Circular group membership: {' -> '.join(cycle)}")
    return warnings
