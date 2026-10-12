"""Server-side filters for the operational installer-build history."""
from __future__ import annotations

from typing import Any


INSTALLER_HISTORY_FILTERS = frozenset({"all", "ready", "active", "failed", "attention"})
INSTALLER_HISTORY_SORTS = frozenset({"created_desc", "target", "status", "version", "requester"})


def installer_history_bucket(row: dict[str, Any]) -> str:
    """Map implementation statuses to the concise choices shown to operators."""
    status = str(row.get("status") or "").upper()
    if status == "READY":
        return "ready"
    if status in {"QUEUED", "BUILDING"}:
        return "active"
    if status in {"FAILED", "INTERRUPTED"}:
        return "failed"
    return "attention"


def filter_installer_history(
    rows: list[dict[str, Any]], *, query: str = "", status: str = "all", sort: str = "created_desc"
) -> tuple[list[dict[str, Any]], str, str, str]:
    """Return a display-safe, server-filtered installer history.

    The browser only remembers the friendly query controls. Filtering and
    ordering happen here so a shared URL and a direct page reload produce the
    same operational list without exposing technical identifiers by default.
    """
    clean_query = " ".join(str(query or "").split())[:160]
    clean_status = str(status or "all").strip().lower()
    clean_sort = str(sort or "created_desc").strip().lower()
    if clean_status not in INSTALLER_HISTORY_FILTERS:
        clean_status = "all"
    if clean_sort not in INSTALLER_HISTORY_SORTS:
        clean_sort = "created_desc"

    query_tokens = tuple(token.casefold() for token in clean_query.split())
    visible: list[dict[str, Any]] = []
    searchable_fields = (
        "target_id", "artifact_name", "package_type", "display_version", "version",
        "requested_by", "os_family", "os_variant", "builder_profile", "gateway_mode",
        "channel", "status",
    )
    for source in rows:
        row = dict(source)
        if clean_status != "all" and installer_history_bucket(row) != clean_status:
            continue
        if query_tokens:
            searchable = " ".join(str(row.get(field) or "") for field in searchable_fields).casefold()
            if not all(token in searchable for token in query_tokens):
                continue
        visible.append(row)

    def text_value(row: dict[str, Any], field: str) -> str:
        return str(row.get(field) or "").casefold()

    def created_value(row: dict[str, Any]) -> str:
        return str(row.get("created_at") or row.get("finished_at") or "")

    # First establish a deterministic newest-first tie-breaker. Python's
    # stable sort then keeps it within each human-friendly sort grouping.
    visible.sort(key=lambda row: (created_value(row), text_value(row, "build_id")), reverse=True)
    if clean_sort == "target":
        visible.sort(key=lambda row: (text_value(row, "target_id"), text_value(row, "os_variant")))
    elif clean_sort == "status":
        status_order = {"active": 0, "attention": 1, "failed": 2, "ready": 3}
        visible.sort(key=lambda row: status_order[installer_history_bucket(row)])
    elif clean_sort == "version":
        visible.sort(key=lambda row: (text_value(row, "display_version"), text_value(row, "version")))
    elif clean_sort == "requester":
        visible.sort(key=lambda row: text_value(row, "requested_by"))
    return visible, clean_query, clean_status, clean_sort
