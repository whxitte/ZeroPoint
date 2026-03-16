"""
ZeroPoint :: db/__init__.py
===========================
Re-exports everything from db.mongo so callers can simply `import db`
and call db.ensure_indexes(), db.upsert_program(), etc.
"""

from db.mongo import (
    ensure_indexes,
    upsert_program,
    get_program,
    list_active_programs,
    upsert_asset,
    bulk_upsert_assets,
    get_new_assets_since,
    count_assets_for_program,
    close_connection,
    get_assets_to_probe,
    update_probe_result,
    get_high_value_assets,
    get_probe_stats,
)

__all__ = [
    "ensure_indexes",
    "upsert_program",
    "get_program",
    "list_active_programs",
    "upsert_asset",
    "bulk_upsert_assets",
    "get_new_assets_since",
    "count_assets_for_program",
    "close_connection",
    "get_assets_to_probe",
    "update_probe_result",
    "get_high_value_assets",
    "get_probe_stats",
]
