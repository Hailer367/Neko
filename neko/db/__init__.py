"""
NekoDB - GitHub-backed Persistent Storage for Neko.

This package provides comprehensive data persistence capabilities:
- Artifact storage (exploits, scripts, knowledge, tools)
- Target tracking and session management
- Search and retrieval

Based on StrixDB with Neko-specific enhancements.
"""

from .nekodb import NekoDB

# Import all actions from nekodb_actions
from .nekodb_actions import (
    # Core NekoDB operations
    nekodb_save,
    nekodb_get,
    nekodb_search,
    nekodb_list,
    nekodb_delete,
    nekodb_get_categories,
    nekodb_get_config_status,
    # Target tracking
    nekodb_target_init,
    nekodb_target_session_start,
    nekodb_target_session_end,
    nekodb_target_add_finding,
)

__all__ = [
    # Class
    "NekoDB",
    # Core operations
    "nekodb_save",
    "nekodb_get",
    "nekodb_search",
    "nekodb_list",
    "nekodb_delete",
    "nekodb_get_categories",
    "nekodb_get_config_status",
    # Target tracking
    "nekodb_target_init",
    "nekodb_target_session_start",
    "nekodb_target_session_end",
    "nekodb_target_add_finding",
]
