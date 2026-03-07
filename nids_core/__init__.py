"""NIDS core package."""

from nids_core.config import DEFAULT_DETECTION_SETTINGS, DB_PATH, SETTINGS_PATH

__all__ = [
    "DB_PATH",
    "SETTINGS_PATH",
    "DEFAULT_DETECTION_SETTINGS",
]
