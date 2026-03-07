"""Persistent detection settings helpers."""

import json
from copy import deepcopy
from pathlib import Path

from nids_core.config import DEFAULT_DETECTION_SETTINGS, SETTINGS_PATH

FLOAT_KEYS = {
    "syn_window",
    "flood_window",
    "ssh_failed_login_window",
    "vnc_failed_login_window",
    "alert_cooldown_seconds",
}

INT_KEYS = {
    "syn_ports_threshold",
    "icmp_flood_threshold",
    "udp_flood_threshold",
    "ssh_failed_login_threshold",
    "vnc_failed_login_threshold",
}


def default_settings():
    return deepcopy(DEFAULT_DETECTION_SETTINGS)


def validate_settings(raw_settings):
    validated = default_settings()

    for key in FLOAT_KEYS:
        if key in raw_settings:
            value = float(raw_settings[key])
            if value <= 0:
                raise ValueError(f"{key} must be greater than 0")
            validated[key] = value

    for key in INT_KEYS:
        if key in raw_settings:
            value = int(raw_settings[key])
            if value < 1:
                raise ValueError(f"{key} must be at least 1")
            validated[key] = value

    return validated


def load_settings(path=SETTINGS_PATH):
    file_path = Path(path)
    if not file_path.exists():
        return default_settings()

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return default_settings()

    if not isinstance(payload, dict):
        return default_settings()

    try:
        return validate_settings(payload)
    except Exception:
        return default_settings()


def save_settings(settings, path=SETTINGS_PATH):
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    validated = validate_settings(settings)
    file_path.write_text(json.dumps(validated, indent=2), encoding="utf-8")
    return validated
