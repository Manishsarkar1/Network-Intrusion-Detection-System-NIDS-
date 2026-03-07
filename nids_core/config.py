"""Core configuration constants and default detector settings."""

from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# Runtime artifacts
DB_PATH = str(DATA_DIR / "nids_alerts.db")
SETTINGS_PATH = str(DATA_DIR / "detection_settings.json")

# Static protocol ports
SSH_PORT = 22
VNC_PORTS = [5900, 5901, 5902, 5903]

# Default detection settings (editable in UI)
DEFAULT_DETECTION_SETTINGS = {
    "syn_window": 5.0,
    "syn_ports_threshold": 10,
    "flood_window": 5.0,
    "icmp_flood_threshold": 50,
    "udp_flood_threshold": 200,
    "ssh_failed_login_window": 60.0,
    "ssh_failed_login_threshold": 5,
    "vnc_failed_login_window": 60.0,
    "vnc_failed_login_threshold": 5,
    "alert_cooldown_seconds": 10.0,
}
