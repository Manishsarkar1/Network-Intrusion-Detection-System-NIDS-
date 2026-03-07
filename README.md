# Network Intrusion Detection System (NIDS)

A Python-based GUI network intrusion detection project using Scapy and CustomTkinter.

## Organized Project Layout

- `main.py`: Root launcher for the NIDS application.
- `nids_core/`: Core detection and GUI modules.
- `scripts/`: Traffic/testing helper scripts.
- `docs/`: Supporting documentation and notes.
- `data/`: Runtime artifacts (SQLite alerts DB).

## Run

1. Install dependencies:
   `pip install -r requirements.txt`
2. Run with admin/root privileges:
   `python main.py`

## Notes

- Alerts are stored in `data/nids_alerts.db`.
- Windows users need Npcap installed.
- Testing helpers are in `scripts/test_ids.py` and `scripts/run_test_admin.bat`.
