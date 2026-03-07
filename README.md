# Network Intrusion Detection System (NIDS)

A Python GUI NIDS project built with Scapy + CustomTkinter.

## What Was Enhanced

- Live runtime stats in monitor window:
  - Packet rate (packets/second)
  - Session uptime timer
- Capture filter presets:
  - All, TCP, UDP, ICMP, ARP
- Export alerts to CSV from the UI
- Better runtime stability:
  - Non-blocking sniff loop (`timeout=1`) for faster stop response
  - Graceful detector thread shutdown on window close
  - Auto fallback to unfiltered sniff if BPF filtering is unavailable
- Cleaner repo hygiene:
  - Ignore local virtualenv and generated runtime files

## Project Layout

- `main.py`: Root launcher
- `nids_core/`: Core GUI + detector modules
- `scripts/`: Test/helper scripts
- `docs/`: Notes and extended docs
- `data/`: Runtime database and exports

## Run

1. Install dependencies:
   `pip install -r requirements.txt`
2. Run with admin/root privileges:
   `python main.py`

## Notes

- Alerts DB: `data/nids_alerts.db`
- Exported CSV files default to `data/`
- Windows users need Npcap installed
