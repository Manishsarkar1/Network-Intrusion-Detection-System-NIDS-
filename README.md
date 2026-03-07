# Network Intrusion Detection System (NIDS)

A Python GUI NIDS + packet analyzer built with Scapy and CustomTkinter.

## Analyzer Features (Wireshark-style controls)

- Packet list table with columns:
  - No, Time, Source, Destination, Protocol, Length, Info
- Protocol decode + raw hex pane on packet click
- Capture filter (BPF) input + quick presets
- Display filtering:
  - Per-protocol toggles (TCP/UDP/ICMP/ARP/OTHER/ALERT)
  - Live search across src/dst/proto/info
  - Adjustable max visible rows
- Capture controls:
  - Start/Stop
  - Pause/Resume display
  - Clear
  - Save capture to PCAP
- IDS features integrated in same window:
  - Live alerts injected into packet table
  - Alert history viewer
  - Export alerts CSV
  - Detection settings editor (apply/save/reset)

## Project Layout

- `main.py`: Root launcher
- `nids_core/`: Core GUI + detector modules
- `scripts/`: Test/helper scripts
- `docs/`: Notes and extended docs
- `data/`: Runtime database, settings, and exports

## Run

1. Install dependencies:
   `pip install -r requirements.txt`
2. Run with admin/root privileges:
   `python main.py`

## Notes

- Alerts DB: `data/nids_alerts.db`
- User settings: `data/detection_settings.json`
- Exports default to `data/`
- Windows users need Npcap installed
