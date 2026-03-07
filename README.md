# Network Intrusion Detection System (NIDS)

A Python GUI NIDS + packet analyzer built with Scapy and CustomTkinter.

## Look and Feel

This project now uses a custom dark "NIDS Studio" layout (not a Wireshark-style table clone):

- Left: live traffic rail with protocol-colored packet cards
- Right: inspector panel with switchable protocol details / raw hex view
- Top: operation bar with capture control, exports, and settings
- Dedicated filter row for BPF + search + protocol toggles

## Features

- Start/Stop capture
- Pause/Resume live rendering
- BPF capture filter + quick presets
- Display filtering (search + protocol toggles)
- Packet inspect panel (decoded structure + hex)
- Save captured packets to PCAP
- Integrated IDS alerts in the live rail
- Alerts history and CSV export
- Runtime detection threshold settings (apply/save/reset)

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
