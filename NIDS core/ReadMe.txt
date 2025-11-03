# Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system with GUI interface built using Python, Scapy, and CustomTkinter.

## Features

### 🛡️ Detection Capabilities

1. **SYN Port Scan Detection**
   - Detects port scanning attempts by monitoring SYN packets
   - Triggers alert when multiple unique destination ports are probed from a single source
   - Default: 10+ unique ports in 5 seconds

2. **ICMP Flood Detection (Ping Flood)**
   - Monitors ICMP packet rates from each source
   - Alerts on excessive ping requests
   - Default: 50+ packets in 5 seconds

3. **UDP Flood Detection**
   - Tracks UDP packet rates to detect flooding attacks
   - Default: 200+ packets in 5 seconds

4. **SSH Brute Force Detection**
   - Monitors SSH connection attempts (port 22)
   - Detects repeated login attempts that may indicate password guessing
   - Default: 5+ attempts in 60 seconds

5. **VNC Brute Force Detection**
   - Monitors VNC ports (5900-5903)
   - Detects repeated connection attempts
   - Default: 5+ attempts in 60 seconds

6. **ARP Poisoning Detection**
   - Maintains an ARP table mapping IPs to MAC addresses
   - Alerts when the same IP is claimed by different MAC addresses
   - Helps detect Man-in-the-Middle (MITM) attacks

## Installation

### Prerequisites

```bash
# Python 3.7 or higher
python --version

# Required packages
pip install scapy customtkinter psutil
```

### Platform-Specific Requirements

**Windows:**
- Install [Npcap](https://npcap.com/) (WinPcap alternative)
- Run as Administrator

**Linux:**
```bash
sudo apt-get install python3-pip libpcap-dev
sudo pip install scapy customtkinter psutil
```

**macOS:**
```bash
brew install libpcap
pip install scapy customtkinter psutil
```

## Usage

### Running the Application

**Windows (as Administrator):**
```bash
# Right-click Command Prompt → "Run as Administrator"
python main.py
```

**Linux/macOS:**
```bash
sudo python3 main.py
```

### Using the Interface

1. **Select Network Interface**
   - Choose from available network interfaces
   - Click "Monitor →" to open monitoring window

2. **Start Monitoring**
   - Click "▶ Start Monitoring" to begin packet capture
   - Real-time packet display with color-coded protocols
   - Alert counter shows security events

3. **View Alerts**
   - Click "📊 View Alerts History" to see all recorded alerts
   - Alerts are stored in SQLite database (`nids_alerts.db`)

4. **Stop Monitoring**
   - Click "■ Stop Monitoring" to pause capture

## Configuration

Edit `config.py` to adjust detection sensitivity:

```python
# SYN Scan Detection
SYN_WINDOW = 5.0  # Time window (seconds)
SYN_PORTS_THRESHOLD = 10  # Unique ports to trigger

# Flood Detection
ICMP_FLOOD_THRESHOLD = 50  # Packets per window
UDP_FLOOD_THRESHOLD = 200  # Packets per window

# Brute Force Detection
SSH_FAILED_LOGIN_THRESHOLD = 5  # Attempts to trigger
VNC_FAILED_LOGIN_THRESHOLD = 5  # Attempts to trigger
```

## File Structure

```
├── main.py                    # Application entry point
├── Interface_selector.py      # Network interface selector GUI
├── sniffer_window.py         # Main monitoring window with IDS
├── detector.py               # IDS detection engine
├── logger.py                 # Alert logging to database
├── os_utils.py              # OS-specific interface detection
├── config.py                # Configuration parameters
└── nids_alerts.db           # SQLite database (auto-created)
```

## How It Works

### Architecture

```
┌─────────────┐
│   Packet    │
│   Capture   │
│  (Scapy)    │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌──────────────┐
│  Detector   │────▶│   Logger     │
│   Engine    │     │  (Database)  │
└──────┬──────┘     └──────────────┘
       │
       ▼
┌─────────────┐
│     GUI     │
│  (Display)  │
└─────────────┘
```

1. **Packet Capture**: Scapy captures network packets in real-time
2. **Detection Engine**: Analyzes packets for malicious patterns
3. **Alert System**: Logs and displays security events
4. **Database Storage**: Persists alerts for later analysis

### Detection Methods

**Pattern-Based Detection:**
- Monitors packet characteristics (flags, ports, rates)
- Uses sliding time windows to track behavior
- Threshold-based alerting with configurable sensitivity

**Stateful Analysis:**
- Maintains connection state (ARP table, attempt counters)
- Tracks historical patterns per source/destination
- Cooldown periods prevent alert spam

## Testing the IDS

### Safe Testing Methods

1. **Port Scan Test (using nmap):**
```bash
# On another machine or VM
nmap -sS -p 1-100 <target-ip>
```

2. **Ping Flood Test:**
```bash
# Linux/macOS
ping -f <target-ip>

# Windows (requires Admin)
ping -l 65500 -t <target-ip>
```

3. **SSH Connection Test:**
```bash
# Repeatedly connect to SSH
for i in {1..10}; do ssh user@<target-ip>; done
```

⚠️ **Warning**: Only test on networks you own or have permission to test!

## Troubleshooting

### Permission Errors
- **Windows**: Run as Administrator
- **Linux/macOS**: Use `sudo`

### No Interfaces Showing
- Check Npcap/libpcap installation
- Verify network adapters are enabled
- Try restarting the application

### No Packets Captured
- Ensure interface is "UP"
- Check firewall settings
- Verify Npcap is running (Windows)

### High CPU Usage
- Reduce capture rate by filtering protocols
- Increase detection thresholds in `config.py`
- Monitor fewer interfaces simultaneously

## Database

Alerts are stored in SQLite database with schema:

```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    ts REAL,           -- Timestamp
    src TEXT,          -- Source IP/MAC
    dst TEXT,          -- Destination IP
    proto TEXT,        -- Protocol (TCP/UDP/ICMP/ARP/SSH/VNC)
    alert TEXT         -- Alert message
)
```

Query alerts manually:
```bash
sqlite3 nids_alerts.db "SELECT * FROM alerts ORDER BY ts DESC LIMIT 10;"
```

## Performance Considerations

- **Light Mode**: Monitor single interface, minimal alerts
- **Production Mode**: Adjust thresholds for your network baseline
- **High-Traffic Networks**: Increase window sizes and thresholds

## Security Notes

⚠️ **This is an educational/monitoring tool:**
- Does NOT prevent attacks (detection only)
- Does NOT provide 100% protection
- Should be part of defense-in-depth strategy
- Alerts may include false positives

## Future Enhancements

Potential features to add:
- DNS spoofing detection
- HTTP/HTTPS anomaly detection
- Protocol-specific deep packet inspection
- Machine learning-based anomaly detection
- Email/SMS alert notifications
- Automated response actions
- Network baseline learning
- Geolocation of attackers

## License

Educational/Research purposes. Use responsibly and only on networks you own or have permission to monitor.

## Credits

Built with:
- [Scapy](https://scapy.net/) - Packet manipulation library
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern UI framework
- [SQLite](https://www.sqlite.org/) - Database engine

---

**⚠️ Legal Disclaimer**: This tool is for educational and authorized security testing only. Unauthorized network monitoring may be illegal in your jurisdiction. Always obtain proper authorization before monitoring any network.