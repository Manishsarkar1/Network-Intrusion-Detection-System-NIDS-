# config.py
"""
IDS Configuration File
Adjust these values to tune detection sensitivity
"""

# SYN Scan Detection
SYN_WINDOW = 5.0  # Time window in seconds
SYN_PORTS_THRESHOLD = 10  # Number of unique ports to trigger alert

# Flood Detection
FLOOD_WINDOW = 5.0  # Time window in seconds
ICMP_FLOOD_THRESHOLD = 50  # ICMP packets threshold
UDP_FLOOD_THRESHOLD = 200  # UDP packets threshold

# SSH Brute Force Detection
SSH_PORT = 22
SSH_FAILED_LOGIN_WINDOW = 60.0  # Time window in seconds (1 minute)
SSH_FAILED_LOGIN_THRESHOLD = 5  # Number of attempts to trigger alert

# VNC Brute Force Detection
VNC_PORTS = [5900, 5901, 5902, 5903]  # Common VNC ports
VNC_FAILED_LOGIN_WINDOW = 60.0  # Time window in seconds (1 minute)
VNC_FAILED_LOGIN_THRESHOLD = 5  # Number of attempts to trigger alert

# ARP Poisoning Detection
ARP_WINDOW = 30.0  # Time window in seconds
ARP_CONFLICT_THRESHOLD = 2  # Number of different MACs for same IP

# Database
DB_PATH = "nids_alerts.db"