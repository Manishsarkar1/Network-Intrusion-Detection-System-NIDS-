# sniffer_window.py
import threading
import datetime
from scapy.all import sniff
from scapy.layers.inet import IP
import customtkinter as ctk
from detector import Detector
from logger import Logger

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SnifferWindow(ctk.CTkToplevel):
    def __init__(self, iface, name):
        super().__init__()
        self.iface = iface
        self.name = name
        self.title(f"Monitoring - {name}")
        self.geometry("1200x700")
        self.sniffing = False
        self.header_printed = False
        self.packet_count = 0
        self.alert_count = 0

        # Initialize IDS components
        self.logger = Logger()
        self.detector = Detector(logger=self.logger, gui_callback=self.display_packet_or_alert)
        self.detector.start()

        print(f"\n{'='*60}")
        print(f"Opening monitor window for: {name}")
        print(f"Scapy interface: {iface}")
        print(f"IDS System: ACTIVE")
        print(f"{'='*60}\n")

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header Frame
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(1, weight=1)

        # Status indicator
        self.status_indicator = ctk.CTkLabel(header_frame, text="●", font=("Consolas", 30), 
                                            text_color="gray")
        self.status_indicator.grid(row=0, column=0, padx=(0, 10))

        # Title and interface info
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(title_container, text="Network Intrusion Detection System", 
                    font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ctk.CTkLabel(title_container, text=f"Interface: {name} | IDS: ACTIVE", 
                    font=("Segoe UI", 12), text_color="#4CAF50").pack(anchor="w")

        # Counters container
        counters_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        counters_frame.grid(row=0, column=2, padx=20)

        self.counter_label = ctk.CTkLabel(counters_frame, text="Packets: 0", 
                                         font=("Segoe UI", 13, "bold"))
        self.counter_label.pack()

        self.alert_label = ctk.CTkLabel(counters_frame, text="Alerts: 0", 
                                       font=("Segoe UI", 13, "bold"),
                                       text_color="#FF5252")
        self.alert_label.pack()

        # Main packet display frame
        display_frame = ctk.CTkFrame(self, corner_radius=10)
        display_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        display_frame.grid_columnconfigure(0, weight=1)
        display_frame.grid_rowconfigure(0, weight=1)

        # Packet display with custom colors
        self.packet_display = ctk.CTkTextbox(display_frame, width=1120, height=500, 
                                            font=("Consolas", 10), 
                                            fg_color=("#1a1a1a", "#0a0a0a"),
                                            corner_radius=8)
        self.packet_display.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)

        # Configure text tags for colored output
        self.packet_display.tag_config("TCP", foreground="#4CAF50")
        self.packet_display.tag_config("UDP", foreground="#2196F3")
        self.packet_display.tag_config("ICMP", foreground="#FF9800")
        self.packet_display.tag_config("OTHER", foreground="#9E9E9E")
        self.packet_display.tag_config("SSH", foreground="#9C27B0")
        self.packet_display.tag_config("VNC", foreground="#E91E63")
        self.packet_display.tag_config("ARP", foreground="#FF5722")
        self.packet_display.tag_config("HEADER", foreground="#FFFFFF")
        self.packet_display.tag_config("TIME", foreground="#64B5F6")
        self.packet_display.tag_config("IP", foreground="#FFD54F")
        self.packet_display.tag_config("ALERT", foreground="#FF5252", font=("Consolas", 10, "bold"))

        # Control panel
        control_frame = ctk.CTkFrame(self, fg_color="transparent")
        control_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        control_frame.grid_columnconfigure(0, weight=1)
        control_frame.grid_columnconfigure(1, weight=1)
        control_frame.grid_columnconfigure(2, weight=1)

        self.start_button = ctk.CTkButton(control_frame, text="▶ Start Monitoring", 
                                         command=self.start_sniffing,
                                         height=40, font=("Segoe UI", 14, "bold"),
                                         fg_color=("#2E7D32", "#1B5E20"),
                                         hover_color=("#388E3C", "#2E7D32"),
                                         corner_radius=8)
        self.start_button.grid(row=0, column=0, padx=10, sticky="ew")

        self.clear_button = ctk.CTkButton(control_frame, text="Clear Display", 
                                         command=self.clear_display,
                                         height=40, font=("Segoe UI", 14),
                                         fg_color=("#424242", "#303030"),
                                         hover_color=("#616161", "#424242"),
                                         corner_radius=8)
        self.clear_button.grid(row=0, column=1, padx=10, sticky="ew")

        self.alerts_button = ctk.CTkButton(control_frame, text="📊 View Alerts History", 
                                          command=self.show_alerts_history,
                                          height=40, font=("Segoe UI", 14),
                                          fg_color=("#D32F2F", "#B71C1C"),
                                          hover_color=("#F44336", "#D32F2F"),
                                          corner_radius=8)
        self.alerts_button.grid(row=0, column=2, padx=10, sticky="ew")

    def clear_display(self):
        self.packet_display.delete("1.0", "end")
        self.header_printed = False
        self.packet_count = 0
        self.counter_label.configure(text="Packets: 0")

    def display_packet_or_alert(self, data):
        """Callback for both normal packets and alerts from detector"""
        timestamp, src, dst, proto = data
        
        # Check if this is an alert
        is_alert = proto.startswith("🚨 ALERT:")
        
        if is_alert:
            self.alert_count += 1
            self.alert_label.configure(text=f"Alerts: {self.alert_count}")
            
            # Display alert prominently
            alert_msg = proto.replace("🚨 ALERT:", "").strip()
            self.packet_display.insert("end", "\n" + "="*100 + "\n", "ALERT")
            self.packet_display.insert("end", f"🚨 SECURITY ALERT at {timestamp}\n", "ALERT")
            self.packet_display.insert("end", f"Source: {src} → Destination: {dst}\n", "ALERT")
            self.packet_display.insert("end", f"Details: {alert_msg}\n", "ALERT")
            self.packet_display.insert("end", "="*100 + "\n\n", "ALERT")
            self.packet_display.see("end")
            return
        
        # Normal packet display
        self.packet_count += 1
        self.counter_label.configure(text=f"Packets: {self.packet_count}")

        if not self.header_printed:
            header = f"{'TIME':<12} │ {'SOURCE IP':<16} │ {'DESTINATION IP':<16} │ PROTOCOL\n"
            separator = "─" * 75 + "\n"
            self.packet_display.insert("end", header, "HEADER")
            self.packet_display.insert("end", separator, "HEADER")
            self.header_printed = True

        # Insert with color-coded protocol
        self.packet_display.insert("end", f"{timestamp:<12} ", "TIME")
        self.packet_display.insert("end", "│ ")
        self.packet_display.insert("end", f"{src:<16} ", "IP")
        self.packet_display.insert("end", "│ ")
        self.packet_display.insert("end", f"{dst:<16} ", "IP")
        self.packet_display.insert("end", "│ ")
        self.packet_display.insert("end", f"{proto}\n", proto)
        self.packet_display.see("end")

    def process_packet(self, packet):
        """Process packet through detector"""
        # Submit packet to detector for analysis
        self.detector.submit(packet)

    def sniff_packets(self):
        try:
            print(f"[INFO] Starting packet capture with IDS on: {self.iface}")
            self.packet_display.insert("end", f"🛡️ Starting IDS monitoring on {self.name}...\n", "HEADER")
            self.packet_display.insert("end", f"Interface: {self.iface}\n", "OTHER")
            self.packet_display.insert("end", f"Active Detections: SYN Scan, ICMP Flood, UDP Flood, SSH Brute Force, VNC Brute Force, ARP Poisoning\n\n", "HEADER")
            self.packet_display.see("end")

            # Sniff packets and send to detector
            sniff(prn=self.process_packet, store=False, iface=self.iface, 
                  stop_filter=lambda x: not self.sniffing)

        except PermissionError:
            error_msg = "\n⚠️ PERMISSION DENIED ⚠️\n\nYou need Administrator privileges to capture packets.\n\nPlease:\n1. Close this application\n2. Right-click on Command Prompt/Terminal\n3. Select 'Run as Administrator'\n4. Run the script again\n\n"
            print(f"[ERROR] {error_msg}")
            self.packet_display.insert("end", error_msg, "ALERT")
            self.sniffing = False
            self.stop_sniffing()

        except Exception as e:
            error_msg = f"\n⚠️ ERROR: {str(e)}\n\nPossible causes:\n- Need Administrator/sudo privileges\n- Interface may not support packet capture\n- Npcap/WinPcap not installed properly\n\nTry running as Administrator!\n\n"
            print(f"[ERROR] {error_msg}")
            self.packet_display.insert("end", error_msg, "ALERT")
            self.sniffing = False
            self.stop_sniffing()

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            t = threading.Thread(target=self.sniff_packets, daemon=True)
            t.start()
            self.start_button.configure(text="■ Stop Monitoring", 
                                       fg_color=("#C62828", "#B71C1C"),
                                       hover_color=("#D32F2F", "#C62828"),
                                       command=self.stop_sniffing)
            self.status_indicator.configure(text_color="#4CAF50")
        else:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.configure(text="▶ Start Monitoring", 
                                   fg_color=("#2E7D32", "#1B5E20"),
                                   hover_color=("#388E3C", "#2E7D32"),
                                   command=self.start_sniffing)
        self.status_indicator.configure(text_color="gray")

    def show_alerts_history(self):
        """Show alert history in a new window"""
        alerts_window = ctk.CTkToplevel(self)
        alerts_window.title("Alert History")
        alerts_window.geometry("900x600")
        
        # Header
        header_frame = ctk.CTkFrame(alerts_window, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(header_frame, text="🚨 Security Alerts History", 
                    font=("Segoe UI", 24, "bold")).pack()
        ctk.CTkLabel(header_frame, text="Last 50 alerts from database", 
                    font=("Segoe UI", 12), text_color="gray").pack()
        
        # Alerts display
        alerts_text = ctk.CTkTextbox(alerts_window, font=("Consolas", 10),
                                     fg_color=("#1a1a1a", "#0a0a0a"))
        alerts_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Fetch and display alerts
        alerts = self.logger.recent(50)
        
        if not alerts:
            alerts_text.insert("end", "No alerts recorded yet.\n\n")
        else:
            header = f"{'TIMESTAMP':<20} │ {'SOURCE':<16} │ {'DEST':<16} │ {'PROTO':<8} │ ALERT\n"
            alerts_text.insert("end", header)
            alerts_text.insert("end", "─" * 120 + "\n")
            
            for ts, src, dst, proto, alert_msg in alerts:
                ts_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                line = f"{ts_str:<20} │ {src:<16} │ {dst:<16} │ {proto:<8} │ {alert_msg}\n"
                alerts_text.insert("end", line)
        
        alerts_text.configure(state="disabled")