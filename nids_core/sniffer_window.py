# sniffer_window.py
import datetime
import threading
import time
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk
from scapy.all import sniff

from nids_core.detector import Detector
from nids_core.logger import Logger

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

FILTER_PRESETS = {
    "All Traffic": None,
    "TCP Only": "tcp",
    "UDP Only": "udp",
    "ICMP Only": "icmp",
    "ARP Only": "arp",
}


class SnifferWindow(ctk.CTkToplevel):
    def __init__(self, iface, name):
        super().__init__()
        self.iface = iface
        self.name = name
        self.title(f"Monitoring - {name}")
        self.geometry("1200x760")
        self.sniffing = False
        self.header_printed = False
        self.packet_count = 0
        self.alert_count = 0
        self._packet_count_last_tick = 0
        self.start_time = None
        self.sniff_thread = None

        # Initialize IDS components
        self.logger = Logger()
        self.detector = Detector(logger=self.logger, gui_callback=self.display_packet_or_alert)
        self.detector.start()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header Frame
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(1, weight=1)

        # Status indicator
        self.status_indicator = ctk.CTkLabel(header_frame, text="o", font=("Consolas", 30), text_color="gray")
        self.status_indicator.grid(row=0, column=0, padx=(0, 10))

        # Title and interface info
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(title_container, text="Network Intrusion Detection System", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ctk.CTkLabel(
            title_container,
            text=f"Interface: {name} | IDS: ACTIVE",
            font=("Segoe UI", 12),
            text_color="#4CAF50",
        ).pack(anchor="w")

        # Counters container
        counters_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        counters_frame.grid(row=0, column=2, padx=20)

        self.counter_label = ctk.CTkLabel(counters_frame, text="Packets: 0", font=("Segoe UI", 13, "bold"))
        self.counter_label.pack(anchor="e")

        self.alert_label = ctk.CTkLabel(
            counters_frame,
            text="Alerts: 0",
            font=("Segoe UI", 13, "bold"),
            text_color="#FF5252",
        )
        self.alert_label.pack(anchor="e")

        self.rate_label = ctk.CTkLabel(counters_frame, text="Rate: 0 pkt/s", font=("Segoe UI", 12))
        self.rate_label.pack(anchor="e")

        self.uptime_label = ctk.CTkLabel(counters_frame, text="Uptime: 00:00:00", font=("Segoe UI", 12))
        self.uptime_label.pack(anchor="e")

        # Controls row
        options_frame = ctk.CTkFrame(self, corner_radius=8)
        options_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        options_frame.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(options_frame, text="Capture Filter", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, padx=(12, 8), pady=10, sticky="w"
        )

        self.filter_var = ctk.StringVar(value="All Traffic")
        self.filter_menu = ctk.CTkOptionMenu(options_frame, variable=self.filter_var, values=list(FILTER_PRESETS.keys()))
        self.filter_menu.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="w")

        self.filter_help = ctk.CTkLabel(
            options_frame,
            text="Tip: Choose a filter before starting capture.",
            font=("Segoe UI", 11),
            text_color="gray",
        )
        self.filter_help.grid(row=0, column=2, padx=(0, 12), pady=10, sticky="w")

        # Main packet display frame
        display_frame = ctk.CTkFrame(self, corner_radius=10)
        display_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
        display_frame.grid_columnconfigure(0, weight=1)
        display_frame.grid_rowconfigure(0, weight=1)

        self.packet_display = ctk.CTkTextbox(
            display_frame,
            width=1120,
            height=500,
            font=("Consolas", 10),
            fg_color=("#1a1a1a", "#0a0a0a"),
            corner_radius=8,
        )
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
        self.packet_display.tag_config("ALERT", foreground="#FF5252")
        self.packet_display.tag_config("INFO", foreground="#90CAF9")

        # Control panel
        control_frame = ctk.CTkFrame(self, fg_color="transparent")
        control_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        for idx in range(4):
            control_frame.grid_columnconfigure(idx, weight=1)

        self.start_button = ctk.CTkButton(
            control_frame,
            text="Start Monitoring",
            command=self.start_sniffing,
            height=40,
            font=("Segoe UI", 14, "bold"),
            fg_color=("#2E7D32", "#1B5E20"),
            hover_color=("#388E3C", "#2E7D32"),
            corner_radius=8,
        )
        self.start_button.grid(row=0, column=0, padx=10, sticky="ew")

        self.clear_button = ctk.CTkButton(
            control_frame,
            text="Clear Display",
            command=self.clear_display,
            height=40,
            font=("Segoe UI", 14),
            fg_color=("#424242", "#303030"),
            hover_color=("#616161", "#424242"),
            corner_radius=8,
        )
        self.clear_button.grid(row=0, column=1, padx=10, sticky="ew")

        self.alerts_button = ctk.CTkButton(
            control_frame,
            text="View Alerts History",
            command=self.show_alerts_history,
            height=40,
            font=("Segoe UI", 14),
            fg_color=("#D32F2F", "#B71C1C"),
            hover_color=("#F44336", "#D32F2F"),
            corner_radius=8,
        )
        self.alerts_button.grid(row=0, column=2, padx=10, sticky="ew")

        self.export_button = ctk.CTkButton(
            control_frame,
            text="Export Alerts CSV",
            command=self.export_alerts,
            height=40,
            font=("Segoe UI", 14),
            fg_color=("#1565C0", "#0D47A1"),
            hover_color=("#1976D2", "#1565C0"),
            corner_radius=8,
        )
        self.export_button.grid(row=0, column=3, padx=10, sticky="ew")

        self._tick_metrics()

    def clear_display(self):
        self.packet_display.delete("1.0", "end")
        self.header_printed = False
        self.packet_count = 0
        self.alert_count = 0
        self._packet_count_last_tick = 0
        self.counter_label.configure(text="Packets: 0")
        self.alert_label.configure(text="Alerts: 0")
        self.rate_label.configure(text="Rate: 0 pkt/s")

    def _tick_metrics(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            s = elapsed % 60
            self.uptime_label.configure(text=f"Uptime: {h:02}:{m:02}:{s:02}")

        current = self.packet_count
        rate = max(0, current - self._packet_count_last_tick)
        self._packet_count_last_tick = current
        self.rate_label.configure(text=f"Rate: {rate} pkt/s")

        self.after(1000, self._tick_metrics)

    def _selected_bpf_filter(self):
        return FILTER_PRESETS.get(self.filter_var.get())

    def _log_info(self, message):
        self.packet_display.insert("end", f"[INFO] {message}\n", "INFO")
        self.packet_display.see("end")

    def display_packet_or_alert(self, data):
        timestamp, src, dst, proto = data

        is_alert = proto.startswith("ALERT:")

        if is_alert:
            self.alert_count += 1
            self.alert_label.configure(text=f"Alerts: {self.alert_count}")

            alert_msg = proto.replace("ALERT:", "").strip()
            self.packet_display.insert("end", "\n" + "=" * 100 + "\n", "ALERT")
            self.packet_display.insert("end", f"SECURITY ALERT at {timestamp}\n", "ALERT")
            self.packet_display.insert("end", f"Source: {src} -> Destination: {dst}\n", "ALERT")
            self.packet_display.insert("end", f"Details: {alert_msg}\n", "ALERT")
            self.packet_display.insert("end", "=" * 100 + "\n\n", "ALERT")
            self.packet_display.see("end")
            return

        self.packet_count += 1
        self.counter_label.configure(text=f"Packets: {self.packet_count}")

        if not self.header_printed:
            header = f"{'TIME':<12} | {'SOURCE IP':<16} | {'DESTINATION IP':<16} | PROTOCOL\n"
            separator = "-" * 75 + "\n"
            self.packet_display.insert("end", header, "HEADER")
            self.packet_display.insert("end", separator, "HEADER")
            self.header_printed = True

        self.packet_display.insert("end", f"{timestamp:<12} ", "TIME")
        self.packet_display.insert("end", "| ")
        self.packet_display.insert("end", f"{src:<16} ", "IP")
        self.packet_display.insert("end", "| ")
        self.packet_display.insert("end", f"{dst:<16} ", "IP")
        self.packet_display.insert("end", "| ")
        self.packet_display.insert("end", f"{proto}\n", proto)
        self.packet_display.see("end")

    def process_packet(self, packet):
        self.detector.submit(packet)

    def sniff_packets(self):
        bpf_filter = self._selected_bpf_filter()

        try:
            self._log_info(f"Starting capture on {self.name}")
            self._log_info(f"Interface: {self.iface}")
            self._log_info(
                "Active detections: SYN scan, ICMP flood, UDP flood, SSH brute force, VNC brute force, ARP poisoning"
            )
            if bpf_filter:
                self._log_info(f"Capture filter: {bpf_filter}")

            while self.sniffing:
                sniff_kwargs = {
                    "prn": self.process_packet,
                    "store": False,
                    "iface": self.iface,
                    "timeout": 1,
                }
                if bpf_filter:
                    sniff_kwargs["filter"] = bpf_filter
                sniff(**sniff_kwargs)

        except PermissionError:
            error_msg = (
                "\nPERMISSION DENIED\n"
                "Run this app with Administrator/root privileges to capture packets.\n\n"
            )
            self.packet_display.insert("end", error_msg, "ALERT")
            self.sniffing = False
            self.stop_sniffing()

        except Exception as e:
            # Filter may fail on some environments. Retry without filter once.
            if bpf_filter:
                try:
                    self._log_info("Capture filter failed in this environment; retrying without filter.")
                    while self.sniffing:
                        sniff(prn=self.process_packet, store=False, iface=self.iface, timeout=1)
                    return
                except Exception as fallback_error:
                    e = fallback_error

            error_msg = (
                f"\nERROR: {str(e)}\n"
                "Possible causes:\n"
                "- Need Administrator/sudo privileges\n"
                "- Interface may not support packet capture\n"
                "- Npcap/WinPcap not installed properly\n\n"
            )
            self.packet_display.insert("end", error_msg, "ALERT")
            self.sniffing = False
            self.stop_sniffing()

    def start_sniffing(self):
        if self.sniffing:
            self.stop_sniffing()
            return

        self.sniffing = True
        self.start_time = time.time()
        self._packet_count_last_tick = self.packet_count
        self.filter_menu.configure(state="disabled")

        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

        self.start_button.configure(
            text="Stop Monitoring",
            fg_color=("#C62828", "#B71C1C"),
            hover_color=("#D32F2F", "#C62828"),
            command=self.stop_sniffing,
        )
        self.status_indicator.configure(text_color="#4CAF50")

    def stop_sniffing(self):
        self.sniffing = False
        self.filter_menu.configure(state="normal")
        self.start_button.configure(
            text="Start Monitoring",
            fg_color=("#2E7D32", "#1B5E20"),
            hover_color=("#388E3C", "#2E7D32"),
            command=self.start_sniffing,
        )
        self.status_indicator.configure(text_color="gray")

    def show_alerts_history(self):
        alerts_window = ctk.CTkToplevel(self)
        alerts_window.title("Alert History")
        alerts_window.geometry("900x600")
        alerts_window.transient(self)

        header_frame = ctk.CTkFrame(alerts_window, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        ctk.CTkLabel(header_frame, text="Security Alerts History", font=("Segoe UI", 24, "bold")).pack()
        ctk.CTkLabel(header_frame, text="Last 100 alerts from database", font=("Segoe UI", 12), text_color="gray").pack()

        alerts_text = ctk.CTkTextbox(alerts_window, font=("Consolas", 10), fg_color=("#1a1a1a", "#0a0a0a"))
        alerts_text.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        alerts = self.logger.recent(100)

        if not alerts:
            alerts_text.insert("end", "No alerts recorded yet.\n\n")
        else:
            header = f"{'TIMESTAMP':<20} | {'SOURCE':<16} | {'DEST':<16} | {'PROTO':<8} | ALERT\n"
            alerts_text.insert("end", header)
            alerts_text.insert("end", "-" * 120 + "\n")

            for ts, src, dst, proto, alert_msg in alerts:
                ts_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                line = f"{ts_str:<20} | {src:<16} | {dst:<16} | {proto:<8} | {alert_msg}\n"
                alerts_text.insert("end", line)

        alerts_text.configure(state="disabled")

    def export_alerts(self):
        default_dir = Path("data")
        default_dir.mkdir(parents=True, exist_ok=True)
        default_name = f"alerts_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        file_path = filedialog.asksaveasfilename(
            title="Export alerts to CSV",
            initialdir=str(default_dir.resolve()),
            initialfile=default_name,
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )

        if not file_path:
            return

        exported = self.logger.export_csv(file_path, limit=2000)
        self._log_info(f"Exported {exported} alerts to {file_path}")

    def on_close(self):
        self.sniffing = False
        self.detector.stop(join_timeout=1.0)
        self.destroy()
