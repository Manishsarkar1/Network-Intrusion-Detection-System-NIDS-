# sniffer_window.py
import datetime
import queue
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk
from scapy.all import sniff, wrpcap
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP

from nids_core.detector import Detector
from nids_core.logger import Logger
from nids_core.settings import default_settings, load_settings, save_settings, validate_settings

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CAPTURE_PRESETS = {
    "None": "",
    "HTTP/HTTPS": "tcp port 80 or tcp port 443",
    "DNS": "udp port 53 or tcp port 53",
    "SSH": "tcp port 22",
    "ICMP": "icmp",
    "ARP": "arp",
    "TCP Only": "tcp",
    "UDP Only": "udp",
}

DISPLAY_PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "OTHER", "ALERT"]

SETTING_FIELDS = [
    ("syn_window", "SYN Window (sec)", float),
    ("syn_ports_threshold", "SYN Ports Threshold", int),
    ("flood_window", "Flood Window (sec)", float),
    ("icmp_flood_threshold", "ICMP Flood Threshold", int),
    ("udp_flood_threshold", "UDP Flood Threshold", int),
    ("ssh_failed_login_window", "SSH Window (sec)", float),
    ("ssh_failed_login_threshold", "SSH Attempts Threshold", int),
    ("vnc_failed_login_window", "VNC Window (sec)", float),
    ("vnc_failed_login_threshold", "VNC Attempts Threshold", int),
    ("alert_cooldown_seconds", "Alert Cooldown (sec)", float),
]


class SnifferWindow(ctk.CTkToplevel):
    def __init__(self, iface, name):
        super().__init__()
        self.iface = iface
        self.name = name
        self.title(f"Packet Analyzer - {name}")
        self.geometry("1400x860")

        self.sniffing = False
        self.paused = False
        self.packet_count = 0
        self.alert_count = 0
        self._packet_count_last_tick = 0
        self.start_time = None
        self.sniff_thread = None

        self.packet_queue = queue.Queue()
        self.packet_records = []
        self.packet_counter = 0
        self.settings_window = None
        self.settings_vars = {}
        self.settings_status = None

        self.detection_settings = load_settings()
        self.logger = Logger()
        self.detector = Detector(
            logger=self.logger,
            gui_callback=self._enqueue_detector_event,
            settings=self.detection_settings,
        )
        self.detector.start()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self._tick_metrics()
        self._process_ui_queue()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))
        header_frame.grid_columnconfigure(1, weight=1)

        self.status_indicator = ctk.CTkLabel(header_frame, text="o", font=("Consolas", 30), text_color="gray")
        self.status_indicator.grid(row=0, column=0, padx=(0, 10))

        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(title_container, text="NIDS Packet Analyzer", font=("Segoe UI", 22, "bold")).pack(anchor="w")
        ctk.CTkLabel(title_container, text=f"Interface: {self.name}", text_color="gray").pack(anchor="w")

        stats_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        stats_frame.grid(row=0, column=2, padx=(10, 0))
        self.counter_label = ctk.CTkLabel(stats_frame, text="Packets: 0", font=("Segoe UI", 13, "bold"))
        self.counter_label.pack(anchor="e")
        self.alert_label = ctk.CTkLabel(stats_frame, text="Alerts: 0", text_color="#FF5252", font=("Segoe UI", 13, "bold"))
        self.alert_label.pack(anchor="e")
        self.rate_label = ctk.CTkLabel(stats_frame, text="Rate: 0 pkt/s")
        self.rate_label.pack(anchor="e")
        self.uptime_label = ctk.CTkLabel(stats_frame, text="Uptime: 00:00:00")
        self.uptime_label.pack(anchor="e")

        controls = ctk.CTkFrame(self)
        controls.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        for i in range(7):
            controls.grid_columnconfigure(i, weight=1)

        self.start_button = ctk.CTkButton(controls, text="Start", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=6, pady=6, sticky="ew")
        self.pause_button = ctk.CTkButton(controls, text="Pause", command=self.toggle_pause, state="disabled")
        self.pause_button.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        ctk.CTkButton(controls, text="Clear", command=self.clear_packets).grid(row=0, column=2, padx=6, pady=6, sticky="ew")
        ctk.CTkButton(controls, text="Save PCAP", command=self.save_pcap).grid(row=0, column=3, padx=6, pady=6, sticky="ew")
        ctk.CTkButton(controls, text="Export Alerts CSV", command=self.export_alerts).grid(row=0, column=4, padx=6, pady=6, sticky="ew")
        ctk.CTkButton(controls, text="Detection Settings", command=self.open_settings_window).grid(row=0, column=5, padx=6, pady=6, sticky="ew")
        ctk.CTkButton(controls, text="Alerts History", command=self.show_alerts_history).grid(row=0, column=6, padx=6, pady=6, sticky="ew")

        filter_bar = ctk.CTkFrame(self)
        filter_bar.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))
        for i in range(9):
            filter_bar.grid_columnconfigure(i, weight=1 if i in (3, 6) else 0)

        ctk.CTkLabel(filter_bar, text="Capture (BPF):").grid(row=0, column=0, padx=(10, 4), pady=8, sticky="w")
        self.bpf_entry = ctk.CTkEntry(filter_bar, placeholder_text="tcp port 443 and host 192.168.1.10")
        self.bpf_entry.grid(row=0, column=1, columnspan=3, padx=4, pady=8, sticky="ew")

        self.capture_preset_var = ctk.StringVar(value="None")
        preset = ctk.CTkOptionMenu(filter_bar, variable=self.capture_preset_var, values=list(CAPTURE_PRESETS.keys()), command=self._apply_capture_preset)
        preset.grid(row=0, column=4, padx=4, pady=8, sticky="ew")

        ctk.CTkLabel(filter_bar, text="Search:").grid(row=0, column=5, padx=(8, 4), pady=8, sticky="w")
        self.search_var = ctk.StringVar(value="")
        self.search_var.trace_add("write", lambda *_: self._rebuild_tree())
        self.search_entry = ctk.CTkEntry(filter_bar, textvariable=self.search_var, placeholder_text="src/dst/proto/info")
        self.search_entry.grid(row=0, column=6, padx=4, pady=8, sticky="ew")

        self.auto_scroll_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(filter_bar, text="Auto Scroll", variable=self.auto_scroll_var, width=120).grid(
            row=0, column=7, padx=6, pady=8, sticky="w"
        )

        max_frame = ctk.CTkFrame(filter_bar, fg_color="transparent")
        max_frame.grid(row=0, column=8, padx=6, pady=8, sticky="e")
        ctk.CTkLabel(max_frame, text="Max View:").pack(side="left", padx=(0, 4))
        self.max_view_var = ctk.StringVar(value="5000")
        max_entry = ctk.CTkEntry(max_frame, textvariable=self.max_view_var, width=70)
        max_entry.pack(side="left")
        self.max_view_var.trace_add("write", lambda *_: self._rebuild_tree())

        proto_bar = ctk.CTkFrame(self)
        proto_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 8))
        self.proto_vars = {}
        for idx, proto in enumerate(DISPLAY_PROTOCOLS):
            var = ctk.BooleanVar(value=True)
            self.proto_vars[proto] = var
            ctk.CTkCheckBox(proto_bar, text=proto, variable=var, command=self._rebuild_tree).grid(
                row=0, column=idx, padx=10, pady=6, sticky="w"
            )

        content = ctk.CTkFrame(self)
        content.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 12))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=3)
        content.grid_rowconfigure(1, weight=2)

        tree_container = ctk.CTkFrame(content)
        tree_container.grid(row=0, column=0, sticky="nsew", padx=8, pady=(8, 4))
        tree_container.grid_columnconfigure(0, weight=1)
        tree_container.grid_rowconfigure(0, weight=1)

        columns = ("no", "time", "source", "destination", "protocol", "length", "info")
        self.packet_tree = ttk.Treeview(tree_container, columns=columns, show="headings")
        self.packet_tree.grid(row=0, column=0, sticky="nsew")

        widths = {"no": 60, "time": 90, "source": 170, "destination": 170, "protocol": 90, "length": 80, "info": 620}
        headings = {"no": "No.", "time": "Time", "source": "Source", "destination": "Destination", "protocol": "Protocol", "length": "Length", "info": "Info"}
        for col in columns:
            self.packet_tree.heading(col, text=headings[col])
            self.packet_tree.column(col, width=widths[col], anchor="w")

        self.packet_tree.tag_configure("ALERT", foreground="#FF5252")

        y_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.packet_tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        self.packet_tree.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(tree_container, orient="horizontal", command=self.packet_tree.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.packet_tree.configure(xscrollcommand=x_scroll.set)

        self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_select)

        bottom = ctk.CTkFrame(content)
        bottom.grid(row=1, column=0, sticky="nsew", padx=8, pady=(4, 8))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)
        bottom.grid_rowconfigure(0, weight=1)

        self.detail_text = ctk.CTkTextbox(bottom, font=("Consolas", 11))
        self.detail_text.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)

        self.raw_text = ctk.CTkTextbox(bottom, font=("Consolas", 11))
        self.raw_text.grid(row=0, column=1, sticky="nsew", padx=(4, 8), pady=8)

    def _apply_capture_preset(self, label):
        self.bpf_entry.delete(0, "end")
        self.bpf_entry.insert(0, CAPTURE_PRESETS.get(label, ""))

    def _tick_metrics(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            s = elapsed % 60
            self.uptime_label.configure(text=f"Uptime: {h:02}:{m:02}:{s:02}")

        rate = max(0, self.packet_count - self._packet_count_last_tick)
        self._packet_count_last_tick = self.packet_count
        self.rate_label.configure(text=f"Rate: {rate} pkt/s")
        self.after(1000, self._tick_metrics)

    def _process_ui_queue(self):
        try:
            while True:
                event = self.packet_queue.get_nowait()
                self._handle_ui_event(event)
        except queue.Empty:
            pass
        self.after(50, self._process_ui_queue)

    def _enqueue_detector_event(self, payload):
        # payload: (time_str, src, dst, "ALERT: ...")
        self.packet_queue.put({"type": "alert", "payload": payload})

    def _summarize_packet(self, pkt):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        length = len(pkt)

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                proto = "TCP"
                info = f"{pkt[TCP].sport} -> {pkt[TCP].dport} flags={pkt[TCP].sprintf('%flags%')}"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
            else:
                proto = "OTHER"
                info = "IP packet"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src = getattr(pkt[ARP], "psrc", "-")
            dst = getattr(pkt[ARP], "pdst", "-")
            op = "reply" if pkt[ARP].op == 2 else "request"
            info = f"ARP {op}"
        else:
            proto = "OTHER"
            src = "-"
            dst = "-"
            info = pkt.summary()

        return {
            "time": now,
            "source": src,
            "destination": dst,
            "protocol": proto,
            "length": str(length),
            "info": info,
        }

    def _format_hex(self, pkt):
        raw = bytes(pkt)
        lines = []
        for i in range(0, len(raw), 16):
            chunk = raw[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
        return "\n".join(lines)

    def _passes_filters(self, record):
        summary = record["summary"]
        proto = summary["protocol"]
        var = self.proto_vars.get(proto)
        if var and not var.get():
            return False

        query = self.search_var.get().strip().lower()
        if query:
            text = " ".join(
                [
                    summary["source"],
                    summary["destination"],
                    summary["protocol"],
                    summary["info"],
                ]
            ).lower()
            if query not in text:
                return False
        return True

    def _max_view_count(self):
        try:
            value = int(self.max_view_var.get().strip())
            return max(100, min(value, 50000))
        except Exception:
            return 5000

    def _rebuild_tree(self):
        selection = self.packet_tree.selection()
        selected_no = None
        if selection:
            vals = self.packet_tree.item(selection[0], "values")
            if vals:
                selected_no = vals[0]

        self.packet_tree.delete(*self.packet_tree.get_children())

        max_view = self._max_view_count()
        visible = [r for r in self.packet_records if self._passes_filters(r)]
        visible = visible[-max_view:]

        for record in visible:
            s = record["summary"]
            values = (
                record["no"],
                s["time"],
                s["source"],
                s["destination"],
                s["protocol"],
                s["length"],
                s["info"],
            )
            tags = ("ALERT",) if s["protocol"] == "ALERT" else ()
            item_id = self.packet_tree.insert("", "end", values=values, tags=tags)
            if selected_no and str(record["no"]) == str(selected_no):
                self.packet_tree.selection_set(item_id)

        if self.auto_scroll_var.get():
            children = self.packet_tree.get_children()
            if children:
                self.packet_tree.see(children[-1])

    def _handle_ui_event(self, event):
        kind = event.get("type")
        if kind == "packet":
            if self.paused:
                return
            record = event["record"]
            self.packet_records.append(record)
            self.packet_count += 1
            self.counter_label.configure(text=f"Packets: {self.packet_count}")
            if self._passes_filters(record):
                self._append_record_to_tree(record)
        elif kind == "alert":
            time_str, src, dst, proto_text = event["payload"]
            msg = proto_text.replace("ALERT:", "").strip()
            self.alert_count += 1
            self.alert_label.configure(text=f"Alerts: {self.alert_count}")
            self.packet_counter += 1
            record = {
                "no": self.packet_counter,
                "summary": {
                    "time": time_str,
                    "source": src,
                    "destination": dst,
                    "protocol": "ALERT",
                    "length": "-",
                    "info": msg,
                },
                "packet": None,
            }
            self.packet_records.append(record)
            if self._passes_filters(record):
                self._append_record_to_tree(record)

    def _append_record_to_tree(self, record):
        s = record["summary"]
        values = (
            record["no"],
            s["time"],
            s["source"],
            s["destination"],
            s["protocol"],
            s["length"],
            s["info"],
        )
        tags = ("ALERT",) if s["protocol"] == "ALERT" else ()
        self.packet_tree.insert("", "end", values=values, tags=tags)
        if self.auto_scroll_var.get():
            children = self.packet_tree.get_children()
            if children:
                self.packet_tree.see(children[-1])

    def _capture_callback(self, pkt):
        self.packet_counter += 1
        summary = self._summarize_packet(pkt)
        record = {"no": self.packet_counter, "summary": summary, "packet": pkt}
        self.packet_queue.put({"type": "packet", "record": record})
        self.detector.submit(pkt)

    def start_sniffing(self):
        if self.sniffing:
            self.stop_sniffing()
            return

        self.sniffing = True
        self.paused = False
        self.start_time = time.time()
        self._packet_count_last_tick = self.packet_count

        self.pause_button.configure(state="normal", text="Pause")
        self.start_button.configure(text="Stop", fg_color=("#C62828", "#B71C1C"), hover_color=("#D32F2F", "#C62828"))
        self.status_indicator.configure(text_color="#4CAF50")

        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def _sniff_loop(self):
        bpf = self.bpf_entry.get().strip()
        self._log_info(f"Capture start on {self.name}")
        if bpf:
            self._log_info(f"BPF: {bpf}")

        while self.sniffing:
            try:
                kwargs = {
                    "prn": self._capture_callback,
                    "store": False,
                    "iface": self.iface,
                    "timeout": 1,
                }
                if bpf:
                    kwargs["filter"] = bpf
                sniff(**kwargs)
            except PermissionError:
                self.packet_queue.put(
                    {
                        "type": "alert",
                        "payload": (
                            datetime.datetime.now().strftime("%H:%M:%S"),
                            "local",
                            self.iface,
                            "ALERT: Permission denied. Run as Administrator/root.",
                        ),
                    }
                )
                self.sniffing = False
            except Exception as e:
                if bpf:
                    self._log_info("BPF failed; retrying without filter.")
                    bpf = ""
                    continue
                self.packet_queue.put(
                    {
                        "type": "alert",
                        "payload": (
                            datetime.datetime.now().strftime("%H:%M:%S"),
                            "local",
                            self.iface,
                            f"ALERT: Capture error: {e}",
                        ),
                    }
                )
                self.sniffing = False

    def stop_sniffing(self):
        self.sniffing = False
        self.paused = False
        self.start_button.configure(text="Start", fg_color=("#2E7D32", "#1B5E20"), hover_color=("#388E3C", "#2E7D32"))
        self.pause_button.configure(state="disabled", text="Pause")
        self.status_indicator.configure(text_color="gray")

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_button.configure(text="Resume" if self.paused else "Pause")
        self._log_info("Display paused" if self.paused else "Display resumed")

    def clear_packets(self):
        self.packet_records = []
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.detail_text.delete("1.0", "end")
        self.raw_text.delete("1.0", "end")
        self.packet_count = 0
        self.alert_count = 0
        self.packet_counter = 0
        self.counter_label.configure(text="Packets: 0")
        self.alert_label.configure(text="Alerts: 0")
        self.rate_label.configure(text="Rate: 0 pkt/s")

    def _find_record_by_no(self, no):
        for rec in self.packet_records:
            if str(rec["no"]) == str(no):
                return rec
        return None

    def _on_packet_select(self, _event):
        selected = self.packet_tree.selection()
        if not selected:
            return
        vals = self.packet_tree.item(selected[0], "values")
        if not vals:
            return
        rec = self._find_record_by_no(vals[0])
        if not rec:
            return

        self.detail_text.delete("1.0", "end")
        self.raw_text.delete("1.0", "end")

        pkt = rec["packet"]
        if pkt is None:
            s = rec["summary"]
            self.detail_text.insert("end", f"ALERT\nTime: {s['time']}\nSource: {s['source']}\nDestination: {s['destination']}\n\n{s['info']}")
            return

        try:
            self.detail_text.insert("end", pkt.show(dump=True))
            self.raw_text.insert("end", self._format_hex(pkt))
        except Exception as e:
            self.detail_text.insert("end", f"Failed to decode packet details: {e}")

    def save_pcap(self):
        packets = [r["packet"] for r in self.packet_records if r["packet"] is not None]
        if not packets:
            messagebox.showinfo("Save PCAP", "No packets captured yet.")
            return

        default_dir = Path("data")
        default_dir.mkdir(parents=True, exist_ok=True)
        default_name = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        file_path = filedialog.asksaveasfilename(
            title="Save capture as PCAP",
            initialdir=str(default_dir.resolve()),
            initialfile=default_name,
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
        )
        if not file_path:
            return

        wrpcap(file_path, packets)
        self._log_info(f"Saved {len(packets)} packets to {file_path}")

    def _log_info(self, msg):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.packet_counter += 1
        record = {
            "no": self.packet_counter,
            "summary": {
                "time": now,
                "source": "local",
                "destination": self.iface,
                "protocol": "OTHER",
                "length": "-",
                "info": msg,
            },
            "packet": None,
        }
        self.packet_records.append(record)
        if self._passes_filters(record):
            self._append_record_to_tree(record)

    def show_alerts_history(self):
        alerts_window = ctk.CTkToplevel(self)
        alerts_window.title("Alert History")
        alerts_window.geometry("1000x620")
        alerts_window.transient(self)

        text = ctk.CTkTextbox(alerts_window, font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=16, pady=16)

        rows = self.logger.recent(200)
        if not rows:
            text.insert("end", "No alerts recorded yet.\n")
        else:
            text.insert("end", f"{'TIMESTAMP':<20} | {'SOURCE':<16} | {'DEST':<16} | {'PROTO':<8} | ALERT\n")
            text.insert("end", "-" * 125 + "\n")
            for ts, src, dst, proto, alert_msg in rows:
                ts_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                text.insert("end", f"{ts_str:<20} | {src:<16} | {dst:<16} | {proto:<8} | {alert_msg}\n")

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

        exported = self.logger.export_csv(file_path, limit=5000)
        self._log_info(f"Exported {exported} alerts to {file_path}")

    def _settings_summary(self, settings):
        return (
            f"syn={settings['syn_ports_threshold']}@{settings['syn_window']}s, "
            f"icmp={settings['icmp_flood_threshold']}, udp={settings['udp_flood_threshold']}, "
            f"ssh={settings['ssh_failed_login_threshold']}@{settings['ssh_failed_login_window']}s, "
            f"vnc={settings['vnc_failed_login_threshold']}@{settings['vnc_failed_login_window']}s, "
            f"cooldown={settings['alert_cooldown_seconds']}s"
        )

    def open_settings_window(self):
        if self.settings_window and self.settings_window.winfo_exists():
            self.settings_window.focus()
            return

        self.settings_window = ctk.CTkToplevel(self)
        self.settings_window.title("Detection Settings")
        self.settings_window.geometry("560x640")
        self.settings_window.transient(self)

        frame = ctk.CTkFrame(self.settings_window)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(frame, text="Detection Thresholds", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(10, 6), padx=14)
        ctk.CTkLabel(
            frame,
            text="Apply updates instantly to the running detector. Save to persist across restarts.",
            text_color="gray",
            wraplength=500,
            justify="left",
        ).pack(anchor="w", padx=14, pady=(0, 10))

        fields_frame = ctk.CTkScrollableFrame(frame, height=420)
        fields_frame.pack(fill="both", expand=True, padx=12, pady=10)
        fields_frame.grid_columnconfigure(1, weight=1)

        self.settings_vars = {}
        for row_idx, (key, label, _cast) in enumerate(SETTING_FIELDS):
            ctk.CTkLabel(fields_frame, text=label).grid(row=row_idx, column=0, sticky="w", padx=8, pady=8)
            var = ctk.StringVar(value=str(self.detection_settings.get(key, default_settings()[key])))
            entry = ctk.CTkEntry(fields_frame, textvariable=var)
            entry.grid(row=row_idx, column=1, sticky="ew", padx=8, pady=8)
            self.settings_vars[key] = var

        self.settings_status = ctk.CTkLabel(frame, text="", text_color="gray")
        self.settings_status.pack(anchor="w", padx=14, pady=(6, 2))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", padx=12, pady=(8, 12))
        buttons.grid_columnconfigure(0, weight=1)
        buttons.grid_columnconfigure(1, weight=1)
        buttons.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(buttons, text="Apply Now", command=lambda: self.apply_settings(persist=False)).grid(row=0, column=0, padx=6, sticky="ew")
        ctk.CTkButton(buttons, text="Save and Apply", command=lambda: self.apply_settings(persist=True)).grid(row=0, column=1, padx=6, sticky="ew")
        ctk.CTkButton(buttons, text="Reset Defaults", command=self.reset_default_settings).grid(row=0, column=2, padx=6, sticky="ew")

    def _collect_settings_from_ui(self):
        raw = {}
        for key, _label, cast_type in SETTING_FIELDS:
            text = self.settings_vars[key].get().strip()
            raw[key] = int(text) if cast_type is int else float(text)
        return raw

    def apply_settings(self, persist=False):
        try:
            raw = self._collect_settings_from_ui()
            validated = validate_settings(raw)
        except Exception as e:
            if self.settings_status:
                self.settings_status.configure(text=f"Invalid value: {e}", text_color="#FF5252")
            return

        self.detection_settings = validated
        self.detector.update_settings(validated)

        if persist:
            save_settings(validated)
            status = "Settings saved and applied."
        else:
            status = "Settings applied for this session."

        if self.settings_status:
            self.settings_status.configure(text=status, text_color="#81C784")
        self._log_info(status + " " + self._settings_summary(validated))

    def reset_default_settings(self):
        defaults = default_settings()
        for key, _label, _cast in SETTING_FIELDS:
            self.settings_vars[key].set(str(defaults[key]))
        self.apply_settings(persist=True)

    def on_close(self):
        self.sniffing = False
        self.detector.stop(join_timeout=1.0)
        self.destroy()
