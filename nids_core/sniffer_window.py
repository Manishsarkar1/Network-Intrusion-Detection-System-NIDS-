# sniffer_window.py
import datetime
import queue
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox

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
    "Web": "tcp port 80 or tcp port 443",
    "DNS": "udp port 53 or tcp port 53",
    "SSH": "tcp port 22",
    "ICMP": "icmp",
    "ARP": "arp",
    "TCP": "tcp",
    "UDP": "udp",
}

DISPLAY_PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "OTHER", "ALERT"]

PROTO_COLORS = {
    "TCP": "#4CAF50",
    "UDP": "#29B6F6",
    "ICMP": "#FFB300",
    "ARP": "#FF7043",
    "OTHER": "#B0BEC5",
    "ALERT": "#FF5252",
}

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
        self.title(f"NIDS Studio - {name}")
        self.geometry("1420x900")

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
        self.selected_no = None

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
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkFrame(self, corner_radius=14, fg_color=("#0f172a", "#0b1220"))
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.grid_columnconfigure(1, weight=1)

        self.status_dot = ctk.CTkLabel(header, text="o", text_color="#64748b", font=("Consolas", 34))
        self.status_dot.grid(row=0, column=0, padx=(12, 8), pady=10)

        title_wrap = ctk.CTkFrame(header, fg_color="transparent")
        title_wrap.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(title_wrap, text="NIDS Studio", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ctk.CTkLabel(
            title_wrap,
            text=f"Interface: {self.name} | Dark Ops Dashboard",
            text_color="#94a3b8",
            font=("Segoe UI", 12),
        ).pack(anchor="w")

        stats = ctk.CTkFrame(header, fg_color="transparent")
        stats.grid(row=0, column=2, padx=12)
        self.counter_label = ctk.CTkLabel(stats, text="Packets 0", font=("Segoe UI", 14, "bold"))
        self.counter_label.pack(anchor="e")
        self.alert_label = ctk.CTkLabel(stats, text="Alerts 0", font=("Segoe UI", 14, "bold"), text_color="#FF5252")
        self.alert_label.pack(anchor="e")
        self.rate_label = ctk.CTkLabel(stats, text="Rate 0/s", text_color="#93c5fd")
        self.rate_label.pack(anchor="e")
        self.uptime_label = ctk.CTkLabel(stats, text="Uptime 00:00:00", text_color="#93c5fd")
        self.uptime_label.pack(anchor="e")

        actions = ctk.CTkFrame(self, corner_radius=12, fg_color=("#111827", "#111827"))
        actions.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        for i in range(7):
            actions.grid_columnconfigure(i, weight=1)

        self.start_btn = ctk.CTkButton(actions, text="Start", command=self.start_sniffing)
        self.start_btn.grid(row=0, column=0, padx=6, pady=8, sticky="ew")
        self.pause_btn = ctk.CTkButton(actions, text="Pause", command=self.toggle_pause, state="disabled")
        self.pause_btn.grid(row=0, column=1, padx=6, pady=8, sticky="ew")
        ctk.CTkButton(actions, text="Clear", command=self.clear_packets).grid(row=0, column=2, padx=6, pady=8, sticky="ew")
        ctk.CTkButton(actions, text="Save PCAP", command=self.save_pcap).grid(row=0, column=3, padx=6, pady=8, sticky="ew")
        ctk.CTkButton(actions, text="Export Alerts", command=self.export_alerts).grid(row=0, column=4, padx=6, pady=8, sticky="ew")
        ctk.CTkButton(actions, text="Detection Settings", command=self.open_settings_window).grid(row=0, column=5, padx=6, pady=8, sticky="ew")
        ctk.CTkButton(actions, text="Alert History", command=self.show_alerts_history).grid(row=0, column=6, padx=6, pady=8, sticky="ew")

        filters = ctk.CTkFrame(self, corner_radius=12, fg_color=("#111827", "#111827"))
        filters.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))
        filters.grid_columnconfigure(1, weight=1)
        filters.grid_columnconfigure(4, weight=1)

        ctk.CTkLabel(filters, text="BPF").grid(row=0, column=0, padx=(12, 4), pady=8, sticky="w")
        self.bpf_entry = ctk.CTkEntry(filters, placeholder_text="tcp port 443 and host 192.168.1.10")
        self.bpf_entry.grid(row=0, column=1, padx=4, pady=8, sticky="ew")

        self.capture_preset_var = ctk.StringVar(value="None")
        ctk.CTkOptionMenu(
            filters,
            variable=self.capture_preset_var,
            values=list(CAPTURE_PRESETS.keys()),
            command=self._apply_capture_preset,
        ).grid(row=0, column=2, padx=4, pady=8, sticky="ew")

        ctk.CTkLabel(filters, text="Search").grid(row=0, column=3, padx=(8, 4), pady=8, sticky="w")
        self.search_var = ctk.StringVar(value="")
        self.search_var.trace_add("write", lambda *_: self._rebuild_event_rail())
        self.search_entry = ctk.CTkEntry(filters, textvariable=self.search_var, placeholder_text="src/dst/proto/info")
        self.search_entry.grid(row=0, column=4, padx=4, pady=8, sticky="ew")

        self.auto_scroll_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(filters, text="Auto Scroll", variable=self.auto_scroll_var).grid(row=0, column=5, padx=8, pady=8)

        self.max_view_var = ctk.StringVar(value="700")
        self.max_view_var.trace_add("write", lambda *_: self._rebuild_event_rail())
        ctk.CTkEntry(filters, textvariable=self.max_view_var, width=70).grid(row=0, column=6, padx=(4, 12), pady=8)

        main = ctk.CTkFrame(self, corner_radius=12, fg_color=("#0b1020", "#0b1020"))
        main.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 12))
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(1, weight=1)

        proto_wrap = ctk.CTkFrame(main, fg_color="transparent")
        proto_wrap.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 0))
        self.proto_vars = {}
        for idx, proto in enumerate(DISPLAY_PROTOCOLS):
            var = ctk.BooleanVar(value=True)
            self.proto_vars[proto] = var
            ctk.CTkCheckBox(proto_wrap, text=proto, variable=var, command=self._rebuild_event_rail).grid(
                row=0,
                column=idx,
                padx=8,
                pady=4,
                sticky="w",
            )

        rail_card = ctk.CTkFrame(main, corner_radius=10, fg_color=("#121a2a", "#121a2a"))
        rail_card.grid(row=1, column=0, sticky="nsew", padx=(10, 6), pady=10)
        rail_card.grid_rowconfigure(1, weight=1)
        rail_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(rail_card, text="Traffic Rail", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        self.rail = ctk.CTkScrollableFrame(rail_card, fg_color=("#0f172a", "#0f172a"), corner_radius=8)
        self.rail.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        inspect_card = ctk.CTkFrame(main, corner_radius=10, fg_color=("#121a2a", "#121a2a"))
        inspect_card.grid(row=1, column=1, sticky="nsew", padx=(6, 10), pady=10)
        inspect_card.grid_rowconfigure(2, weight=1)
        inspect_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(inspect_card, text="Inspector", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 4))

        self.inspect_mode = ctk.StringVar(value="details")
        ctk.CTkSegmentedButton(
            inspect_card,
            values=["details", "hex"],
            variable=self.inspect_mode,
            command=lambda _: self._render_selected(),
        ).grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))

        self.inspect_text = ctk.CTkTextbox(inspect_card, font=("Consolas", 11), fg_color=("#0f172a", "#0f172a"))
        self.inspect_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _apply_capture_preset(self, label):
        self.bpf_entry.delete(0, "end")
        self.bpf_entry.insert(0, CAPTURE_PRESETS.get(label, ""))

    def _tick_metrics(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            s = elapsed % 60
            self.uptime_label.configure(text=f"Uptime {h:02}:{m:02}:{s:02}")

        rate = max(0, self.packet_count - self._packet_count_last_tick)
        self._packet_count_last_tick = self.packet_count
        self.rate_label.configure(text=f"Rate {rate}/s")
        self.after(1000, self._tick_metrics)

    def _enqueue_detector_event(self, payload):
        self.packet_queue.put({"type": "alert", "payload": payload})

    def _enqueue_local_info(self, message):
        self.packet_queue.put({"type": "local", "message": message})

    def _process_ui_queue(self):
        max_events = 120
        processed = 0
        try:
            while processed < max_events:
                event = self.packet_queue.get_nowait()
                try:
                    self._handle_ui_event(event)
                except Exception as ex:
                    print(f"[UI] Event handling error: {ex}")
                processed += 1
        except queue.Empty:
            pass

        delay_ms = 10 if processed >= max_events else 50
        self.after(delay_ms, self._process_ui_queue)

    def _summarize_packet(self, pkt):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        length = len(pkt)

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if pkt.haslayer(TCP):
                proto = "TCP"
                info = f"{pkt[TCP].sport}->{pkt[TCP].dport} flags={pkt[TCP].sprintf('%flags%')}"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info = f"{pkt[UDP].sport}->{pkt[UDP].dport}"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
            else:
                proto = "OTHER"
                info = "IP frame"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src = getattr(pkt[ARP], "psrc", "-")
            dst = getattr(pkt[ARP], "pdst", "-")
            info = "ARP reply" if pkt[ARP].op == 2 else "ARP request"
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
        s = record["summary"]
        proto = s["protocol"]
        pvar = self.proto_vars.get(proto)
        if pvar and not pvar.get():
            return False

        query = self.search_var.get().strip().lower()
        if query:
            combined = " ".join([s["source"], s["destination"], s["protocol"], s["info"]]).lower()
            if query not in combined:
                return False
        return True

    def _max_view_count(self):
        try:
            return max(100, min(int(self.max_view_var.get().strip()), 5000))
        except Exception:
            return 700

    def _active_records(self):
        visible = [r for r in self.packet_records if self._passes_filters(r)]
        return visible[-self._max_view_count() :]

    def _clear_rail_widgets(self):
        for widget in self.rail.winfo_children():
            widget.destroy()

    def _scroll_rail_to_end(self):
        try:
            canvas = getattr(self.rail, "_parent_canvas", None)
            if canvas is not None:
                canvas.yview_moveto(1.0)
        except Exception:
            pass

    def _build_card(self, parent, record):
        s = record["summary"]
        proto = s["protocol"]
        color = PROTO_COLORS.get(proto, "#B0BEC5")
        is_selected = self.selected_no == record["no"]

        card = ctk.CTkFrame(
            parent,
            corner_radius=8,
            fg_color=("#172036", "#172036") if not is_selected else ("#1f2a44", "#1f2a44"),
        )
        card.pack(fill="x", padx=4, pady=4)

        ctk.CTkFrame(card, width=6, fg_color=color, corner_radius=6).pack(side="left", fill="y", padx=(0, 8), pady=0)

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(side="left", fill="both", expand=True, padx=(0, 8), pady=6)

        title = f"#{record['no']}  {s['time']}  [{proto}]  {s['source']} -> {s['destination']}"
        ctk.CTkLabel(body, text=title, anchor="w", font=("Consolas", 12, "bold"), text_color="#e2e8f0").pack(fill="x")
        ctk.CTkLabel(body, text=f"len {s['length']} | {s['info']}", anchor="w", text_color="#94a3b8").pack(fill="x")

        ctk.CTkButton(
            card,
            text="Inspect",
            width=80,
            fg_color=("#334155", "#334155"),
            hover_color=("#475569", "#475569"),
            command=lambda n=record["no"]: self._select_record(n),
        ).pack(side="right", padx=8, pady=8)

    def _rebuild_event_rail(self):
        self._clear_rail_widgets()
        for record in self._active_records():
            self._build_card(self.rail, record)

        if self.auto_scroll_var.get():
            self._scroll_rail_to_end()

    def _select_record(self, no):
        self.selected_no = no
        self._rebuild_event_rail()
        self._render_selected()

    def _find_record(self, no):
        for rec in self.packet_records:
            if rec["no"] == no:
                return rec
        return None

    def _render_selected(self):
        self.inspect_text.delete("1.0", "end")
        if self.selected_no is None:
            self.inspect_text.insert("end", "Select a packet from the traffic rail.")
            return

        rec = self._find_record(self.selected_no)
        if not rec:
            self.inspect_text.insert("end", "Selection not found.")
            return

        pkt = rec["packet"]
        if pkt is None:
            s = rec["summary"]
            self.inspect_text.insert(
                "end",
                f"ALERT\nTime: {s['time']}\nSource: {s['source']}\nDestination: {s['destination']}\n\n{s['info']}",
            )
            return

        try:
            if self.inspect_mode.get() == "details":
                self.inspect_text.insert("end", pkt.show(dump=True))
            else:
                self.inspect_text.insert("end", self._format_hex(pkt))
        except Exception as e:
            self.inspect_text.insert("end", f"Failed to render packet: {e}")
    def _append_visible_record(self, record):
        if not self._passes_filters(record):
            return

        self._build_card(self.rail, record)

        # Keep rail size bounded for UI responsiveness.
        children = self.rail.winfo_children()
        overflow = len(children) - self._max_view_count()
        if overflow > 0:
            for widget in children[:overflow]:
                widget.destroy()

        if self.auto_scroll_var.get():
            self._scroll_rail_to_end()

    def _handle_ui_event(self, event):
        kind = event.get("type")

        if kind == "packet":
            if self.paused:
                return
            rec = event["record"]
            self.packet_records.append(rec)
            self.packet_count += 1
            self.counter_label.configure(text=f"Packets {self.packet_count}")
            self._append_visible_record(rec)
            if self.selected_no is None:
                self.selected_no = rec["no"]
                self._render_selected()
            return

        if kind == "alert":
            t, src, dst, alert_proto = event["payload"]
            msg = alert_proto.replace("ALERT:", "").strip()
            self.alert_count += 1
            self.alert_label.configure(text=f"Alerts {self.alert_count}")

            self.packet_counter += 1
            rec = {
                "no": self.packet_counter,
                "summary": {
                    "time": t,
                    "source": src,
                    "destination": dst,
                    "protocol": "ALERT",
                    "length": "-",
                    "info": msg,
                },
                "packet": None,
            }
            self.packet_records.append(rec)
            self._append_visible_record(rec)
            return

        if kind == "local":
            self._log_local(event["message"])

    def _capture_callback(self, pkt):
        self.packet_counter += 1
        rec = {
            "no": self.packet_counter,
            "summary": self._summarize_packet(pkt),
            "packet": pkt,
        }
        self.packet_queue.put({"type": "packet", "record": rec})
        self.detector.submit(pkt)

    def start_sniffing(self):
        if self.sniffing:
            self.stop_sniffing()
            return

        self.sniffing = True
        self.paused = False
        self.start_time = time.time()
        self._packet_count_last_tick = self.packet_count
        self.pause_btn.configure(state="normal", text="Pause")
        self.start_btn.configure(text="Stop", fg_color=("#C62828", "#B71C1C"), hover_color=("#D32F2F", "#C62828"))
        self.status_dot.configure(text_color="#22c55e")

        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def _sniff_loop(self):
        bpf = self.bpf_entry.get().strip()
        self._enqueue_local_info(f"Capture started on {self.name}")
        if bpf:
            self._enqueue_local_info(f"BPF filter: {bpf}")

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
                    self._enqueue_local_info("BPF failed, retrying without BPF")
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
        self.start_btn.configure(text="Start", fg_color=("#2563eb", "#1d4ed8"), hover_color=("#3b82f6", "#2563eb"))
        self.pause_btn.configure(state="disabled", text="Pause")
        self.status_dot.configure(text_color="#64748b")

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.configure(text="Resume" if self.paused else "Pause")
        self._log_local("Display paused" if self.paused else "Display resumed")

    def clear_packets(self):
        self.packet_records = []
        self.packet_count = 0
        self.alert_count = 0
        self.packet_counter = 0
        self.selected_no = None
        self.counter_label.configure(text="Packets 0")
        self.alert_label.configure(text="Alerts 0")
        self.inspect_text.delete("1.0", "end")
        self._rebuild_event_rail()

    def save_pcap(self):
        packets = [r["packet"] for r in self.packet_records if r["packet"] is not None]
        if not packets:
            messagebox.showinfo("Save PCAP", "No packets captured yet.")
            return

        out_dir = Path("data")
        out_dir.mkdir(parents=True, exist_ok=True)
        name = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        target = filedialog.asksaveasfilename(
            title="Save capture",
            initialdir=str(out_dir.resolve()),
            initialfile=name,
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
        )
        if not target:
            return

        wrpcap(target, packets)
        self._log_local(f"Saved {len(packets)} packets to {target}")

    def _log_local(self, message):
        self.packet_counter += 1
        rec = {
            "no": self.packet_counter,
            "summary": {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "source": "local",
                "destination": self.iface,
                "protocol": "OTHER",
                "length": "-",
                "info": message,
            },
            "packet": None,
        }
        self.packet_records.append(rec)
        self._append_visible_record(rec)

    def show_alerts_history(self):
        window = ctk.CTkToplevel(self)
        window.title("Alert History")
        window.geometry("980x620")
        window.transient(self)

        text = ctk.CTkTextbox(window, font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=16, pady=16)

        rows = self.logger.recent(200)
        if not rows:
            text.insert("end", "No alerts recorded yet.\n")
            return

        text.insert("end", f"{'TIMESTAMP':<20} | {'SOURCE':<16} | {'DEST':<16} | {'PROTO':<8} | ALERT\n")
        text.insert("end", "-" * 125 + "\n")
        for ts, src, dst, proto, alert_msg in rows:
            t = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            text.insert("end", f"{t:<20} | {src:<16} | {dst:<16} | {proto:<8} | {alert_msg}\n")

    def export_alerts(self):
        out_dir = Path("data")
        out_dir.mkdir(parents=True, exist_ok=True)
        name = f"alerts_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        target = filedialog.asksaveasfilename(
            title="Export alerts",
            initialdir=str(out_dir.resolve()),
            initialfile=name,
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not target:
            return

        count = self.logger.export_csv(target, limit=5000)
        self._log_local(f"Exported {count} alerts to {target}")

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
            text="Apply instantly to running detector. Save to keep across restarts.",
            text_color="gray",
            wraplength=500,
            justify="left",
        ).pack(anchor="w", padx=14, pady=(0, 10))

        fields = ctk.CTkScrollableFrame(frame, height=420)
        fields.pack(fill="both", expand=True, padx=12, pady=10)
        fields.grid_columnconfigure(1, weight=1)

        self.settings_vars = {}
        defaults = default_settings()
        for idx, (key, label, _cast) in enumerate(SETTING_FIELDS):
            ctk.CTkLabel(fields, text=label).grid(row=idx, column=0, sticky="w", padx=8, pady=8)
            var = ctk.StringVar(value=str(self.detection_settings.get(key, defaults[key])))
            ctk.CTkEntry(fields, textvariable=var).grid(row=idx, column=1, sticky="ew", padx=8, pady=8)
            self.settings_vars[key] = var

        self.settings_status = ctk.CTkLabel(frame, text="", text_color="gray")
        self.settings_status.pack(anchor="w", padx=14, pady=(6, 2))

        buttons = ctk.CTkFrame(frame, fg_color="transparent")
        buttons.pack(fill="x", padx=12, pady=(8, 12))
        buttons.grid_columnconfigure(0, weight=1)
        buttons.grid_columnconfigure(1, weight=1)
        buttons.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(buttons, text="Apply", command=lambda: self.apply_settings(False)).grid(row=0, column=0, padx=6, sticky="ew")
        ctk.CTkButton(buttons, text="Save", command=lambda: self.apply_settings(True)).grid(row=0, column=1, padx=6, sticky="ew")
        ctk.CTkButton(buttons, text="Reset", command=self.reset_default_settings).grid(row=0, column=2, padx=6, sticky="ew")

    def _collect_settings_from_ui(self):
        raw = {}
        for key, _label, cast_type in SETTING_FIELDS:
            v = self.settings_vars[key].get().strip()
            raw[key] = int(v) if cast_type is int else float(v)
        return raw

    def apply_settings(self, persist=False):
        try:
            validated = validate_settings(self._collect_settings_from_ui())
        except Exception as e:
            if self.settings_status:
                self.settings_status.configure(text=f"Invalid value: {e}", text_color="#FF5252")
            return

        self.detection_settings = validated
        self.detector.update_settings(validated)

        if persist:
            save_settings(validated)
            msg = "Settings saved and applied"
        else:
            msg = "Settings applied"

        if self.settings_status:
            self.settings_status.configure(text=msg, text_color="#22c55e")
        self._log_local(msg + " | " + self._settings_summary(validated))

    def reset_default_settings(self):
        defaults = default_settings()
        for key, _label, _cast in SETTING_FIELDS:
            self.settings_vars[key].set(str(defaults[key]))
        self.apply_settings(True)

    def on_close(self):
        self.sniffing = False
        self.detector.stop(join_timeout=1.0)
        self.destroy()
