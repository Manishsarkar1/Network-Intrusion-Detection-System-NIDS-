import threading
import platform
import subprocess
import re
import psutil
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP
import customtkinter as ctk
import datetime

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ---------------- OS Detector ----------------
def detect_os():
    return platform.system()

# ---------------- Interface Mapper ----------------
def get_interfaces_for_os(os_name):
    interfaces = {}
    if os_name == "Windows":
        # Fetch Windows friendly names using netsh
        try:
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.splitlines()
            for line in lines[3:]:
                line = line.strip()
                if not line:
                    continue
                cols = re.split(r"\s{2,}", line)
                if len(cols) >= 4:
                    state, admin, type_, name = cols[:4]
                    # Map to scapy iface
                    matched_iface = next((iface for iface in get_if_list() if name in iface), None)
                    interfaces[name] = matched_iface if matched_iface else name
        except Exception:
            # Fallback to psutil names
            for name in psutil.net_if_addrs().keys():
                interfaces[name] = name
    else:  # Linux / macOS
        scapy_ifaces = get_if_list()
        for i, iface in enumerate(scapy_ifaces):
            interfaces[iface] = iface
    return interfaces

# ---------------- Packet Monitor Window ----------------
class SnifferWindow(ctk.CTkToplevel):
    def __init__(self, iface, name):
        super().__init__()
        self.iface = iface
        self.name = name
        self.title(f"Monitoring - {name}")
        self.geometry("900x600")
        self.sniffing = False
        self.header_printed = False

        ctk.CTkLabel(self, text=f"Monitoring Interface: {name}", font=("Consolas", 16, "bold")).pack(pady=10)
        self.packet_display = ctk.CTkTextbox(self, width=850, height=450, font=("Consolas", 12))
        self.packet_display.pack(pady=10, padx=20)

        self.start_button = ctk.CTkButton(self, text="Start Monitoring", command=self.start_sniffing)
        self.start_button.pack(pady=10)

    def log_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_num = packet[IP].proto
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto_num, str(proto_num))

            if not self.header_printed:
                header = f"{'Time':<10}\t | \tSource\t | \tDestination\t | \tProtocol\n"
                self.packet_display.insert("end", header)
                self.packet_display.insert("end", "-" * len(header) + "\n")
                self.header_printed = True

            log_msg = f"[{timestamp}]\t | \t{src}\t -> \t{dst}\t | \tProtocol: {proto_name}\n"
            self.packet_display.insert("end", log_msg)
            self.packet_display.see("end")

    def sniff_packets(self):
        sniff(prn=self.log_packet, store=False, iface=self.iface, stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            t = threading.Thread(target=self.sniff_packets)
            t.daemon = True
            t.start()
            self.start_button.configure(text="Monitoring... (Click to Stop)", command=self.stop_sniffing)
        else:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.configure(text="Start Monitoring", command=self.start_sniffing)

# ---------------- Interface Selection Window ----------------
class InterfaceSelector(ctk.CTk):
    def __init__(self, os_name, interfaces):
        super().__init__()
        self.title("Select Interface - NIDS")
        self.geometry("500x500")
        ctk.CTkLabel(self, text="Select Interface(s) to Monitor", font=("Consolas", 18, "bold")).pack(pady=20)

        self.interface_frame = ctk.CTkScrollableFrame(self, width=400, height=300)
        self.interface_frame.pack(pady=10)

        for display_name, scapy_iface in interfaces.items():
            btn = ctk.CTkButton(self.interface_frame, text=display_name, width=300,
                                command=lambda s=scapy_iface, n=display_name: self.open_sniffer_window(s, n))
            btn.pack(pady=5)

        ctk.CTkLabel(self, text="Click an interface to start monitoring.\nYou can open multiple at once.",
                     font=("Consolas", 12)).pack(pady=10)

    def open_sniffer_window(self, iface, name):
        SnifferWindow(iface, name)

# ---------------- Main ----------------
def main():
    # Detect OS in a thread
    os_name = detect_os()
    interfaces = get_interfaces_for_os(os_name)

    app = InterfaceSelector(os_name, interfaces)
    app.mainloop()

if __name__ == "__main__":
    main()
