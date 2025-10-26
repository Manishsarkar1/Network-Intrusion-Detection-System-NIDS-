import threading
import customtkinter as ctk
from scapy.all import sniff
import datetime
import psutil

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class InterfaceSelector(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Select Interface - NIDS")
        self.geometry("500x500")

        ctk.CTkLabel(self, text="Select Interface(s) to Monitor", font=("Consolas", 18, "bold")).pack(pady=20)
        self.interface_frame = ctk.CTkScrollableFrame(self, width=400, height=300)
        self.interface_frame.pack(pady=10)

        self.interfaces = self.get_interfaces()
        self.buttons = []

        for name, scapy_iface in self.interfaces.items():
            btn = ctk.CTkButton(self.interface_frame, text=name, width=300, command=lambda s=scapy_iface, n=name: self.open_sniffer_window(s, n))
            btn.pack(pady=5)
            self.buttons.append(btn)

        ctk.CTkLabel(self, text="Click an interface to start monitoring.\nYou can open multiple at once.",
                     font=("Consolas", 12)).pack(pady=10)

    def get_interfaces(self):
        import re
        from scapy.all import get_if_list

        scapy_ifaces = get_if_list()
        psutil_ifaces = psutil.net_if_addrs()

        iface_map = {}
        for name in psutil_ifaces.keys():
            # Try matching friendly name with Npcap device name
            matched = next((iface for iface in scapy_ifaces if re.search(name, iface, re.IGNORECASE)), None)
            if matched:
                iface_map[name] = matched
        if not iface_map:
            for iface in scapy_ifaces:
                iface_map[iface] = iface
        return iface_map

    def open_sniffer_window(self, iface, name):
        SnifferWindow(iface, name)


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
        from scapy.layers.inet import IP
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
            sniff_thread = threading.Thread(target=self.sniff_packets)
            sniff_thread.daemon = True
            sniff_thread.start()
            self.start_button.configure(text="Monitoring... (Click to Stop)", command=self.stop_sniffing)
        else:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.configure(text="Start Monitoring", command=self.start_sniffing)


if __name__ == "__main__":
    app = InterfaceSelector()
    app.mainloop()
