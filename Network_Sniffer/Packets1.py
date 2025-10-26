import threading
import customtkinter as ctk
from scapy.all import sniff, IP, get_if_list
import datetime

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PacketSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Packet Monitor - NIDS")
        self.geometry("900x600")

        # ---- Interface selection section ----
        self.interface_label = ctk.CTkLabel(self, text="Select Network Interface:")
        self.interface_label.pack(pady=(15, 5))

        self.interfaces = get_if_list()
        self.interface_var = ctk.StringVar(value=self.interfaces[0] if self.interfaces else "No interfaces found")
        self.interface_dropdown = ctk.CTkOptionMenu(self, values=self.interfaces, variable=self.interface_var)
        self.interface_dropdown.pack(pady=(0, 10))

        # ---- Packet display section ----
        self.packet_display = ctk.CTkTextbox(self, width=850, height=450, font=("Consolas", 12))
        self.packet_display.pack(pady=10, padx=20)

        # ---- Start/Stop button ----
        self.start_button = ctk.CTkButton(self, text="Start Monitoring", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.sniffing = False

    def log_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_num = packet[IP].proto
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")

            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto_num, str(proto_num))
            log_msg = f"[{timestamp}]\t|\t{src}\t->\t{dst}\t|\tProtocol: {proto_name}\n"

            if not hasattr(self, "header_printed"):
                header = f"{'Time':<10}\t|\tSource (SRC)\t|\tDestination (DST)\t|\tProtocol\n"
                self.packet_display.insert("end", header)
                self.packet_display.insert("end", "-" * len(header) + "\n")
                self.header_printed = True

            self.packet_display.insert("end", log_msg)
            self.packet_display.see("end")

    def sniff_packets(self, iface):
        sniff(prn=self.log_packet, store=False, iface=iface, stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):
        if not self.sniffing:
            iface = self.interface_var.get()
            self.sniffing = True

            # Disable selection once sniffing starts
            self.interface_dropdown.configure(state="disabled")
            self.start_button.configure(text="Monitoring... (Click to Stop)", command=self.stop_sniffing)

            sniff_thread = threading.Thread(target=self.sniff_packets, args=(iface,))
            sniff_thread.daemon = True
            sniff_thread.start()
        else:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.configure(text="Start Monitoring", command=self.start_sniffing)
        self.interface_dropdown.configure(state="normal")

if __name__ == "__main__":
    app = PacketSnifferGUI()
    app.mainloop()
