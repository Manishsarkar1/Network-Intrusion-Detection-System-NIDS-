import threading
import customtkinter as ctk
from scapy.all import sniff, IP
import datetime

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PacketSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Packet Monitor - NIDS")
        self.geometry("900x600")
        self.packet_display = ctk.CTkTextbox(self, width = 850, height = 500, font = ("Consolas", 12))
        self.packet_display.pack(pady=20, padx=20)

        self.start_button = ctk.CTkButton(self, text = "Start Monitoring", command = self.start_sniffing)
        self.start_button.pack(pady = 10)

        self.sniffing = False

    def log_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_num = packet[IP].proto
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto_num, str(proto_num))
            log_msg = f"[{timestamp}]\t | \t{src}\t -> \t{dst}\t | \tProtocol: {proto_name}\n"
            if not hasattr(self, "header_printed"):
                header = f"{'Time':<10}\t | \t{src:18}\t | \t{dst:<18}\t | \t{proto_name:<0}\n"
                self.packet_display.insert("end", header)
                self.packet_display.insert("end", "-" * len(header) + "\n")
                self.header_printed = True

            self.packet_display.insert("end", log_msg)
            self.packet_display.see("end")

    def sniff_packets(self):
        sniff(prn = self.log_packet, store = False, stop_filter = lambda x:not self.sniffing)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            sniff_thread = threading.Thread(target = self.sniff_packets)
            sniff_thread.daemon = True
            sniff_thread.start()
            self.start_button.configure(text = "Monitoring... (CLick to stop)", command = self.stop_sniffing)

        else:
            self.stop_sniffing()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.configure(text = "Start Monitoring", command = self.start_sniffing)

if __name__ == "__main__":
    app = PacketSnifferGUI()
    app.mainloop()