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
        from scapy.arch.windows import get_windows_if_list
        
        # Get detailed Windows interface list from Scapy
        try:
            windows_ifaces = get_windows_if_list()
            print(f"\nScanning {len(windows_ifaces)} interfaces...")
            
            # Get active interfaces from psutil
            psutil_stats = psutil.net_if_stats()
            active_interfaces = {name: stats for name, stats in psutil_stats.items() if stats.isup}
            
            for iface in windows_ifaces:
                # Extract information
                name = iface.get('name', 'Unknown')
                description = iface.get('description', '')
                guid = iface.get('guid', '')
                ip = iface.get('ip', '')
                mac = iface.get('mac', '')
                
                # Skip if no valid identifier
                if not guid and not name:
                    continue
                
                # Filter criteria: must have IP or MAC, and be in active list
                has_ip = ip and ip != '0.0.0.0'
                has_mac = mac and mac != '00:00:00:00:00:00'
                
                # Check if interface is up/active
                is_active = False
                for active_name in active_interfaces.keys():
                    if guid in active_name or name in active_name or description in active_name:
                        is_active = True
                        break
                
                # Only include interfaces that are active AND have IP or MAC
                if is_active and (has_ip or has_mac):
                    # Use description as display name (most readable)
                    if description:
                        display_name = description
                    elif name:
                        display_name = name
                    else:
                        display_name = f"Interface {guid[:8]}"
                    
                    # Add IP info to name for clarity
                    if has_ip:
                        display_name = f"{display_name} ({ip})"
                    
                    # The actual interface identifier for Scapy
                    scapy_iface = guid if guid else name
                    
                    # Avoid duplicates
                    if display_name not in interfaces:
                        print(f"  ✓ {display_name}")
                        interfaces[display_name] = scapy_iface
                
        except Exception as e:
            print(f"Error getting Windows interfaces: {e}")
            # Fallback to basic Scapy interface list
            scapy_ifaces = get_if_list()
            print(f"Fallback: Using basic interface list ({len(scapy_ifaces)} found)")
            
            for scapy_iface in scapy_ifaces:
                # Try to clean up the name
                display_name = scapy_iface
                if '\\' in display_name:
                    display_name = display_name.split('\\')[-1]
                display_name = display_name.replace('NPF_', '').replace('{', '').replace('}', '')
                
                interfaces[display_name] = scapy_iface
        
        print(f"\nFiltered to {len(interfaces)} active interfaces\n")
                
    else:  # Linux / macOS
        scapy_ifaces = get_if_list()
        for iface in scapy_ifaces:
            interfaces[iface] = iface
    
    return interfaces

# ---------------- Packet Monitor Window ----------------
class SnifferWindow(ctk.CTkToplevel):
    def __init__(self, iface, name):
        super().__init__()
        self.iface = iface
        self.name = name
        self.title(f"Monitoring - {name}")
        self.geometry("1000x650")
        self.sniffing = False
        self.header_printed = False
        self.packet_count = 0
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header Frame
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(1, weight=1)
        
        # Status indicator
        self.status_indicator = ctk.CTkLabel(header_frame, text="●", font=("Consolas", 24), 
                                            text_color="gray")
        self.status_indicator.grid(row=0, column=0, padx=(0, 10))
        
        # Title and interface info
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.grid(row=0, column=1, sticky="w")
        
        ctk.CTkLabel(title_container, text="Network Interface Monitor", 
                    font=("Segoe UI", 20, "bold")).pack(anchor="w")
        ctk.CTkLabel(title_container, text=f"Interface: {name}", 
                    font=("Segoe UI", 12), text_color="gray").pack(anchor="w")
        
        # Packet counter
        self.counter_label = ctk.CTkLabel(header_frame, text="Packets: 0", 
                                         font=("Segoe UI", 14, "bold"))
        self.counter_label.grid(row=0, column=2, padx=20)

        # Main packet display frame
        display_frame = ctk.CTkFrame(self, corner_radius=10)
        display_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        display_frame.grid_columnconfigure(0, weight=1)
        display_frame.grid_rowconfigure(0, weight=1)
        
        # Packet display with custom colors
        self.packet_display = ctk.CTkTextbox(display_frame, width=920, height=450, 
                                            font=("Consolas", 11), 
                                            fg_color=("#1a1a1a", "#0a0a0a"),
                                            corner_radius=8)
        self.packet_display.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        
        # Configure text tags for colored protocols
        self.packet_display.tag_config("TCP", foreground="#4CAF50")
        self.packet_display.tag_config("UDP", foreground="#2196F3")
        self.packet_display.tag_config("ICMP", foreground="#FF9800")
        self.packet_display.tag_config("OTHER", foreground="#9E9E9E")
        self.packet_display.tag_config("HEADER", foreground="#FFFFFF", font=("Consolas", 11, "bold"))
        self.packet_display.tag_config("TIME", foreground="#64B5F6")
        self.packet_display.tag_config("IP", foreground="#FFD54F")

        # Control panel
        control_frame = ctk.CTkFrame(self, fg_color="transparent")
        control_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        control_frame.grid_columnconfigure(0, weight=1)
        control_frame.grid_columnconfigure(1, weight=1)
        
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

    def clear_display(self):
        self.packet_display.delete("1.0", "end")
        self.header_printed = False
        self.packet_count = 0
        self.counter_label.configure(text="Packets: 0")

    def log_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto_num = packet[IP].proto
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto_num, "OTHER")
            
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
            self.packet_display.insert("end", f"{proto_name}\n", proto_name)
            self.packet_display.see("end")

    def sniff_packets(self):
        try:
            print(f"Starting sniff on interface: {self.iface}")
            sniff(prn=self.log_packet, store=False, iface=self.iface, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            print(f"Sniffing error: {e}")
            self.packet_display.insert("end", f"\n⚠️ Error: {str(e)}\n", "OTHER")
            self.packet_display.insert("end", "Try running as Administrator/sudo\n", "OTHER")
            self.sniffing = False
            self.stop_sniffing()

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            t = threading.Thread(target=self.sniff_packets)
            t.daemon = True
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

# ---------------- Interface Selection Window ----------------
class InterfaceSelector(ctk.CTk):
    def __init__(self, os_name, interfaces):
        super().__init__()
        self.title("Network Intrusion Detection System")
        self.geometry("600x650")
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # Header section
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, pady=(30, 10), padx=30, sticky="ew")
        
        ctk.CTkLabel(header_frame, text="🛡️ NIDS", 
                    font=("Segoe UI", 32, "bold")).pack()
        ctk.CTkLabel(header_frame, text="Network Intrusion Detection System", 
                    font=("Segoe UI", 14), text_color="gray").pack(pady=(5, 0))
        
        # Info card
        info_frame = ctk.CTkFrame(self, corner_radius=10)
        info_frame.grid(row=1, column=0, pady=10, padx=30, sticky="ew")
        
        info_text = f"Operating System: {os_name}\nAvailable Interfaces: {len(interfaces)}"
        ctk.CTkLabel(info_frame, text=info_text, font=("Segoe UI", 12), 
                    justify="left").pack(pady=15, padx=20)
        
        # Interface selection section
        ctk.CTkLabel(self, text="Select Network Interface", 
                    font=("Segoe UI", 18, "bold")).grid(row=2, column=0, pady=(20, 10))
        
        # Scrollable interface list
        self.interface_frame = ctk.CTkScrollableFrame(self, width=520, height=300,
                                                      corner_radius=10)
        self.interface_frame.grid(row=3, column=0, pady=10, padx=30, sticky="nsew")

        for display_name, scapy_iface in interfaces.items():
            # Interface card
            iface_card = ctk.CTkFrame(self.interface_frame, corner_radius=8, 
                                     fg_color=("#2b2b2b", "#1a1a1a"))
            iface_card.pack(pady=8, padx=5, fill="x")
            
            # Interface name and button in same row
            iface_card.grid_columnconfigure(0, weight=1)
            
            ctk.CTkLabel(iface_card, text=display_name, font=("Segoe UI", 13, "bold"),
                        anchor="w").grid(row=0, column=0, padx=15, pady=12, sticky="w")
            
            btn = ctk.CTkButton(iface_card, text="Monitor →", width=120,
                               command=lambda s=scapy_iface, n=display_name: self.open_sniffer_window(s, n),
                               corner_radius=6, font=("Segoe UI", 12),
                               fg_color=("#1976D2", "#1565C0"),
                               hover_color=("#2196F3", "#1976D2"))
            btn.grid(row=0, column=1, padx=15, pady=8)

        # Footer
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.grid(row=4, column=0, pady=(10, 20), padx=30)
        
        ctk.CTkLabel(footer_frame, 
                    text="💡 Tip: You can monitor multiple interfaces simultaneously",
                    font=("Segoe UI", 11), text_color="gray").pack()

    def open_sniffer_window(self, iface, name):
        window = SnifferWindow(iface, name)
        window.focus()

# ---------------- Main ----------------
def main():
    os_name = detect_os()
    interfaces = get_interfaces_for_os(os_name)

    app = InterfaceSelector(os_name, interfaces)
    app.mainloop()

if __name__ == "__main__":
    main()