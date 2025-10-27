# interface_selector.py
import customtkinter as ctk
from os_utils import detect_os, get_interfaces_for_os
from sniffer_window import SnifferWindow

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

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
        # Create the sniffer window
        window = SnifferWindow(iface, name)

        # Keep the interface selector in background
        window.transient(self)      # Associate with main window
        window.lift()               # Bring new window to front once
    # Do NOT call window.focus() – this prevents stealing focus repeatedly
