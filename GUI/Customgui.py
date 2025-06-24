import customtkinter
import scapy
import threading
from sniffer import start_sniffing

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("600x700")
app.title("Network Intrusion Detection System")

textbox = customtkinter.CTkTextbox(app, width = 580, height = 400, corner_radius = 10)
textbox.pack(pady = 20, padx = 10)

status_label = customtkinter.CTkLabel(app, text = "Status : IDLE", font = ("Arial", 16))
status_label.pack()

sniffing_thread = None
stop_flag = threading.Event()

def SummarizeAndPrint_packet(packet):
    try:
        summary = packet.summary()
        textbox.insert("end", summary + "\n")
        textbox.see("end")

    except Exception as e:
        textbox.insert("end", f"[Error]\t->\t{str(e)}\n")

def start_Monitoring():
    global sniffing_thread
    stop_flag.clear()
    status_label.configure(text = "Status : Monitoring....")
    sniffing_thread = threading.Thread(target = lambda: start_sniffing(SummarizeAndPrint_packet, daemon = True))
    sniffing_thread.start()

def stop_Monitoring():
    status_label.configure(text = "Status: Stopped")
    stop_flag.set()

start_button = customtkinter.CTkButton(app, text = "Start Monitoring", command = start_Monitoring)
start_button.pack(pady = 10)

stop_button = customtkinter.CTkButton(app, text = "Stop Monitoring", command = stop_Monitoring)
stop_button.pack(pady = 10)

app.mainloop()