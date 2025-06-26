import customtkinter
import threading
import sys, os
sys.path.append(os.path.abspath("Snipe_the_packets"))
from Sniffer import start_sniffing, handle_packet

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("800x700")
app.title("Network Sniffer")

status_label = customtkinter.CTkLabel(app, text = "Status: Not Sniffing", text_color= "red", font = ('Arial', 10, 'bold'))
status_label.pack(pady = 10)

textbox = customtkinter.CTkTextbox(app, width = 780, height = 400, corner_radius= 10)
textbox.pack(pady = 20, padx = 10)


def packet_printer(text):
    textbox.insert("end", text + "\n")
    textbox.see("end")

def start_monitoring():
    status_label.configure(text = "Status: Sniffing...")
    thread = threading.Thread(target = lambda: start_sniffing(packet_printer), daemon = True)
    thread.start()

start_button = customtkinter.CTkButton(app, text = "Start Sniffing", command = start_monitoring)
start_button.pack(pady = 10)

stop_button = customtkinter.CTkButton(app, text = "Stop Sniffing", command=lambda: status_label.configure(text="Status: Not Sniffing"))
stop_button.pack(pady = 10)

app.mainloop()