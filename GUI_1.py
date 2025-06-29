import customtkinter
import threading
import sys, os
sys.path.append(os.path.abspath("./Engine"))
from Sniffer import start_sniffing

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("1200x1000")
app.title("Network Sniffer")

status_label = customtkinter.CTkLabel(app, text = "Status: Not Sniffing", text_color= "red", font = ('Arial', 20, 'bold'))
status_label.pack(pady = 10)

main_frame = customtkinter.CTkFrame(app)
main_frame.pack(pady = 10, padx = 10, fill="both", expand=True)

left_frame = customtkinter.CTkFrame(main_frame)
left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

right_frame = customtkinter.CTkFrame(main_frame)
right_frame.pack(side="right", fill="Y", padx=(20, 0))

textbox = customtkinter.CTkTextbox(left_frame, width = 780, height = 400)
textbox.pack(pady = 10, padx = 10, fill="both", expand=True)

def packet_printer(text):
    textbox.insert("end", text + "\n")
    textbox.see("end")

def start_monitoring():
    set_flag.clear()
    status_label.configure(text = "Status: Sniffing...")
    thread = threading.Thread(target = lambda: start_sniffing(packet_printer, set_flag), daemon = True)
    thread.start()

set_flag = threading.Event()

def stop_monitoring():
    set_flag.set()
    status_label.configure(text = "Status: Not Sniffing")

start_button = customtkinter.CTkButton(app, text = "Start Sniffing", command = start_monitoring)
start_button.pack(pady = 10)

stop_button = customtkinter.CTkButton(app, text = "Stop Sniffing", command= stop_monitoring)
stop_button.pack(pady = 10)

app.mainloop()