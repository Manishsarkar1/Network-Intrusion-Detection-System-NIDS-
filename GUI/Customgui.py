import customtkinter

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

app = customtkinter.CTk()
app.geometry("600x700")
app.title("Network Intrusion Detection System")

label = customtkinter.CTkLabel(app, text = "NIDS status: Idle", font = ("Arial", 20))
label.pack(pady = 20)

start_button = customtkinter.CTkButton(app, text = "Start Monitoring")
start_button.pack(pady = 10)

stop_button = customtkinter.CTkButton(app, text = "Stop Monitoring")
stop_button.pack(pady = 10)


app.mainloop()