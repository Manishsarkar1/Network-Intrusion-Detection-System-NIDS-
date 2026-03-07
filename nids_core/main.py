# main.py
from nids_core.os_utils import detect_os, get_interfaces_for_os
from nids_core.interface_selector import InterfaceSelector

def main():
    os_name = detect_os()
    interfaces = get_interfaces_for_os(os_name)

    app = InterfaceSelector(os_name, interfaces)
    app.mainloop()

if __name__ == "__main__":
    main()