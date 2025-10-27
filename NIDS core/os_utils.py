# os_utils.py
import platform
import psutil
from scapy.all import get_if_list

def detect_os():
    return platform.system()

def get_interfaces_for_os(os_name):
    interfaces = {}

    if os_name == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            import psutil

            windows_ifaces = get_windows_if_list()
            psutil_stats = psutil.net_if_stats()

            exclude_keywords = [
                'pseudo', 'loopback', 'miniport', 'wan miniport',
                'microsoft kernel debug', 'root enumerator',
                'teredo', 'isatap', '6to4', 'vpn', 'virtual'
            ]

            for iface in windows_ifaces:
                name = iface.get('name', '')
                description = iface.get('description', '')
                guid = iface.get('guid', '')
                scapy_iface = name  # full string like \Device\NPF_{GUID}
                ip = iface.get('ip', '')

                display_name = description if description else name
                display_lower = display_name.lower()

                # Skip unwanted adapters
                if any(keyword in display_lower for keyword in exclude_keywords):
                    continue

                # Skip if interface is down
                is_up = False
                for key in psutil_stats:
                    if guid in key or name in key or description in key:
                        if psutil_stats[key].isup:
                            is_up = True
                        break
                if not is_up:
                    continue

                # Determine adapter type for brackets
                adapter_type = ""
                if "wi-fi" in display_lower or "wlan" in display_lower:
                    adapter_type = "Wi-Fi"
                elif "ethernet" in display_lower or "lan" in display_lower:
                    adapter_type = "Ethernet"
                elif "bridge" in display_lower:
                    adapter_type = "Bridge"
                # else leave empty, but you can add more rules if needed

                if adapter_type:
                    display_name = f"{display_name} ({adapter_type})"

                # Append IP if valid
                if ip and ip != '0.0.0.0':
                    display_name = f"{display_name} ({ip})"

                interfaces[display_name] = scapy_iface

        except Exception:
            from scapy.all import get_if_list
            scapy_ifaces = get_if_list()
            for scapy_iface in scapy_ifaces:
                display_name = scapy_iface
                if '\\' in display_name:
                    display_name = display_name.split('\\')[-1]
                display_name = display_name.replace('NPF_', '').replace('{', '').replace('}', '')
                interfaces[display_name] = scapy_iface

    else:
        # Linux / macOS
        from scapy.all import get_if_list
        scapy_ifaces = get_if_list()
        for iface in scapy_ifaces:
            interfaces[iface] = iface

    return interfaces
