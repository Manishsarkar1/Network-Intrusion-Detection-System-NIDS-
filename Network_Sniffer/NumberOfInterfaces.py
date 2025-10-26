# from scapy.all import conf
# interfaces_table = conf.ifaces
# print(f"Number of Network Interfaces: {len(interfaces_table)}")
# print("\nList of Interfaces: ")
# conf.ifaces.show()



from scapy.all import get_if_list, get_if_addr, get_if_hwaddr

interfaces = get_if_list()
print("\nDetected Interfaces:")
for i, iface in enumerate(interfaces):
    try:
        ip = get_if_addr(iface)
    except:
        ip = "No IP"
    try:
        mac = get_if_hwaddr(iface)
    except:
        mac = "No MAC"
    print(f"{i+1}. {iface}  |  IP: {ip}  |  MAC: {mac}")
