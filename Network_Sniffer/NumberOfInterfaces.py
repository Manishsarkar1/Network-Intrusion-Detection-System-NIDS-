from scapy.all import conf
interfaces_table = conf.ifaces
print(f"Number of Network Interfaces: {len(interfaces_table)}")
print("\nList of Interfaces: ")
conf.ifaces.show()