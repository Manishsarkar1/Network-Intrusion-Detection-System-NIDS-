from scapy.all import get_if_list

interfaces_list = get_if_list()

num_interfaces = len(interfaces_list)
print(f"Number of Network Interfaces: {num_interfaces}")

print("\nList of interface names: ")
print(interfaces_list)