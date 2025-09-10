from scapy.all import sniff

def packet_capture(packet):
    print(packet.summary())

sniff(prn = packet_capture, store = False)