from scapy.all import sniff

capture = sniff(5)
print(capture.summary())