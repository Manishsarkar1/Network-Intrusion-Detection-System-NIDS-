from scapy.all import sniff

def handle_packet(packet, printer):
    '''
    Handles each captured packet
    '''
    try:
        summary = packet.summary()
        printer(summary)

    except Exception as e:
        printer(f"[Error] {e}")

def start_sniffing(printer, stop_flag):
    '''
    start sniffing packet and sends summaries to the printer function
    '''
    sniff(
        prn = lambda packet:handle_packet(packet, printer),
        store = False,
        stop_filter =  lambda packet:stop_flag.is_set())