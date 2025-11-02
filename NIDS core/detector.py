# detector.py
import threading
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP, UDP, ICMP

# tunables (adjust later or move to config)
SYN_WINDOW = 5.0
SYN_PORTS_THRESHOLD = 10
FLOOD_WINDOW = 5.0
ICMP_FLOOD_THRESHOLD = 50
UDP_FLOOD_THRESHOLD = 200

def proto_name(num):
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(num, "OTHER")

class Detector:
    def __init__(self, logger=None, gui_callback=None):
        self.logger = logger
        self.gui_callback = gui_callback  # function to push (time,src,dst,proto) tuples to GUI
        self.queue = deque()
        self.lock = threading.Lock()
        self.running = False

        # rule state
        self.syn_history = defaultdict(lambda: deque())  # src -> deque of (ts, dport)
        self.icmp_history = defaultdict(lambda: deque()) # src -> deque ts
        self.udp_history = defaultdict(lambda: deque())  # src -> deque ts

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._consumer_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def submit(self, pkt):
        # lightweight enqueue, callable from capture thread
        with self.lock:
            self.queue.append(pkt)

    def _consumer_loop(self):
        while self.running:
            pkt = None
            with self.lock:
                if self.queue:
                    pkt = self.queue.popleft()
            if pkt is None:
                time.sleep(0.01)
                continue

            try:
                self._analyze(pkt)
            except Exception as e:
                # don't crash consumer on single packet parse error
                print("[DETECTOR] analysis error:", e)

    def _analyze(self, pkt):
        # Only IP-based analysis
        if not pkt.haslayer(IP):
            return

        ts = time.time()
        ip = pkt.getlayer(IP)
        src = ip.src
        dst = ip.dst
        pnum = ip.proto
        pname = proto_name(pnum)

        # let GUI know (non-alert line)
        if self.gui_callback:
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            self.gui_callback((tstr, src, dst, pname))

        # --- SYN scan detection ---
        if pkt.haslayer(TCP):
            tcp = pkt.getlayer(TCP)
            flags = int(tcp.flags)
            # SYN and not ACK
            if (flags & 0x02) and not (flags & 0x10):
                dq = self.syn_history[src]
                dq.append((ts, tcp.dport))
                # expire old
                while dq and (ts - dq[0][0]) > SYN_WINDOW:
                    dq.popleft()
                unique_ports = {p for _, p in dq}
                if len(unique_ports) >= SYN_PORTS_THRESHOLD:
                    msg = f"SYN port scan: {len(unique_ports)} unique dst ports in {SYN_WINDOW}s"
                    if self.logger:
                        self.logger.alert(ts, src, dst, "TCP", msg)
                    if self.gui_callback:
                        tstr = time.strftime("%H:%M:%S", time.localtime(ts))
                        self.gui_callback((tstr, src, dst, "ALERT: " + msg))
                    dq.clear()

        # --- ICMP flood detection ---
        if pkt.haslayer(ICMP):
            dq = self.icmp_history[src]
            dq.append(ts)
            while dq and (ts - dq[0]) > FLOOD_WINDOW:
                dq.popleft()
            if len(dq) >= ICMP_FLOOD_THRESHOLD:
                msg = f"ICMP flood: {len(dq)} pkts in {FLOOD_WINDOW}s"
                if self.logger:
                    self.logger.alert(ts, src, dst, "ICMP", msg)
                if self.gui_callback:
                    tstr = time.strftime("%H:%M:%S", time.localtime(ts))
                    self.gui_callback((tstr, src, dst, "ALERT: " + msg))
                dq.clear()

        # --- UDP flood detection ---
        if pkt.haslayer(UDP):
            dq = self.udp_history[src]
            dq.append(ts)
            while dq and (ts - dq[0]) > FLOOD_WINDOW:
                dq.popleft()
            if len(dq) >= UDP_FLOOD_THRESHOLD:
                msg = f"UDP flood: {len(dq)} pkts in {FLOOD_WINDOW}s"
                if self.logger:
                    self.logger.alert(ts, src, dst, "UDP", msg)
                if self.gui_callback:
                    tstr = time.strftime("%H:%M:%S", time.localtime(ts))
                    self.gui_callback((tstr, src, dst, "ALERT: " + msg))
                dq.clear()
