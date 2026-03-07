# detector.py
import threading
import time
from collections import defaultdict, deque
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

# Import configuration
try:
    from nids_core.config import *
except ImportError:
    # Fallback defaults if config.py not found
    SYN_WINDOW = 5.0
    SYN_PORTS_THRESHOLD = 10
    FLOOD_WINDOW = 5.0
    ICMP_FLOOD_THRESHOLD = 50
    UDP_FLOOD_THRESHOLD = 200
    SSH_PORT = 22
    SSH_FAILED_LOGIN_WINDOW = 60.0
    SSH_FAILED_LOGIN_THRESHOLD = 5
    VNC_PORTS = [5900, 5901, 5902, 5903]
    VNC_FAILED_LOGIN_WINDOW = 60.0
    VNC_FAILED_LOGIN_THRESHOLD = 5
    ARP_WINDOW = 30.0
    ARP_CONFLICT_THRESHOLD = 2

def proto_name(num):
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(num, "OTHER")

class Detector:
    def __init__(self, logger=None, gui_callback=None):
        self.logger = logger
        self.gui_callback = gui_callback
        self.queue = deque()
        self.lock = threading.Lock()
        self.running = False

        # Detection state trackers
        self.syn_history = defaultdict(lambda: deque())
        self.icmp_history = defaultdict(lambda: deque())
        self.udp_history = defaultdict(lambda: deque())
        self.ssh_attempts = defaultdict(lambda: deque())
        self.vnc_attempts = defaultdict(lambda: deque())
        
        # ARP poisoning detection
        self.arp_table = {}  # IP -> (MAC, last_seen_timestamp)
        self.arp_conflicts = defaultdict(lambda: deque())
        
        # Alert cooldown to prevent spam
        self.alert_cooldown = {}  # (src, alert_type) -> last_alert_time
        self.cooldown_period = 10.0  # seconds

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._consumer_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def submit(self, pkt):
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
                print(f"[DETECTOR] Analysis error: {e}")

    def _analyze(self, pkt):
        ts = time.time()
        
        # ARP Detection (Layer 2)
        if pkt.haslayer(ARP):
            self._detect_arp_poisoning(pkt, ts)
        
        # IP-based analysis
        if not pkt.haslayer(IP):
            return

        ip = pkt.getlayer(IP)
        src = ip.src
        dst = ip.dst
        pnum = ip.proto
        pname = proto_name(pnum)

        # Notify GUI of normal traffic
        if self.gui_callback:
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            self.gui_callback((tstr, src, dst, pname))

        # TCP-based detections
        if pkt.haslayer(TCP):
            tcp = pkt.getlayer(TCP)
            self._detect_syn_scan(src, dst, tcp, ts)
            self._detect_ssh_bruteforce(src, dst, tcp, ts)
            self._detect_vnc_bruteforce(src, dst, tcp, ts)

        # ICMP flood detection
        if pkt.haslayer(ICMP):
            self._detect_icmp_flood(src, dst, ts)

        # UDP flood detection
        if pkt.haslayer(UDP):
            self._detect_udp_flood(src, dst, ts)

    def _should_alert(self, src, alert_type):
        """Check if enough time has passed since last alert of this type"""
        key = (src, alert_type)
        now = time.time()
        
        if key in self.alert_cooldown:
            if now - self.alert_cooldown[key] < self.cooldown_period:
                return False
        
        self.alert_cooldown[key] = now
        return True

    def _detect_syn_scan(self, src, dst, tcp, ts):
        """Detect SYN port scanning"""
        flags = int(tcp.flags)
        if (flags & 0x02) and not (flags & 0x10):  # SYN without ACK
            dq = self.syn_history[src]
            dq.append((ts, tcp.dport))
            
            # Expire old entries
            while dq and (ts - dq[0][0]) > SYN_WINDOW:
                dq.popleft()
            
            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= SYN_PORTS_THRESHOLD:
                if self._should_alert(src, "SYN_SCAN"):
                    msg = f"SYN port scan: {len(unique_ports)} unique ports in {SYN_WINDOW}s"
                    self._alert(ts, src, dst, "TCP", msg)
                dq.clear()

    def _detect_icmp_flood(self, src, dst, ts):
        """Detect ICMP flood (ping flood)"""
        dq = self.icmp_history[src]
        dq.append(ts)
        
        while dq and (ts - dq[0]) > FLOOD_WINDOW:
            dq.popleft()
        
        if len(dq) >= ICMP_FLOOD_THRESHOLD:
            if self._should_alert(src, "ICMP_FLOOD"):
                msg = f"ICMP flood: {len(dq)} packets in {FLOOD_WINDOW}s"
                self._alert(ts, src, dst, "ICMP", msg)
            dq.clear()

    def _detect_udp_flood(self, src, dst, ts):
        """Detect UDP flood"""
        dq = self.udp_history[src]
        dq.append(ts)
        
        while dq and (ts - dq[0]) > FLOOD_WINDOW:
            dq.popleft()
        
        if len(dq) >= UDP_FLOOD_THRESHOLD:
            if self._should_alert(src, "UDP_FLOOD"):
                msg = f"UDP flood: {len(dq)} packets in {FLOOD_WINDOW}s"
                self._alert(ts, src, dst, "UDP", msg)
            dq.clear()

    def _detect_ssh_bruteforce(self, src, dst, tcp, ts):
        """Detect SSH brute force attempts"""
        if tcp.dport == SSH_PORT:
            flags = int(tcp.flags)
            # Track connection attempts (SYN packets)
            if (flags & 0x02):  # SYN
                key = (src, dst)
                dq = self.ssh_attempts[key]
                dq.append(ts)
                
                # Expire old attempts
                while dq and (ts - dq[0]) > SSH_FAILED_LOGIN_WINDOW:
                    dq.popleft()
                
                if len(dq) >= SSH_FAILED_LOGIN_THRESHOLD:
                    if self._should_alert(src, "SSH_BRUTE"):
                        msg = f"SSH brute force: {len(dq)} connection attempts in {SSH_FAILED_LOGIN_WINDOW}s"
                        self._alert(ts, src, dst, "SSH", msg)
                    dq.clear()

    def _detect_vnc_bruteforce(self, src, dst, tcp, ts):
        """Detect VNC brute force attempts"""
        if tcp.dport in VNC_PORTS:
            flags = int(tcp.flags)
            # Track connection attempts
            if (flags & 0x02):  # SYN
                key = (src, dst, tcp.dport)
                dq = self.vnc_attempts[key]
                dq.append(ts)
                
                # Expire old attempts
                while dq and (ts - dq[0]) > VNC_FAILED_LOGIN_WINDOW:
                    dq.popleft()
                
                if len(dq) >= VNC_FAILED_LOGIN_THRESHOLD:
                    if self._should_alert(src, f"VNC_BRUTE_{tcp.dport}"):
                        msg = f"VNC brute force: {len(dq)} attempts to port {tcp.dport} in {VNC_FAILED_LOGIN_WINDOW}s"
                        self._alert(ts, src, dst, "VNC", msg)
                    dq.clear()

    def _detect_arp_poisoning(self, pkt, ts):
        """Detect ARP spoofing/poisoning attacks"""
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            arp = pkt[ARP]
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc
            
            # Check if we've seen this IP before
            if sender_ip in self.arp_table:
                known_mac, _ = self.arp_table[sender_ip]
                
                # Different MAC for same IP - potential poisoning
                if known_mac != sender_mac:
                    if self._should_alert(sender_ip, "ARP_POISON"):
                        msg = f"ARP poisoning: IP {sender_ip} claimed by MAC {sender_mac} (previously {known_mac})"
                        self._alert(ts, sender_mac, sender_ip, "ARP", msg)
            
            # Update ARP table
            self.arp_table[sender_ip] = (sender_mac, ts)

    def _alert(self, ts, src, dst, proto, message):
        """Send alert to logger and GUI"""
        if self.logger:
            self.logger.alert(ts, src, dst, proto, message)
        
        if self.gui_callback:
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            self.gui_callback((tstr, src, dst, f"🚨 ALERT: {message}"))
        
        # Also print to console for debugging
        print(f"[ALERT] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} | {src} → {dst} | {proto} | {message}")