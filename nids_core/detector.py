# detector.py
import threading
import time
from collections import defaultdict, deque

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP

from nids_core.config import SSH_PORT, VNC_PORTS
from nids_core.settings import default_settings, validate_settings



class Detector:
    def __init__(self, logger=None, gui_callback=None, settings=None):
        self.logger = logger
        self.gui_callback = gui_callback
        self.queue = deque()
        self.lock = threading.Lock()
        self.config_lock = threading.Lock()
        self.running = False
        self.thread = None

        # Detection state trackers
        self.syn_history = defaultdict(lambda: deque())
        self.icmp_history = defaultdict(lambda: deque())
        self.udp_history = defaultdict(lambda: deque())
        self.ssh_attempts = defaultdict(lambda: deque())
        self.vnc_attempts = defaultdict(lambda: deque())

        # ARP poisoning detection
        self.arp_table = {}  # IP -> (MAC, last_seen_timestamp)

        # Alert cooldown to prevent spam
        self.alert_cooldown = {}  # (src, alert_type) -> last_alert_time

        self.settings = default_settings()
        if settings:
            self.update_settings(settings)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._consumer_loop, daemon=True)
        self.thread.start()

    def stop(self, join_timeout=1.0):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=join_timeout)

    def update_settings(self, settings):
        validated = validate_settings(settings)
        with self.config_lock:
            self.settings = validated

    def _cfg(self, key):
        with self.config_lock:
            return self.settings[key]

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

        if pkt.haslayer(ARP):
            self._detect_arp_poisoning(pkt, ts)

        if not pkt.haslayer(IP):
            return

        ip = pkt.getlayer(IP)
        src = ip.src
        dst = ip.dst

        if pkt.haslayer(TCP):
            tcp = pkt.getlayer(TCP)
            self._detect_syn_scan(src, dst, tcp, ts)
            self._detect_ssh_bruteforce(src, dst, tcp, ts)
            self._detect_vnc_bruteforce(src, dst, tcp, ts)

        if pkt.haslayer(ICMP):
            self._detect_icmp_flood(src, dst, ts)

        if pkt.haslayer(UDP):
            self._detect_udp_flood(src, dst, ts)

    def _should_alert(self, src, alert_type):
        key = (src, alert_type)
        now = time.time()
        cooldown_period = self._cfg("alert_cooldown_seconds")

        if key in self.alert_cooldown:
            if now - self.alert_cooldown[key] < cooldown_period:
                return False

        self.alert_cooldown[key] = now
        return True

    def _detect_syn_scan(self, src, dst, tcp, ts):
        flags = int(tcp.flags)
        if (flags & 0x02) and not (flags & 0x10):
            syn_window = self._cfg("syn_window")
            syn_ports_threshold = self._cfg("syn_ports_threshold")

            dq = self.syn_history[src]
            dq.append((ts, tcp.dport))

            while dq and (ts - dq[0][0]) > syn_window:
                dq.popleft()

            unique_ports = {p for _, p in dq}
            if len(unique_ports) >= syn_ports_threshold:
                if self._should_alert(src, "SYN_SCAN"):
                    msg = f"SYN port scan: {len(unique_ports)} unique ports in {syn_window}s"
                    self._alert(ts, src, dst, "TCP", msg)
                dq.clear()

    def _detect_icmp_flood(self, src, dst, ts):
        flood_window = self._cfg("flood_window")
        icmp_flood_threshold = self._cfg("icmp_flood_threshold")

        dq = self.icmp_history[src]
        dq.append(ts)

        while dq and (ts - dq[0]) > flood_window:
            dq.popleft()

        if len(dq) >= icmp_flood_threshold:
            if self._should_alert(src, "ICMP_FLOOD"):
                msg = f"ICMP flood: {len(dq)} packets in {flood_window}s"
                self._alert(ts, src, dst, "ICMP", msg)
            dq.clear()

    def _detect_udp_flood(self, src, dst, ts):
        flood_window = self._cfg("flood_window")
        udp_flood_threshold = self._cfg("udp_flood_threshold")

        dq = self.udp_history[src]
        dq.append(ts)

        while dq and (ts - dq[0]) > flood_window:
            dq.popleft()

        if len(dq) >= udp_flood_threshold:
            if self._should_alert(src, "UDP_FLOOD"):
                msg = f"UDP flood: {len(dq)} packets in {flood_window}s"
                self._alert(ts, src, dst, "UDP", msg)
            dq.clear()

    def _detect_ssh_bruteforce(self, src, dst, tcp, ts):
        if tcp.dport == SSH_PORT:
            flags = int(tcp.flags)
            if (flags & 0x02):
                ssh_failed_login_window = self._cfg("ssh_failed_login_window")
                ssh_failed_login_threshold = self._cfg("ssh_failed_login_threshold")

                key = (src, dst)
                dq = self.ssh_attempts[key]
                dq.append(ts)

                while dq and (ts - dq[0]) > ssh_failed_login_window:
                    dq.popleft()

                if len(dq) >= ssh_failed_login_threshold:
                    if self._should_alert(src, "SSH_BRUTE"):
                        msg = (
                            f"SSH brute force: {len(dq)} connection attempts "
                            f"in {ssh_failed_login_window}s"
                        )
                        self._alert(ts, src, dst, "SSH", msg)
                    dq.clear()

    def _detect_vnc_bruteforce(self, src, dst, tcp, ts):
        if tcp.dport in VNC_PORTS:
            flags = int(tcp.flags)
            if (flags & 0x02):
                vnc_failed_login_window = self._cfg("vnc_failed_login_window")
                vnc_failed_login_threshold = self._cfg("vnc_failed_login_threshold")

                key = (src, dst, tcp.dport)
                dq = self.vnc_attempts[key]
                dq.append(ts)

                while dq and (ts - dq[0]) > vnc_failed_login_window:
                    dq.popleft()

                if len(dq) >= vnc_failed_login_threshold:
                    if self._should_alert(src, f"VNC_BRUTE_{tcp.dport}"):
                        msg = (
                            f"VNC brute force: {len(dq)} attempts to port {tcp.dport} "
                            f"in {vnc_failed_login_window}s"
                        )
                        self._alert(ts, src, dst, "VNC", msg)
                    dq.clear()

    def _detect_arp_poisoning(self, pkt, ts):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            arp = pkt[ARP]
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc

            if sender_ip in self.arp_table:
                known_mac, _ = self.arp_table[sender_ip]
                if known_mac != sender_mac:
                    if self._should_alert(sender_ip, "ARP_POISON"):
                        msg = (
                            f"ARP poisoning: IP {sender_ip} claimed by MAC {sender_mac} "
                            f"(previously {known_mac})"
                        )
                        self._alert(ts, sender_mac, sender_ip, "ARP", msg)

            self.arp_table[sender_ip] = (sender_mac, ts)

    def _alert(self, ts, src, dst, proto, message):
        if self.logger:
            self.logger.alert(ts, src, dst, proto, message)

        if self.gui_callback:
            tstr = time.strftime("%H:%M:%S", time.localtime(ts))
            self.gui_callback((tstr, src, dst, f"ALERT: {message}"))

        print(
            f"[ALERT] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} "
            f"| {src} -> {dst} | {proto} | {message}"
        )
