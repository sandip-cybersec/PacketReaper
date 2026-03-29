"""
PacketReaper - Packet Sniffer
Live capture via Scapy (root). Falls back to realistic mock traffic generator.
"""

import time
import threading
import random
from typing import Callable, Optional


SCAPY_OK = False
try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from scapy.all import sniff, IP, conf  # type: ignore
        conf.verb = 0
        SCAPY_OK = True
except Exception:
    SCAPY_OK = False


def _proto(pkt) -> str:
    for layer in ("TCP", "UDP", "ICMP"):
        if pkt.haslayer(layer): return layer
    return "OTHER"

def _ports(pkt):
    for layer in ("TCP", "UDP"):
        if pkt.haslayer(layer):
            return pkt[layer].sport, pkt[layer].dport
    return 0, 0


class PacketSniffer:
    def __init__(self, callback: Callable, iface: Optional[str] = None):
        self.callback = callback
        self.iface    = iface
        self._running = False

    def start(self):
        self._running = True
        root = self._is_root()
        target = self._live if (SCAPY_OK and root) else self._mock
        threading.Thread(target=target, daemon=True).start()
        return root and SCAPY_OK   # True = live mode

    def stop(self):
        self._running = False

    def _is_root(self):
        try:
            import os; return os.getuid() == 0
        except AttributeError:
            return False

    def _live(self):
        def handler(pkt):
            if not self._running or not pkt.haslayer("IP"): return
            ip = pkt["IP"]
            sp, dp = _ports(pkt)
            self.callback(src=ip.src, dst=ip.dst, sport=sp, dport=dp,
                          proto=_proto(pkt), size=len(pkt))
        sniff(iface=self.iface, prn=handler, store=False,
              stop_filter=lambda _: not self._running)

    def _mock(self):
        """
        Realistic synthetic traffic:
        - Normal background traffic
        - Occasional port scan bursts
        - Periodic flood simulations
        """
        legit = [
            "192.168.1.10", "192.168.1.22", "10.0.0.5",
            "172.16.0.3",   "10.10.0.99",   "192.168.0.50",
        ]
        attackers = [
            "45.33.32.156", "198.51.100.77", "203.0.113.45",
            "5.188.10.254", "91.108.4.11",   "185.220.101.5",
        ]
        server_dst = "192.168.1.1"
        common_ports = [80, 443, 22, 53, 8080, 3306, 5432, 25, 110, 143]
        scan_ports   = list(range(20, 1024, 7))

        scenario_timer  = time.time()
        scan_active     = False
        flood_active    = False
        scan_ip         = None
        flood_ip        = None
        scan_idx        = 0

        while self._running:
            now = time.time()

            # Every 30s switch scenario
            if now - scenario_timer > 30:
                scenario_timer = now
                scan_active  = random.random() < 0.5
                flood_active = random.random() < 0.3
                scan_ip  = random.choice(attackers) if scan_active  else None
                flood_ip = random.choice(attackers) if flood_active else None
                scan_idx = 0

            # Port scan burst
            if scan_active and scan_ip and scan_idx < len(scan_ports):
                for _ in range(3):
                    if scan_idx >= len(scan_ports): break
                    self.callback(
                        src=scan_ip, dst=server_dst,
                        sport=random.randint(40000, 60000),
                        dport=scan_ports[scan_idx],
                        proto="TCP", size=random.randint(40, 80)
                    )
                    scan_idx += 1
                time.sleep(0.05)
                continue

            # Flood
            if flood_active and flood_ip:
                for _ in range(8):
                    self.callback(
                        src=flood_ip, dst=server_dst,
                        sport=random.randint(1024, 65535),
                        dport=80, proto="UDP",
                        size=random.randint(900, 1400)
                    )
                time.sleep(0.05)
                continue

            # Normal traffic
            src = random.choice(legit)
            proto = random.choices(["TCP", "UDP", "ICMP"], weights=[6, 3, 1])[0]
            dport = random.choice(common_ports)
            self.callback(
                src=src, dst=server_dst,
                sport=random.randint(1024, 65535),
                dport=dport, proto=proto,
                size=random.randint(64, 1460)
            )
            time.sleep(random.uniform(0.05, 0.25))
