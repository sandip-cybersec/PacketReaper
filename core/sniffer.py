"""
PacketReaper - Packet Sniffer
Live capture via Scapy (root). Falls back to realistic mock traffic generator.
Auto-detects the best network interface.
"""

import time
import threading
import random
import subprocess
from typing import Callable, Optional


SCAPY_OK = False
try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from scapy.all import sniff, IP, ARP, conf, get_if_list  # type: ignore
        conf.verb = 0
        SCAPY_OK = True
except Exception:
    SCAPY_OK = False


def _get_best_iface() -> Optional[str]:
    """Auto-detect best interface: prefer eth0/ens*/wlan0 over lo."""
    try:
        ifaces = get_if_list() if SCAPY_OK else []
    except Exception:
        ifaces = []

    # Priority order
    for prefix in ("eth", "ens", "enp", "wlan", "wlp", "wlx", "ens3"):
        for iface in ifaces:
            if iface.startswith(prefix):
                return iface

    # Fallback: anything not loopback
    for iface in ifaces:
        if iface != "lo":
            return iface

    return None  # Scapy will pick default


def _proto(pkt) -> str:
    if SCAPY_OK:
        try:
            from scapy.all import TCP, UDP, ICMP, ARP as SARP
            if pkt.haslayer(SARP): return "ARP"
            if pkt.haslayer(TCP):  return "TCP"
            if pkt.haslayer(UDP):  return "UDP"
            if pkt.haslayer(ICMP): return "ICMP"
        except Exception:
            pass
    return "OTHER"


def _ports(pkt):
    if SCAPY_OK:
        try:
            from scapy.all import TCP, UDP
            for layer in (TCP, UDP):
                if pkt.haslayer(layer):
                    return pkt[layer].sport, pkt[layer].dport
        except Exception:
            pass
    return 0, 0


def _icmp_type(pkt) -> int:
    """Return ICMP type (8 = echo request / ping)."""
    if SCAPY_OK:
        try:
            from scapy.all import ICMP
            if pkt.haslayer(ICMP):
                return pkt[ICMP].type
        except Exception:
            pass
    return -1


class PacketSniffer:
    def __init__(self, callback: Callable, iface: Optional[str] = None):
        self.callback = callback
        self.iface    = iface or _get_best_iface()
        self._running = False

    def start(self) -> bool:
        """Start sniffing. Returns True if live (root + scapy), False if mock."""
        self._running = True
        root   = self._is_root()
        is_live = SCAPY_OK and root
        target  = self._live if is_live else self._mock
        t = threading.Thread(target=target, daemon=True)
        t.start()
        return is_live

    def stop(self):
        self._running = False

    def _is_root(self) -> bool:
        try:
            import os
            return os.getuid() == 0
        except AttributeError:
            return False

    # ── Live Capture ──────────────────────────────────────────────

    def _live(self):
        from scapy.all import IP, ARP as SARP, ICMP

        def handler(pkt):
            if not self._running:
                return

            # ARP packets (no IP layer)
            if pkt.haslayer(SARP):
                arp = pkt[SARP]
                self.callback(
                    src=arp.psrc, dst=arp.pdst,
                    sport=0, dport=0,
                    proto="ARP", size=len(pkt),
                    extra={"arp_op": arp.op}  # 1=who-has, 2=is-at
                )
                return

            if not pkt.haslayer(IP):
                return

            ip   = pkt["IP"]
            sp, dp = _ports(pkt)
            proto  = _proto(pkt)
            extra  = {}

            # ICMP specifics
            if proto == "ICMP":
                extra["icmp_type"] = _icmp_type(pkt)

            # TCP flags
            if proto == "TCP":
                try:
                    from scapy.all import TCP
                    flags = pkt[TCP].flags
                    extra["tcp_flags"] = int(flags)
                except Exception:
                    pass

            self.callback(
                src=ip.src, dst=ip.dst,
                sport=sp, dport=dp,
                proto=proto, size=len(pkt),
                extra=extra
            )

        sniff(
            iface=self.iface,
            prn=handler,
            store=False,
            stop_filter=lambda _: not self._running
        )

    # ── Mock Traffic (when not root / no Scapy) ───────────────────

    def _mock(self):
        legit = [
            "192.168.1.10", "192.168.1.22", "10.0.0.5",
            "172.16.0.3",   "10.10.0.99",   "192.168.0.50",
        ]
        attackers = [
            "45.33.32.156", "198.51.100.77", "203.0.113.45",
            "5.188.10.254", "91.108.4.11",   "185.220.101.5",
        ]
        server_dst   = "192.168.1.1"
        common_ports = [80, 443, 22, 53, 8080, 3306, 5432, 25, 110, 143]
        scan_ports   = list(range(20, 1024, 7))

        scenario_timer = time.time()
        scan_active = flood_active = icmp_active = syn_active = arp_active = False
        scan_ip = flood_ip = icmp_ip = syn_ip = arp_ip = None
        scan_idx = 0

        while self._running:
            now = time.time()

            # Every 30s rotate scenarios
            if now - scenario_timer > 30:
                scenario_timer = now
                scan_active  = random.random() < 0.35
                flood_active = random.random() < 0.25
                icmp_active  = random.random() < 0.35  # ping flood
                syn_active   = random.random() < 0.25  # SYN flood
                arp_active   = random.random() < 0.20  # ARP spoof
                scan_ip  = random.choice(attackers) if scan_active  else None
                flood_ip = random.choice(attackers) if flood_active else None
                icmp_ip  = random.choice(attackers) if icmp_active  else None
                syn_ip   = random.choice(attackers) if syn_active   else None
                arp_ip   = random.choice(attackers) if arp_active   else None
                scan_idx = 0

            # ICMP / ping flood
            if icmp_active and icmp_ip:
                for _ in range(10):
                    self.callback(src=icmp_ip, dst=server_dst,
                                  sport=0, dport=0,
                                  proto="ICMP", size=random.randint(64, 1480),
                                  extra={"icmp_type": 8})
                time.sleep(0.05)
                continue

            # SYN flood
            if syn_active and syn_ip:
                for _ in range(8):
                    self.callback(src=syn_ip, dst=server_dst,
                                  sport=random.randint(1024, 65535), dport=80,
                                  proto="TCP", size=random.randint(40, 60),
                                  extra={"tcp_flags": 2})  # SYN flag = 0x02
                time.sleep(0.05)
                continue

            # ARP spoof
            if arp_active and arp_ip:
                for _ in range(4):
                    self.callback(src=arp_ip, dst=server_dst,
                                  sport=0, dport=0,
                                  proto="ARP", size=28,
                                  extra={"arp_op": 2})  # is-at (gratuitous)
                time.sleep(0.1)
                continue

            # Port scan
            if scan_active and scan_ip and scan_idx < len(scan_ports):
                for _ in range(3):
                    if scan_idx >= len(scan_ports):
                        break
                    self.callback(src=scan_ip, dst=server_dst,
                                  sport=random.randint(40000, 60000),
                                  dport=scan_ports[scan_idx],
                                  proto="TCP", size=random.randint(40, 80),
                                  extra={"tcp_flags": 2})
                    scan_idx += 1
                time.sleep(0.05)
                continue

            # UDP flood
            if flood_active and flood_ip:
                for _ in range(8):
                    self.callback(src=flood_ip, dst=server_dst,
                                  sport=random.randint(1024, 65535), dport=80,
                                  proto="UDP", size=random.randint(900, 1400),
                                  extra={})
                time.sleep(0.05)
                continue

            # Normal traffic
            src   = random.choice(legit)
            proto = random.choices(["TCP", "UDP", "ICMP"], weights=[6, 3, 1])[0]
            dport = random.choice(common_ports)
            extra = {}
            if proto == "ICMP":
                extra["icmp_type"] = 8
            elif proto == "TCP":
                extra["tcp_flags"] = 16  # ACK = normal traffic

            self.callback(src=src, dst=server_dst,
                          sport=random.randint(1024, 65535), dport=dport,
                          proto=proto, size=random.randint(64, 1460),
                          extra=extra)
            time.sleep(random.uniform(0.05, 0.25))
