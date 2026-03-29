"""
PacketReaper - Threat Engine
Auto-detects port scans, floods, and anomalies.
Manages blocklist with TTL-based expiry and AI anomaly scoring.
"""

import time
import threading
import json
import os
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, Set, Optional, Tuple

# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

@dataclass
class BlockEntry:
    ip: str
    reason: str
    timestamp: float
    auto: bool = True
    ttl: int = 0          # 0 = permanent
    hit_count: int = 1
    threat_score: float = 0.0

@dataclass
class PacketRecord:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    size: int
    timestamp: float
    action: str = "ALLOW"
    reason: str = ""
    threat_score: float = 0.0

@dataclass
class LiveStats:
    total_packets: int = 0
    blocked_packets: int = 0
    alerted_packets: int = 0
    bytes_total: int = 0
    active_blocks: int = 0
    auto_bans: int = 0
    packets_per_sec: float = 0.0


# ─────────────────────────────────────────────
# Anomaly Scorer (lightweight AI-style heuristic)
# ─────────────────────────────────────────────

class AnomalyScorer:
    """
    Scores each IP's behavior from 0.0 (clean) to 1.0 (critical threat).
    Uses entropy of destination ports, packet rate, and size variance
    as features — no external ML library required.
    """

    WINDOW = 15  # seconds

    def __init__(self):
        self._history: Dict[str, deque] = defaultdict(deque)  # ip -> [(ts, dport, size)]

    def record(self, ip: str, dport: int, size: int, ts: float):
        q = self._history[ip]
        q.append((ts, dport, size))
        while q and ts - q[0][0] > self.WINDOW:
            q.popleft()

    def score(self, ip: str) -> float:
        """Returns 0.0–1.0 threat score."""
        q = self._history.get(ip)
        if not q or len(q) < 3:
            return 0.0

        ports = [d for _, d, _ in q]
        sizes = [s for _, _, s in q]
        n = len(q)
        duration = max(q[-1][0] - q[0][0], 0.001)

        # Feature 1: Port entropy (high entropy = scanning many ports)
        port_counts = defaultdict(int)
        for p in ports:
            port_counts[p] += 1
        total = sum(port_counts.values())
        entropy = -sum((c/total) * math.log2(c/total) for c in port_counts.values() if c > 0)
        max_entropy = math.log2(max(len(port_counts), 1))
        entropy_score = (entropy / max_entropy) if max_entropy > 0 else 0

        # Feature 2: Packet rate (normalized to flood threshold)
        pps = n / duration
        rate_score = min(pps / 60.0, 1.0)

        # Feature 3: Size variance (bursty uniform sizes = flood tool)
        if len(sizes) > 1:
            mean_s = sum(sizes) / len(sizes)
            variance = sum((s - mean_s) ** 2 for s in sizes) / len(sizes)
            # Low variance at high rate = synthetic/flood
            cv = math.sqrt(variance) / (mean_s + 1)
            size_score = max(0.0, 1.0 - cv) * rate_score
        else:
            size_score = 0.0

        # Weighted combination
        final = (entropy_score * 0.45) + (rate_score * 0.35) + (size_score * 0.20)
        return round(min(final, 1.0), 3)


# ─────────────────────────────────────────────
# Threat Engine
# ─────────────────────────────────────────────

class ThreatEngine:
    PORTSCAN_UNIQUE_PORTS  = 12
    FLOOD_PPS_THRESHOLD    = 70
    RATE_WINDOW            = 10
    AUTO_BAN_TTL           = 600
    ANOMALY_BAN_THRESHOLD  = 0.78

    def __init__(self, rules_path: str = "rules/rules.json"):
        self.rules_path = rules_path
        self.blocked_ips: Dict[str, BlockEntry] = {}
        self.blocked_ports: Set[int] = set()
        self.allowed_ips: Set[str] = set()

        self._ip_ts: Dict[str, deque] = defaultdict(deque)
        self._ip_ports: Dict[str, deque] = defaultdict(deque)
        self._source_counts: Dict[str, int] = defaultdict(int)
        self._pps_window: deque = deque()

        self.scorer = AnomalyScorer()
        self.stats = LiveStats()
        self._lock = threading.Lock()
        self._load_rules()

        threading.Thread(target=self._ttl_loop, daemon=True).start()

    # ── Persistence ──

    def _load_rules(self):
        os.makedirs(os.path.dirname(self.rules_path) or ".", exist_ok=True)
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path) as f:
                    data = json.load(f)
                for e in data.get("blocked_ips", []):
                    b = BlockEntry(**e)
                    self.blocked_ips[b.ip] = b
                self.blocked_ports = set(data.get("blocked_ports", []))
                self.allowed_ips   = set(data.get("allowed_ips", []))
            except Exception:
                pass

    def save_rules(self):
        data = {
            "blocked_ips":   [asdict(b) for b in self.blocked_ips.values()],
            "blocked_ports": list(self.blocked_ports),
            "allowed_ips":   list(self.allowed_ips),
        }
        os.makedirs(os.path.dirname(self.rules_path) or ".", exist_ok=True)
        with open(self.rules_path, "w") as f:
            json.dump(data, f, indent=2)

    # ── Public API ──

    def block_ip(self, ip: str, reason: str = "Manual", ttl: int = 0) -> bool:
        with self._lock:
            if ip in self.blocked_ips:
                return False
            self.blocked_ips[ip] = BlockEntry(ip=ip, reason=reason, timestamp=time.time(), auto=False, ttl=ttl)
        self.save_rules()
        return True

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip not in self.blocked_ips:
                return False
            del self.blocked_ips[ip]
        self.save_rules()
        return True

    def block_port(self, port: int) -> bool:
        with self._lock:
            if port in self.blocked_ports:
                return False
            self.blocked_ports.add(port)
        self.save_rules(); return True

    def unblock_port(self, port: int) -> bool:
        with self._lock:
            self.blocked_ports.discard(port)
        self.save_rules(); return True

    def whitelist_ip(self, ip: str):
        with self._lock:
            self.allowed_ips.add(ip)
        self.save_rules()

    # ── Core Analysis ──

    def analyze(self, src: str, dst: str, sport: int, dport: int, proto: str, size: int) -> PacketRecord:
        now = time.time()
        with self._lock:
            self.stats.total_packets += 1
            self.stats.bytes_total += size
            self._source_counts[src] += 1
            self._pps_window.append(now)
            while self._pps_window and now - self._pps_window[0] > 1.0:
                self._pps_window.popleft()
            self.stats.packets_per_sec = len(self._pps_window)

            rec = PacketRecord(src=src, dst=dst, sport=sport, dport=dport,
                               proto=proto, size=size, timestamp=now)

            if src in self.allowed_ips:
                rec.action = "ALLOW"; rec.reason = "Whitelisted"; return rec

            if src in self.blocked_ips:
                self.blocked_ips[src].hit_count += 1
                rec.action = "BLOCK"
                rec.reason  = self.blocked_ips[src].reason
                self.stats.blocked_packets += 1
                return rec

            if dport in self.blocked_ports:
                rec.action = "BLOCK"; rec.reason = f"Port {dport} blocked"
                self.stats.blocked_packets += 1
                return rec

            # Heuristic threat detection
            threat, reason = self._heuristic(src, dport, now)
            # AI anomaly scoring
            self.scorer.record(src, dport, size, now)
            score = self.scorer.score(src)
            rec.threat_score = score

            if threat or score >= self.ANOMALY_BAN_THRESHOLD:
                final_reason = reason if threat else f"Anomaly score {score:.2f}"
                self._auto_ban(src, final_reason, score)
                rec.action = "BLOCK"; rec.reason = final_reason
                self.stats.blocked_packets += 1
                self.stats.alerted_packets += 1
                return rec

            if score >= 0.5:
                rec.action = "ALERT"; rec.reason = f"Suspicious (score {score:.2f})"
                self.stats.alerted_packets += 1
                return rec

            rec.action = "ALLOW"
            return rec

    def _heuristic(self, src: str, dport: int, now: float) -> Tuple[bool, str]:
        w = self.RATE_WINDOW
        ts_q = self._ip_ts[src]; ts_q.append(now)
        while ts_q and now - ts_q[0] > w: ts_q.popleft()

        pt_q = self._ip_ports[src]; pt_q.append((now, dport))
        while pt_q and now - pt_q[0][0] > w: pt_q.popleft()

        pps = len(ts_q) / w
        unique_ports = len({p for _, p in pt_q})

        if unique_ports >= self.PORTSCAN_UNIQUE_PORTS:
            return True, f"Port scan ({unique_ports} ports/{w}s)"
        if pps >= self.FLOOD_PPS_THRESHOLD:
            return True, f"Packet flood ({pps:.0f} pps)"
        return False, ""

    def _auto_ban(self, ip: str, reason: str, score: float = 0.0):
        if ip not in self.blocked_ips:
            self.blocked_ips[ip] = BlockEntry(
                ip=ip, reason=reason, timestamp=time.time(),
                auto=True, ttl=self.AUTO_BAN_TTL, threat_score=score
            )
            self.stats.auto_bans += 1

    def _ttl_loop(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [ip for ip, b in self.blocked_ips.items()
                           if b.ttl > 0 and (now - b.timestamp) >= b.ttl]
                for ip in expired:
                    del self.blocked_ips[ip]

    # ── Snapshot helpers ──

    def get_top_sources(self, n=8):
        with self._lock:
            return sorted(self._source_counts.items(), key=lambda x: -x[1])[:n]

    def get_blocked_list(self):
        with self._lock:
            return list(self.blocked_ips.values())

    def get_blocked_ports(self):
        with self._lock:
            return list(self.blocked_ports)

    def snapshot(self) -> dict:
        s = self.stats
        with self._lock:
            return {
                "total": s.total_packets,
                "blocked": s.blocked_packets,
                "alerted": s.alerted_packets,
                "bytes": s.bytes_total,
                "active_blocks": len(self.blocked_ips),
                "auto_bans": s.auto_bans,
                "pps": s.packets_per_sec,
            }
