"""
PacketReaper - Web API Server
Flask backend serving the dashboard and REST API.
Run: sudo python3 server.py
"""

import os
import time
import threading
import json
from collections import deque
from flask import Flask, jsonify, request, send_from_directory, Response

from core.threat_engine import ThreatEngine
from core.sniffer import PacketSniffer
from core.logger import SessionLogger

# ─────────────────────────────────────────────
app    = Flask(__name__, static_folder="dashboard")
engine = ThreatEngine(rules_path="rules/rules.json")
logger = SessionLogger(log_dir="logs")
sniffer: PacketSniffer = None

_running      = False
_live_mode    = False
_recent: deque = deque(maxlen=200)   # last 200 packet records for the feed
_sse_clients  = []
_session_path = None
# ─────────────────────────────────────────────


def _packet_handler(src, dst, sport, dport, proto, size):
    rec = engine.analyze(src, dst, sport, dport, proto, size)
    logger.log(rec)

    entry = {
        "src": rec.src,
        "dst": rec.dst,
        "sport": rec.sport,
        "dport": rec.dport,
        "proto": rec.proto,
        "size": rec.size,
        "action": rec.action,
        "reason": rec.reason,
        "score": rec.threat_score,
        "ts": time.strftime("%H:%M:%S", time.localtime(rec.timestamp)),
    }
    _recent.appendleft(entry)

    # Push to SSE clients
    payload = f"data: {json.dumps(entry)}\n\n"
    dead = []
    for q in _sse_clients:
        try:
            q.put_nowait(payload)
        except Exception:
            dead.append(q)
    for q in dead:
        try: _sse_clients.remove(q)
        except ValueError: pass


# ─────────────────────────────────────────────
# Dashboard static files
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


# ─────────────────────────────────────────────
# API: Control
# ─────────────────────────────────────────────

@app.route("/api/start", methods=["POST"])
def api_start():
    global sniffer, _running, _live_mode, _session_path
    if _running:
        return jsonify({"ok": False, "msg": "Already running"})

    _session_path = logger.start_session()
    sniffer = PacketSniffer(callback=_packet_handler)
    _live_mode = sniffer.start()
    _running   = True
    return jsonify({"ok": True, "live": _live_mode, "session": _session_path})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global sniffer, _running
    if not _running:
        return jsonify({"ok": False, "msg": "Not running"})
    if sniffer:
        sniffer.stop()
        sniffer = None
    result = logger.end_session()
    _running = False
    return jsonify({"ok": True, **result})


@app.route("/api/status")
def api_status():
    snap = engine.snapshot()
    snap["running"] = _running
    snap["live_mode"] = _live_mode
    return jsonify(snap)


# ─────────────────────────────────────────────
# API: Firewall Rules
# ─────────────────────────────────────────────

@app.route("/api/block/ip", methods=["POST"])
def api_block_ip():
    ip     = request.json.get("ip", "").strip()
    reason = request.json.get("reason", "Manual block")
    ttl    = int(request.json.get("ttl", 0))
    if not ip:
        return jsonify({"ok": False, "msg": "No IP provided"})
    ok = engine.block_ip(ip, reason, ttl)
    return jsonify({"ok": ok, "msg": "Blocked" if ok else "Already blocked"})


@app.route("/api/unblock/ip", methods=["POST"])
def api_unblock_ip():
    ip = request.json.get("ip", "").strip()
    ok = engine.unblock_ip(ip)
    return jsonify({"ok": ok})


@app.route("/api/block/port", methods=["POST"])
def api_block_port():
    port = int(request.json.get("port", 0))
    ok   = engine.block_port(port)
    return jsonify({"ok": ok})


@app.route("/api/unblock/port", methods=["POST"])
def api_unblock_port():
    port = int(request.json.get("port", 0))
    ok   = engine.unblock_port(port)
    return jsonify({"ok": ok})


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist():
    ip = request.json.get("ip", "").strip()
    engine.whitelist_ip(ip)
    return jsonify({"ok": True})


@app.route("/api/blocked")
def api_blocked():
    entries = engine.get_blocked_list()
    return jsonify([
        {
            "ip": b.ip, "reason": b.reason,
            "auto": b.auto, "hits": b.hit_count,
            "score": b.threat_score,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(b.timestamp)),
            "ttl": b.ttl,
        }
        for b in entries
    ])


@app.route("/api/blocked/ports")
def api_blocked_ports():
    return jsonify(engine.get_blocked_ports())


@app.route("/api/top_sources")
def api_top_sources():
    return jsonify([{"ip": ip, "count": c} for ip, c in engine.get_top_sources(8)])


@app.route("/api/feed")
def api_feed():
    return jsonify(list(_recent))


# ─────────────────────────────────────────────
# Server-Sent Events for live packet feed
# ─────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    import queue as q_mod
    client_q = q_mod.Queue(maxsize=100)
    _sse_clients.append(client_q)

    def generate():
        try:
            yield "data: {\"ping\":true}\n\n"
            while True:
                try:
                    msg = client_q.get(timeout=15)
                    yield msg
                except Exception:
                    yield "data: {\"ping\":true}\n\n"
        finally:
            try: _sse_clients.remove(client_q)
            except ValueError: pass

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    print(f"\n  🔪 PacketReaper running at http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
