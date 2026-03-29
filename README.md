# 🔪 PacketReaper
### AI-Powered Network Threat Monitor

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Scapy](https://img.shields.io/badge/Scapy-2.5-orange)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)

> A real-time, browser-based firewall and network threat monitor built with Python, Flask and Scapy. Features AI-powered anomaly detection that automatically bans suspicious IPs without any manual input.

---

## 🔍 What is PacketReaper?

PacketReaper is a Blue Team cybersecurity tool designed for network defenders and SOC analysts. It captures live network traffic, analyzes every packet using an AI anomaly scorer, and displays everything in a real-time web dashboard.

Unlike traditional tools that only react to known threats, PacketReaper uses behavioral analysis to detect and block unknown threats automatically.

---

## ✨ Features

- 🟢 **Live Packet Capture** — Real-time traffic sniffing via Scapy
- 🤖 **AI Anomaly Scorer** — Scores every IP from 0.0 to 1.0 using port entropy, packet rate and size variance
- 🚫 **Auto-Ban Engine** — Automatically blocks IPs crossing the threat threshold
- 🔍 **Port Scan Detection** — Detects scanning across 12+ unique ports in 10 seconds
- 💥 **Flood Detection** — Detects traffic floods above 70 packets per second
- 🛡️ **IP Firewall** — Manual block, unblock and whitelist IPs
- 🔒 **Port Firewall** — Block entire ports globally
- 📡 **Real-Time Dashboard** — Web UI with live packet feed via Server-Sent Events
- 📁 **Session Logging** — Every session saved as structured JSON-L logs
- ⏱️ **TTL Auto-Expiry** — Auto-bans expire after 10 minutes automatically
- 💾 **Persistent Rules** — Blocked IPs and ports saved to rules.json

---

## 📊 Why PacketReaper is Different

| Feature | KALI-SHIELD-PRO | PacketReaper |
|---|---|---|
| Interface | Desktop GUI (needs X11) | Web browser (any OS) |
| Blocking | IP only | IP + Port + Whitelist |
| Detection | Manual only | AI auto-ban |
| Live Feed | Polling | Server-Sent Events (SSE) |
| Logs | Plain .log files | Structured JSON-L |
| Theme | Green on black | Navy + Amber |

---

## 📁 Project Structure
```
PacketReaper/
├── server.py              # Flask web server + REST API
├── core/
│   ├── threat_engine.py   # AI threat detection + rule engine
│   ├── sniffer.py         # Live Scapy capture + mock mode
│   └── logger.py          # JSON-L session logger
├── dashboard/
│   └── index.html         # Real-time web dashboard
├── rules/
│   └── rules.json         # Persistent block rules
└── logs/                  # Session log files
```

---

## ⚙️ Installation

### Requirements
- Kali Linux or Ubuntu
- Python 3.x

### Step 1 — Clone the repository
```bash
git clone https://github.com/sandip-cybersec/PacketReaper.git
cd PacketReaper
```

### Step 2 — Install dependencies
```bash
pip install flask scapy --break-system-packages
```

### Step 3 — Run PacketReaper
```bash
# With sudo = LIVE mode (captures real packets)
sudo python3 server.py

# Without sudo = DEMO mode (synthetic traffic)
python3 server.py
```

### Step 4 — Open the dashboard
```
http://localhost:8787
```

---

## 🎮 How to Use

1. Click **ENGAGE** to start packet capture
2. Watch packets stream in the live feed
3. Type an IP and click **BLOCK IP** to block manually
4. Type a port number and click **BLOCK** to block a port
5. Watch the AI auto-ban suspicious IPs automatically
6. Click **CEASE** to stop and save the session log

---

## 🔌 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/start` | POST | Start packet capture |
| `/api/stop` | POST | Stop and save session |
| `/api/status` | GET | Live stats snapshot |
| `/api/block/ip` | POST | Block an IP |
| `/api/unblock/ip` | POST | Unblock an IP |
| `/api/block/port` | POST | Block a port |
| `/api/unblock/port` | POST | Unblock a port |
| `/api/whitelist` | POST | Whitelist an IP |
| `/api/blocked` | GET | List all blocked IPs |
| `/api/top_sources` | GET | Top traffic sources |
| `/api/stream` | GET | SSE live packet stream |

---

## 🧠 How the AI Anomaly Scorer Works

Every IP gets a real-time threat score from 0.0 to 1.0 using three behavioral features:

- **Port Entropy** — High entropy means scanning many different ports
- **Packet Rate** — Flood detection via sliding-window packets per second
- **Size Variance** — Low variance at high rate indicates an automated flood tool

IPs crossing the **0.78 threshold** are automatically banned for 10 minutes.

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core language |
| Flask | Web framework and REST API |
| Scapy | Packet capture and analysis |
| HTML / CSS / JS | Frontend dashboard |
| Server-Sent Events | Real-time packet streaming |
| JSON-L | Structured session logging |

---

## 👥 Team

| Member | Role |
|---|---|
| Sandip | Lead Developer |
| Adnan | QA Tester |
| Varun | Technical Writer |
| Chaitanya | Researcher |
| Shalini | Presenter |
| Raghav | DevOps |

---

## ⚠️ Disclaimer

This tool is for educational and authorized network monitoring only. Ensure you have permission before capturing traffic on any network you do not own.

---

## 👤 Author

**sandip-cybersec**
🔗 [github.com/sandip-cybersec](https://github.com/sandip-cybersec)
