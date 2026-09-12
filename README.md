<div align="center">

# 🛰️ SniffNet

### A colorful, terminal-based packet sniffer & traffic analyzer

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Enabled-00BFA6?style=for-the-badge&logo=wireshark&logoColor=white)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](#-license)
[![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)](#)

</div>

---

## 📖 About

**SniffNet** is a lightweight, terminal-based tool for capturing and inspecting live network traffic in real time. It parses packets down to the protocol layer — IP, TCP, UDP, ICMP, and DNS — and prints color-coded, human-readable breakdowns straight to your console.

It's built with **Scapy** for full-featured packet dissection, and automatically falls back to **raw sockets** if Scapy isn't installed, so it still runs on a bare-bones Linux box.

> ⚠️ **Ethical use only.** This tool is intended for educational purposes and authorized network diagnostics on networks you own or have explicit permission to monitor. See [Disclaimer](#️-disclaimer).

---

## ✨ Features

| | |
|---|---|
| 🎨 | **Color-coded terminal output** for fast visual scanning |
| 🧠 | **Deep packet inspection** — IP, TCP, UDP, ICMP, and DNS layers |
| 🔍 | **Service fingerprinting** — flags HTTP, HTTPS, SSH, FTP, MySQL, SMTP & more |
| 🚨 | **Plaintext protocol warnings** (e.g. FTP) highlighted in red |
| 🧾 | **Hex + ASCII payload dump** for raw packet inspection |
| 📊 | **Live capture summary** with per-protocol packet counts |
| 🧩 | **BPF filter support** (e.g. `tcp port 80`) |
| 🛡️ | **Automatic fallback** to raw sockets when Scapy isn't available |
| 🖧 | **Interface listing** to pick the right NIC before capturing |

---

## 🖥️ Preview

```
 ╔═╗╔╗╔╦╔═╗╔═╗╔╗╔╔═╗╔╦╗
 ╚═╗║║║║╠╣ ╠╣ ║║║║╣  ║
 ╚═╝╝╚╝╩╚  ╚  ╝╚╝╚═╝ ╩
            Terminal Packet Sniffer & Traffic Analyzer
                    Developed by Ishaq | Ethical Use Only

[*] Engine     : Scapy
[*] Interface  : eth0
[*] Filter     : tcp port 443
[*] Count      : ∞

────────────────────────────────────────────────────────────────
[#1]  14:32:07.812
  [IP]  192.168.1.12 → 142.250.190.14  proto=TCP  ttl=64  len=60
  [TCP] :51322 → :443  flags=S  seq=1029384756
  [HTTPS/TLS]
```

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/sniffnet-py.git
cd sniffnet-py

# (Recommended) install Scapy for full packet parsing
pip install scapy
```

> If Scapy isn't installed, the script automatically drops into a raw-socket fallback mode (Linux only, root required).

---

## 🚀 Usage

Packet sniffing requires elevated privileges to open raw sockets:

```bash
sudo python3 network_sniffer.py
```

### Options

| Flag | Description | Example |
|---|---|---|
| `-i`, `--interface` | Interface to sniff on | `-i eth0` |
| `-c`, `--count` | Number of packets to capture (`0` = unlimited) | `-c 100` |
| `-f`, `--filter` | BPF filter expression | `-f "tcp port 80"` |
| `--list` | List available network interfaces and exit | `--list` |

### Examples

```bash
# Capture 50 packets on eth0
sudo python3 network_sniffer.py -i eth0 -c 50

# Capture only HTTP/HTTPS traffic
sudo python3 network_sniffer.py -f "tcp port 80 or tcp port 443"

# List all available interfaces
sudo python3 network_sniffer.py --list
```

Press **`Ctrl+C`** at any time to stop capturing — a summary table of total packets and protocol breakdown will be printed automatically.

---

## 🧩 How It Works

```
┌─────────────┐      ┌────────────────┐      ┌───────────────────┐
│  Raw Packet │ ───▶ │  Parse Layers  │ ───▶ │  Color-coded Print │
│  (NIC/socket)│      │ IP·TCP·UDP·DNS │      │  + Hex/ASCII Dump  │
└─────────────┘      └────────────────┘      └───────────────────┘
                                │
                                ▼
                     ┌────────────────────┐
                     │  Protocol Counters  │
                     │  → Capture Summary  │
                     └────────────────────┘
```

- If **Scapy** is available, it's used for robust, high-level packet parsing (`sniff()`, layer access, DNS decoding).
- If not, the script manually unpacks Ethernet/IP/TCP/UDP headers via `struct` over an `AF_PACKET` raw socket.

---

## 🛠️ Requirements

- Python **3.8+**
- Root/administrator privileges (required to open raw sockets)
- Recommended: [`scapy`](https://pypi.org/project/scapy/)

---

## ⚠️ Disclaimer

This project was built for **educational purposes**. Capturing network traffic without authorization may be **illegal** in your jurisdiction.

Only run this tool on:
- Networks you **own**, or
- Networks you have **explicit written permission** to monitor.

The author and contributors accept no liability for misuse of this software.

---

## 👤 Author

**Muhammad Ishaq Khalid**

---

## 📄 License

Released under the [MIT License](LICENSE) — free to use, modify, and distribute with attribution.

<div align="center">

⭐ If you found this useful, consider giving the repo a star!

</div>
