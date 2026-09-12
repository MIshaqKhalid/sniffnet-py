#!/usr/bin/env python3
"""
CodeAlpha Internship — Task 1: Basic Network Sniffer
Author   : Ishaq
Purpose  : Capture & analyze network packets (scapy preferred, raw-socket fallback)
Usage    : sudo python3 network_sniffer.py [-i INTERFACE] [-c COUNT] [-f FILTER]
"""

import socket
import struct
import sys
import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Colours ──────────────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; BOLD = "\033[1m"; X = "\033[0m"

BANNER = f"""{C}{BOLD}
 ╔═╗╔═╗╔╦╗╔═╗╔═╗╦  ╔═╗╦ ╦╔═╗  ╔╗╔╔═╗╔╦╗  ╔═╗╔╗╔╦╔═╗╔═╗╔═╗╦═╗
 ║  ║ ║ ║║║╣ ╠═╣║  ╠═╝╠═╣╠═╣  ║║║║╣  ║   ╚═╗║║║║╠╣ ╠╣ ║╣ ╠╦╝
 ╚═╝╚═╝═╩╝╚═╝╩ ╩╩═╝╩  ╩ ╩╩ ╩  ╝╚╝╚═╝ ╩   ╚═╝╝╚╝╩╚  ╚  ╚═╝╩╚═
{X}{G}            CodeAlpha Internship — Task 1: Network Sniffer{X}
{Y}                    Developed by Ishaq | Ethical Use Only{X}
"""

PROTO_MAP = {1:"ICMP", 6:"TCP", 17:"UDP", 2:"IGMP", 41:"IPv6", 89:"OSPF"}
stats        = defaultdict(int)
packet_count = 0

# ── Helpers ───────────────────────────────────────────────────────────────────
def ts():       return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
def div():      print(f"{C}{'─'*68}{X}")
def fmt_mac(b): return ":".join(f"{x:02x}" for x in b)
def fmt_ip(b):  return ".".join(str(x) for x in b)

def hex_dump(data, indent=4):
    lines = []
    for i in range(0, min(len(data), 64), 16):
        chunk = data[i:i+16]
        h = " ".join(f"{b:02x}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{' '*indent}{i:04x}  {h:<48}  |{a}|")
    return "\n".join(lines)

def print_stats():
    print(f"\n{BOLD}{C}{'═'*50}{X}")
    print(f"{BOLD}{G}  CAPTURE SUMMARY{X}")
    print(f"{C}{'═'*50}{X}")
    print(f"  Total Packets : {Y}{packet_count}{X}")
    for p, n in sorted(stats.items(), key=lambda x: -x[1]):
        bar = f"{M}{'█' * min(n, 28)}{X}"
        print(f"  {p:<12} {bar} {n}")
    print(f"{C}{'═'*50}{X}\n")

# ── SCAPY handler ─────────────────────────────────────────────────────────────
def scapy_handler(pkt):
    global packet_count
    packet_count += 1
    div()
    print(f"{BOLD}{G}[#{packet_count}]  {ts()}{X}")

    if IP not in pkt:
        return

    ip = pkt[IP]
    pname = PROTO_MAP.get(ip.proto, f"PROTO-{ip.proto}")
    stats[pname] += 1
    print(f"  {Y}[IP]{X}  {C}{ip.src}{X} → {C}{ip.dst}{X}  proto={M}{pname}{X}  ttl={ip.ttl}  len={ip.len}")

    if TCP in pkt:
        t = pkt[TCP]
        flags = t.sprintf("%TCP.flags%")
        print(f"  {Y}[TCP]{X} :{t.sport} → :{t.dport}  flags={R}{flags}{X}  seq={t.seq}")
        service = {80:"HTTP", 443:"HTTPS/TLS", 22:"SSH", 21:"FTP (⚠ plaintext!)",
                   3306:"MySQL", 5432:"PostgreSQL", 25:"SMTP", 110:"POP3", 143:"IMAP"}
        for port in (t.sport, t.dport):
            if port in service:
                colour = R if "plaintext" in service[port] else G
                print(f"  {colour}[{service[port]}]{X}")

    elif UDP in pkt:
        u = pkt[UDP]
        print(f"  {Y}[UDP]{X} :{u.sport} → :{u.dport}  len={u.len}")
        if DNS in pkt:
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:
                print(f"  {B}[DNS Query]{X}   → {dns.qd.qname.decode(errors='replace')}")
            elif dns.qr == 1 and dns.an:
                print(f"  {B}[DNS Answer]{X}  ← {dns.an.rdata}")

    elif ICMP in pkt:
        icmp = pkt[ICMP]
        t_map = {0:"Echo Reply", 8:"Echo Request", 3:"Dest Unreachable", 11:"TTL Exceeded"}
        print(f"  {Y}[ICMP]{X} {t_map.get(icmp.type, f'type={icmp.type}')}")

    if Raw in pkt and len(pkt[Raw].load) > 0:
        print(f"  {Y}[Payload]{X}\n{hex_dump(pkt[Raw].load)}")


def run_scapy(interface=None, count=0, bpf=""):
    print(BANNER)
    print(f"{G}[*] Engine     : Scapy{X}")
    print(f"{G}[*] Interface  : {interface or 'ALL'}{X}")
    print(f"{G}[*] Filter     : {bpf or 'none'}{X}")
    print(f"{G}[*] Count      : {'∞' if count == 0 else count}{X}")
    print(f"{Y}[!] Ctrl+C to stop\n{X}")
    try:
        sniff(iface=interface or None,
              filter=bpf or None,
              prn=scapy_handler,
              count=count,
              store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print_stats()

# ── Raw-socket fallback (Linux) ───────────────────────────────────────────────
def raw_sniffer(count=50):
    print(BANNER)
    print(f"{Y}[!] Scapy not found — using raw sockets (Linux/root only){X}")
    global packet_count
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except (AttributeError, PermissionError) as e:
        print(f"{R}[!] {e}  →  run with sudo or install scapy{X}"); sys.exit(1)

    try:
        while count == 0 or packet_count < count:
            raw, _ = s.recvfrom(65536)
            packet_count += 1
            dst_mac, src_mac, eth_p = fmt_mac(raw[:6]), fmt_mac(raw[6:12]), socket.htons(struct.unpack("!H", raw[12:14])[0])
            div()
            print(f"{BOLD}{G}[#{packet_count}]  {ts()}{X}")
            print(f"  {Y}[ETH]{X} {src_mac} → {dst_mac}  type={eth_p}")

            if eth_p == 8:
                hl = (raw[14] & 15) * 4
                ttl, proto = raw[22], raw[23]
                src_ip = fmt_ip(raw[26:30]); dst_ip = fmt_ip(raw[30:34])
                pname = PROTO_MAP.get(proto, f"PROTO-{proto}")
                stats[pname] += 1
                print(f"  {Y}[IP]{X}  {C}{src_ip}{X} → {C}{dst_ip}{X}  proto={M}{pname}{X}  ttl={ttl}")
                payload = raw[14+hl:]

                if proto == 6:
                    sp, dp = struct.unpack("!HH", payload[:4])
                    off = ((payload[12] >> 4) * 4)
                    flag_byte = payload[13]
                    active = [f for f, b in [("SYN",0x02),("ACK",0x10),("FIN",0x01),
                                              ("RST",0x04),("PSH",0x08)] if flag_byte & b]
                    print(f"  {Y}[TCP]{X} :{sp} → :{dp}  flags={R}{','.join(active) or 'NONE'}{X}")
                    if len(payload) > off:
                        print(f"  {Y}[Payload]{X}\n{hex_dump(payload[off:])}")

                elif proto == 17:
                    sp, dp, ln = struct.unpack("!HHH", payload[:6])
                    print(f"  {Y}[UDP]{X} :{sp} → :{dp}  len={ln}")

                elif proto == 1:
                    t_map = {0:"Echo Reply", 8:"Echo Request", 3:"Unreachable"}
                    print(f"  {Y}[ICMP]{X} {t_map.get(payload[0], str(payload[0]))}")

    except KeyboardInterrupt:
        pass
    finally:
        print_stats()

# ── Entry ─────────────────────────────────────────────────────────────────────
def main():
    import argparse
    p = argparse.ArgumentParser(description="CodeAlpha Task 1 — Network Sniffer")
    p.add_argument("-i", "--interface", help="Interface to sniff on (e.g. eth0)")
    p.add_argument("-c", "--count",     type=int, default=0,  help="Packet count (0=unlimited)")
    p.add_argument("-f", "--filter",    default="",            help="BPF filter (e.g. 'tcp port 80')")
    p.add_argument("--list",            action="store_true",   help="List interfaces and exit")
    args = p.parse_args()

    if args.list:
        if SCAPY_AVAILABLE:
            print(f"{G}Interfaces:{X}")
            for i in get_if_list(): print(f"  {i}")
        else:
            print(f"{R}Install scapy to list interfaces{X}")
        sys.exit(0)

    if SCAPY_AVAILABLE:
        run_scapy(args.interface, args.count, args.filter)
    else:
        raw_sniffer(args.count or 50)

if __name__ == "__main__":
    main()
