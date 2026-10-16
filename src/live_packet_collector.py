from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR
import os
import sqlite3
from pathlib import Path
from datetime import datetime

DB_FILE = Path(__file__).resolve().parent.parent / "ids_live.db"
INTERFACE = os.environ.get("IDS_INTERFACE", "eth0")


def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src TEXT,
        dst TEXT,
        protocol TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        size INTEGER,
        info TEXT,
        tcp_flags TEXT
    )
    """)

    conn.commit()
    conn.close()


def get_tcp_flags(pkt):
    flags = pkt[TCP].flags
    flag_names = []

    if flags & 0x02:
        flag_names.append("SYN")
    if flags & 0x10:
        flag_names.append("ACK")
    if flags & 0x01:
        flag_names.append("FIN")
    if flags & 0x04:
        flag_names.append("RST")
    if flags & 0x08:
        flag_names.append("PSH")
    if flags & 0x20:
        flag_names.append("URG")

    return ",".join(flag_names) if flag_names else "NONE"


def save_packet(pkt):
    src = "unknown"
    dst = "unknown"
    protocol = "OTHER"
    src_port = None
    dst_port = None
    size = len(pkt)
    info = ""
    tcp_flags = None

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = get_tcp_flags(pkt)

            if src_port in [80, 8080] or dst_port in [80, 8080]:
                protocol = "HTTP"
                info = "HTTP traffic"
            elif src_port == 22 or dst_port == 22:
                protocol = "SSH"
                info = "SSH traffic"
            elif src_port == 443 or dst_port == 443:
                protocol = "HTTPS"
                info = "HTTPS traffic"
            else:
                protocol = "TCP"
                info = f"TCP flags: {tcp_flags}"

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                try:
                    text = payload.decode(errors="ignore")
                    if text.startswith("GET"):
                        info = "HTTP GET request"
                    elif text.startswith("POST"):
                        info = "HTTP POST request"
                    elif text.startswith("HEAD"):
                        info = "HTTP HEAD request"
                except Exception:
                    pass

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            if src_port == 53 or dst_port == 53:
                protocol = "DNS"
                info = "DNS traffic"

                if DNS in pkt and pkt[DNS].qd and DNSQR in pkt:
                    try:
                        query = pkt[DNSQR].qname.decode(errors="ignore")
                        info = f"DNS query: {query}"
                    except Exception:
                        pass
            else:
                protocol = "UDP"
                info = "UDP traffic"

        elif ICMP in pkt:
            protocol = "ICMP"

            icmp_type = pkt[ICMP].type
            if icmp_type == 8:
                info = "ICMP Echo Request"
            elif icmp_type == 0:
                info = "ICMP Echo Reply"
            else:
                info = f"ICMP type {icmp_type}"

        else:
            protocol = "IP"
            info = "IP packet"

    elif ARP in pkt:
        protocol = "ARP"
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst

        if pkt[ARP].op == 1:
            info = "ARP Request"
        elif pkt[ARP].op == 2:
            info = "ARP Reply"
        else:
            info = "ARP packet"

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO packets
        (timestamp, src, dst, protocol, src_port, dst_port, size, info, tcp_flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        src,
        dst,
        protocol,
        src_port,
        dst_port,
        size,
        info,
        tcp_flags
    ))

    cur.execute("""
        DELETE FROM packets
        WHERE id < (
            SELECT COALESCE(MAX(id) - 5000, 0)
            FROM packets
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    setup_database()
    print(f"Listening on {INTERFACE}...")
    sniff(iface=INTERFACE, prn=save_packet, store=False)
