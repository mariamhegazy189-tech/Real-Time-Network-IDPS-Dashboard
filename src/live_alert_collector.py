import json
import ipaddress
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent.parent / "ids_live.db"
ALERT_FILE = Path.home() / "snort_logs" / "alert_json.txt"
MAX_ALERTS = 10000


def to_int(value):
    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def endpoint(ip, port):
    if not ip:
        return None

    if port is None or port == "":
        return ip

    return f"{ip}:{port}"


def get_connection():
    return sqlite3.connect(DB_FILE)


def add_column_if_missing(cur, table_name, column_name, column_definition):
    cur.execute(f"PRAGMA table_info({table_name})")
    existing_columns = [row[1] for row in cur.fetchall()]

    if column_name not in existing_columns:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")

def setup_database():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT
    )
    """)

    alert_columns = {
        # Old fields kept for dashboard compatibility
        "timestamp": "TEXT",
        "rule": "TEXT",
        "classification": "TEXT",
        "priority": "INTEGER",
        "protocol": "TEXT",
        "src": "TEXT",
        "dst": "TEXT",

        # New Snort JSON fields
        "snort_rule": "TEXT",
        "iface": "TEXT",
        "service": "TEXT",
        "src_addr": "TEXT",
        "src_port": "INTEGER",
        "dst_addr": "TEXT",
        "dst_port": "INTEGER",
        "direction": "TEXT",
        "pkt_len": "INTEGER",
        "action": "TEXT",
        "msg": "TEXT",
        "gid": "INTEGER",
        "sid": "INTEGER",
        "rev": "INTEGER",
        "ttl": "INTEGER",
        "tos": "INTEGER",
        "tcp_flags": "TEXT",
        "icmp_type": "INTEGER",
        "icmp_code": "INTEGER",
        "client_pkts": "INTEGER",
        "client_bytes": "INTEGER",
        "server_pkts": "INTEGER",
        "server_bytes": "INTEGER",
        "raw_json": "TEXT",
    }

    for column_name, column_definition in alert_columns.items():
        add_column_if_missing(cur, "alerts", column_name, column_definition)

    conn.commit()
    conn.close()


def maybe_auto_block(alert):
    """Guarded auto-block: dry-run by default, never enabled implicitly."""
    if os.getenv("IDS_AUTO_BLOCK", "0") != "1":
        return

    if to_int(alert.get("priority")) != 1:
        return

    source = alert.get("src_addr")
    try:
        ip = ipaddress.ip_address(str(source).strip())
    except ValueError:
        print("[AUTO-BLOCK] Skipped invalid source IP.")
        return

    if ip.version != 4 or not ip.is_global:
        print(f"[AUTO-BLOCK] Skipped non-public IPv4 source: {ip}")
        return

    destination = alert.get("dst_addr")
    try:
        if destination and ip == ipaddress.ip_address(str(destination).strip()):
            print("[AUTO-BLOCK] Skipped: source equals destination.")
            return
    except ValueError:
        pass

    # Comma-separated trusted addresses, e.g. "8.8.8.8,1.1.1.1".
    allowlist = set()
    for item in os.getenv("IDS_AUTO_BLOCK_ALLOWLIST", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            trusted_ip = ipaddress.ip_address(item)
            if trusted_ip.version == 4:
                allowlist.add(str(trusted_ip))
        except ValueError:
            print(f"[AUTO-BLOCK] Ignoring invalid allowlist entry: {item}")

    if str(ip) in allowlist:
        print(f"[AUTO-BLOCK] Skipped trusted source: {ip}")
        return

    # Avoid blocking public IPv4 addresses assigned directly to this host.
    import re
    import subprocess

    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        local_ips = set(re.findall(
            r"\\binet\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})/",
            result.stdout,
        ))
        if str(ip) in local_ips:
            print(f"[AUTO-BLOCK] Skipped local host address: {ip}")
            return
    except Exception as exc:
        # Fail closed: do not auto-block if host-address checks fail.
        print(f"[AUTO-BLOCK] Skipped; unable to verify local addresses: {exc}")
        return

    # Dry-run is the default. Real blocking requires BOTH settings.
    if os.getenv("IDS_AUTO_BLOCK_MODE", "dry-run").lower() != "apply":
        print(f"[AUTO-BLOCK] DRY RUN: eligible source {ip}; firewall unchanged.")
        return

    try:
        import ips_controller
        status = ips_controller.block_ip(str(ip))
        if not status.get("ready"):
            print(f"[AUTO-BLOCK] Failed: firewall is not ready for {ip}")
            return
        print(f"[AUTO-BLOCK] Applied firewall block for {ip}.")
    except Exception as exc:
        print(f"[AUTO-BLOCK] Failed for {ip}: {exc}")


def save_alert(alert):
    raw_json = json.dumps(alert, sort_keys=True)

    timestamp = alert.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = alert.get("msg")
    snort_rule = alert.get("rule")
    classification = alert.get("class")
    priority = to_int(alert.get("priority"))
    protocol = alert.get("proto")

    src_addr = alert.get("src_addr")
    src_port = to_int(alert.get("src_port"))
    dst_addr = alert.get("dst_addr")
    dst_port = to_int(alert.get("dst_port"))

    src = endpoint(src_addr, src_port)
    dst = endpoint(dst_addr, dst_port)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM alerts WHERE raw_json = ?", (raw_json,))
    existing_alert = cur.fetchone()

    if existing_alert:
        conn.close()
        return

    cur.execute("""
        INSERT INTO alerts (
            timestamp,
            rule,
            classification,
            priority,
            protocol,
            src,
            dst,
            snort_rule,
            iface,
            service,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            direction,
            pkt_len,
            action,
            msg,
            gid,
            sid,
            rev,
            ttl,
            tos,
            tcp_flags,
            icmp_type,
            icmp_code,
            client_pkts,
            client_bytes,
            server_pkts,
            server_bytes,
            raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,

        # Keep old dashboard compatibility:
        # old "rule" column now stores the readable Snort message.
        msg,

        classification,
        priority,
        protocol,
        src,
        dst,

        # New Snort JSON fields:
        snort_rule,
        alert.get("iface"),
        alert.get("service"),
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        alert.get("dir"),
        to_int(alert.get("pkt_len")),
        alert.get("action"),
        msg,
        to_int(alert.get("gid")),
        to_int(alert.get("sid")),
        to_int(alert.get("rev")),
        to_int(alert.get("ttl")),
        to_int(alert.get("tos")),
        alert.get("tcp_flags"),
        to_int(alert.get("icmp_type")),
        to_int(alert.get("icmp_code")),
        to_int(alert.get("client_pkts")),
        to_int(alert.get("client_bytes")),
        to_int(alert.get("server_pkts")),
        to_int(alert.get("server_bytes")),
        raw_json,
    ))

    cur.execute("""
        DELETE FROM alerts
        WHERE id NOT IN (
            SELECT id
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        )
    """, (MAX_ALERTS,))

    conn.commit()
    conn.close()
    maybe_auto_block(alert)


def follow_alert_file():
    print(f"Watching Snort JSON alert file: {ALERT_FILE}")
    print(f"Writing latest {MAX_ALERTS} alerts to: {DB_FILE}")

    if not ALERT_FILE.exists():
        raise FileNotFoundError(
            f"Snort alert file does not exist: {ALERT_FILE}"
        )

    with open(ALERT_FILE, "r") as f:
        # Start from beginning so already captured JSON alerts also get inserted.
        f.seek(0)

        while True:
            line = f.readline()

            if line:
                line = line.strip()

                if not line:
                    continue

                try:
                    alert = json.loads(line)
                    save_alert(alert)

                    print(
                        f"[ALERT] {alert.get('timestamp')} | "
                        f"{alert.get('msg')} | "
                        f"{alert.get('src_addr')} -> {alert.get('dst_addr')} | "
                        f"Priority: {alert.get('priority')}"
                    )

                except json.JSONDecodeError:
                    print(f"[!] Skipping invalid JSON line: {line[:120]}")

            else:
                time.sleep(0.5)

                try:
                    if ALERT_FILE.stat().st_size < f.tell():
                        print("[*] Alert file was truncated. Resetting reader.")
                        f.seek(0)
                except FileNotFoundError:
                    print("[!] Alert file not found. Waiting...")
                    time.sleep(1)


if __name__ == "__main__":
    setup_database()
    follow_alert_file()
