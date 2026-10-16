import ipaddress
import re
import subprocess

TABLE = "ids_dashboard"
SET = "blocked_ipv4"
CHAIN = "input_guard"


def run_nft(args):
    result = subprocess.run(
        ["sudo", "-n", "/usr/sbin/nft", *args],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or "nft failed"
        )
    return result.stdout.strip()


def validate_ipv4(value):
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("Enter a valid IPv4 address.")

    if (
        ip.version != 4
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_link_local
        or ip.is_reserved
        or ip == ipaddress.ip_address("255.255.255.255")
    ):
        raise ValueError("This IPv4 address is not allowed.")

    return str(ip)


def get_status():
    result = subprocess.run(
        ["sudo", "-n", "/usr/sbin/nft", "list", "table", "inet", TABLE],
        capture_output=True,
        text=True,
        timeout=5,
    )

    if result.returncode != 0:
        return {
            "ready": False,
            "blocked_ips": [],
            "message": "IPS rules are not configured.",
        }

    rules = result.stdout
    has_set = re.search(r"\bset\s+" + SET + r"\b", rules) is not None
    has_chain = re.search(r"\bchain\s+" + CHAIN + r"\b", rules) is not None
    has_hook = (
        has_chain
        and re.search(
            r"chain\s+" + CHAIN + r"\s*\{[^}]*hook input",
            rules,
            re.DOTALL,
        ) is not None
    )
    has_drop = (
        has_chain
        and re.search(r"ip\s+saddr\s+@" + SET + r"\s+counter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\s+drop", rules)
        is not None
    )

    ready = has_set and has_hook and has_drop

    match = re.search(
        r"set\s+" + SET + r"\s*\{(.*?)\}",
        rules,
        re.DOTALL,
    )
    ips = []
    if match:
        ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            match.group(1),
        )

    return {
        "ready": ready,
        "blocked_ips": sorted(set(ips)),
        "message": (
            "Inbound IPv4 blocking rule is active."
            if ready
            else "IPS rules are missing or incomplete."
        ),
    }


def block_ip(value):
    ip = validate_ipv4(value)
    status = get_status()

    if not status["ready"]:
        raise RuntimeError("IPS firewall is not ready.")

    if ip not in status["blocked_ips"]:
        run_nft(["add", "element", "inet", TABLE, SET, "{", ip, "}"])

    return get_status()


def unblock_ip(value):
    ip = validate_ipv4(value)
    status = get_status()

    if not status["ready"]:
        raise RuntimeError("IPS firewall is not ready.")

    if ip in status["blocked_ips"]:
        run_nft(["delete", "element", "inet", TABLE, SET, "{", ip, "}"])

    return get_status()
