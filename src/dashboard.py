import re
import json
import sqlite3
import hashlib
import subprocess
import html
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_DIR = Path(__file__).resolve().parent.parent
DB_FILE = PROJECT_DIR / "ids_live.db"
RULE_DOC_JSON_FILE = PROJECT_DIR / "data/json/rule_docs_preprocessed_by_sid.json"
SNORT_ALERT_LOG_FILE = Path.home() / "snort_logs" / "alert_json.txt"
ENRICHED_ALERT_JSON_FILE = PROJECT_DIR / "data/json/enriched_snort_alerts_with_rule_docs.json"

# PCAP replay test statistics from the controlled Kali tcpreplay run
PCAP_TOTAL_PACKETS = 135292
PCAP_TOTAL_BYTES = 39277152
PCAP_REPLAY_PPS = 800
PCAP_REPLAY_DURATION_SECONDS = 169.11

DASHBOARD_VERSION = "v4.0"

st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st_autorefresh(interval=10000, key="dashboard_refresh")

st.markdown("""
<style>
.main {
    background-color: #0e1117;
}
.metric-card {
    background: linear-gradient(145deg, #111827, #0d1117);
    padding: 16px 16px 14px 16px;
    border-radius: 14px;
    border: 1px solid #30363d;
    min-height: 102px;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.20);
}
.metric-card:hover {
    border-color: rgba(88, 166, 255, 0.55);
    transform: translateY(-1px);
    transition: all 0.15s ease-in-out;
}
.metric-label {
    color: #c9d1d9;
    font-size: 13px;
    font-weight: 750;
    margin-bottom: 10px;
    white-space: nowrap;
}
.metric-value {
    color: #ffffff;
    font-size: 34px;
    font-weight: 850;
    line-height: 1;
    letter-spacing: -0.5px;
}
.metric-accent {
    width: 34px;
    height: 4px;
    border-radius: 999px;
    margin-top: 14px;
    background: #58a6ff;
}
.metric-accent.red {
    background: #ff4b4b;
}
.metric-accent.orange {
    background: #f59e0b;
}
.metric-accent.green {
    background: #2ea043;
}
.metric-accent.purple {
    background: #a371f7;
}
h1, h2, h3 {
    color: #f0f6fc;
}
.version-pill {
    display: inline-block;
    background: linear-gradient(135deg, #238636, #2ea043);
    color: #ffffff;
    padding: 6px 14px;
    border-radius: 999px;
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.3px;
    border: 1px solid rgba(255, 255, 255, 0.12);
}
.sidebar-card {
    background: transparent;
    border: 0;
    padding: 6px 4px 14px 4px;
    margin-bottom: 14px;
}
.sidebar-title {
    font-size: 22px;
    font-weight: 850;
    color: #f0f6fc;
    margin-bottom: 6px;
}
.sidebar-subtitle {
    font-size: 13px;
    color: #8b949e;
    line-height: 1.45;
}
.sidebar-section-label {
    color: #8b949e;
    font-size: 14px;
    font-weight: 700;
    margin: 26px 0 12px 4px;
}
.sidebar-nav {
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.sidebar-nav-item {
    display: flex;
    align-items: center;
    gap: 13px;
    padding: 13px 12px;
    border-radius: 12px;
    color: #8b949e !important;
    text-decoration: none !important;
    font-size: 17px;
    font-weight: 650;
    border-left: 3px solid transparent;
    transition: all 0.15s ease-in-out;
}
.sidebar-nav-item:hover {
    background-color: rgba(88, 166, 255, 0.10);
    color: #f0f6fc !important;
}
.sidebar-nav-item.active {
    color: #ffffff !important;
    background-color: rgba(255, 255, 255, 0.03);
    border-left: 3px solid #ffffff;
}
.sidebar-nav-icon {
    width: 24px;
    display: inline-flex;
    justify-content: center;
    opacity: 0.95;
}
.sidebar-note {
    border-top: 1px solid #30363d;
    color: #8b949e;
    font-size: 13px;
    line-height: 1.6;
    margin-top: 28px;
    padding-top: 20px;
}
.info-card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 14px;
    padding: 16px 18px;
    margin: 12px 0 18px 0;
}
.selected-alert-card {
    background-color: #111827;
    border-left: 5px solid #ff4b4b;
    border-radius: 12px;
    padding: 14px 18px;
    margin: 14px 0 18px 0;
}
.small-muted {
    color: #8b949e;
    font-size: 13px;
}
.rule-doc-notice {
    background: rgba(46, 160, 67, 0.14);
    border: 1px solid rgba(46, 160, 67, 0.35);
    color: #7ee787;
    border-radius: 12px;
    padding: 12px 14px;
    margin: 8px 0 16px 0;
    font-size: 14px;
    font-weight: 650;
}
.rule-kv-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
    margin: 10px 0 18px 0;
}
.rule-kv-card {
    background: #111827;
    border: 1px solid #30363d;
    border-radius: 14px;
    padding: 14px 16px;
    min-height: 78px;
}
.rule-kv-label {
    color: #8b949e;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.2px;
    text-transform: uppercase;
    margin-bottom: 8px;
}
.rule-kv-value {
    color: #f0f6fc;
    font-size: 21px;
    font-weight: 850;
    line-height: 1.15;
    overflow-wrap: anywhere;
}
.rule-doc-card {
    background: #111827;
    border: 1px solid #30363d;
    border-radius: 16px;
    padding: 18px 20px;
    margin: 14px 0;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.18);
}
.rule-doc-card.accent-blue { border-left: 5px solid #58a6ff; }
.rule-doc-card.accent-green { border-left: 5px solid #2ea043; }
.rule-doc-card.accent-orange { border-left: 5px solid #f59e0b; }
.rule-doc-title {
    color: #f0f6fc;
    font-size: 17px;
    font-weight: 850;
    margin-bottom: 10px;
}
.rule-doc-body {
    color: #c9d1d9;
    font-size: 15px;
    line-height: 1.65;
    overflow-wrap: anywhere;
}
.rule-mini-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-top: 12px;
}
.rule-mini-item {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 12px 14px;
}
.rule-mini-label {
    color: #8b949e;
    font-size: 12px;
    font-weight: 800;
    margin-bottom: 6px;
}
.rule-mini-value {
    color: #f0f6fc;
    font-size: 14px;
    font-weight: 750;
    overflow-wrap: anywhere;
}
.rule-chip-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
}
.rule-chip {
    background: rgba(88, 166, 255, 0.12);
    border: 1px solid rgba(88, 166, 255, 0.35);
    color: #79c0ff;
    border-radius: 999px;
    padding: 6px 11px;
    font-size: 13px;
    font-weight: 750;
}
@media (max-width: 1000px) {
    .rule-kv-grid, .rule-mini-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
</style>
""", unsafe_allow_html=True)


def get_connection():
    return sqlite3.connect(DB_FILE)


def load_table(table_name):
    conn = get_connection()
    try:
        df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def load_query(query):
    conn = get_connection()
    try:
        df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df

@st.cache_data(ttl=10)
def count_raw_alert_lines():
    """
    Count raw Snort JSON alerts from alert_json.txt.
    This shows total alerts written by Snort, while ids_live.db keeps recent alerts.
    """
    try:
        with SNORT_ALERT_LOG_FILE.open("r", encoding="utf-8", errors="ignore") as file:
            return sum(1 for line in file if line.strip().startswith("{"))
    except FileNotFoundError:
        return 0
    except Exception:
        return 0


@st.cache_data(ttl=10)
def load_enriched_alerts_json():
    """
    Load the combined enriched alert JSON export.
    The export contains alert fields from ids_live.db joined with rule documentation.
    """
    if not ENRICHED_ALERT_JSON_FILE.exists():
        return {}

    try:
        with ENRICHED_ALERT_JSON_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def find_enriched_alert_by_id(alert_id):
    """
    Find the selected alert record inside enriched_snort_alerts_with_rule_docs.json.
    """
    enriched_data = load_enriched_alerts_json()
    alerts_list = enriched_data.get("alerts", [])

    try:
        selected_id = int(alert_id)
    except Exception:
        return None

    for item in alerts_list:
        try:
            if int(item.get("alert_id")) == selected_id:
                return item
        except Exception:
            continue

    return None


def load_rule_doc(gid, sid):
    if sid is None or pd.isna(sid):
        return {}

    try:
        sid = int(float(sid))
    except Exception:
        return {}

    try:
        gid = int(float(gid)) if gid is not None and not pd.isna(gid) else 1
    except Exception:
        gid = 1

    df = load_query(f"""
        SELECT *
        FROM rule_docs
        WHERE gid = {gid}
          AND sid = {sid}
        LIMIT 1
    """)

    if df.empty:
        return {}

    return df.iloc[0].to_dict()


def show_doc_field(label, value):
    if value is not None and str(value).strip() not in ["", "nan", "None"]:
        st.markdown(f"**{label}:**")
        st.write(value)


def metric_card(label, value, accent="blue"):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-accent {accent}"></div>
        </div>
        """,
        unsafe_allow_html=True
    )


def normalize_rule_key(value):
    """Convert GID/SID values from alerts into clean JSON lookup keys."""
    if value is None or pd.isna(value):
        return None

    try:
        return str(int(float(value)))
    except Exception:
        text = str(value).strip()
        if text.endswith(".0"):
            text = text[:-2]
        return text if text else None


@st.cache_data(ttl=300)
def load_rule_docs_json():
    """Load the preprocessed JSON rule documentation file."""
    possible_paths = [
        RULE_DOC_JSON_FILE,
        Path("rule_docs_preprocessed_by_sid.json"),
        Path("../data/json/rule_docs_preprocessed_by_sid.json"),
    ]

    for json_path in possible_paths:
        if json_path.exists():
            try:
                with json_path.open("r", encoding="utf-8") as file:
                    return json.load(file)
            except Exception:
                return {}

    return {}


def load_rule_doc_from_json(gid, sid):
    """Fetch a rule document from the SID-keyed preprocessed JSON dataset."""
    docs = load_rule_docs_json()
    if not docs:
        return {}

    sid_key = normalize_rule_key(sid)
    gid_key = normalize_rule_key(gid) or "1"

    if not sid_key:
        return {}

    lookup_keys = [
        sid_key,
        f"{gid_key}:{sid_key}",
        f"{gid_key}-{sid_key}",
    ]

    for key in lookup_keys:
        if key in docs:
            return docs[key]

    return {}


def clean_display_value(value):
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    text = str(value).strip()
    if text.lower() in ["", "nan", "none", "null", "n/a", "na"]:
        return ""
    return text


def render_kv_cards(items):
    cards = []
    for label, value in items:
        value = clean_display_value(value)
        if not value:
            continue
        cards.append(
            '<div class="rule-kv-card">'
            f'<div class="rule-kv-label">{html.escape(str(label))}</div>'
            f'<div class="rule-kv-value">{html.escape(value)}</div>'
            '</div>'
        )
    if cards:
        st.markdown(f'<div class="rule-kv-grid">{"".join(cards)}</div>', unsafe_allow_html=True)


def render_rule_card(title, body, accent="blue"):
    body = clean_display_value(body)
    if not body:
        return
    st.markdown(
        '<div class="rule-doc-card accent-' + html.escape(accent) + '">'
        f'<div class="rule-doc-title">{html.escape(str(title))}</div>'
        f'<div class="rule-doc-body">{html.escape(body)}</div>'
        '</div>',
        unsafe_allow_html=True
    )


def render_mini_grid(items):
    rows = []
    for label, value in items:
        value = clean_display_value(value)
        if not value:
            continue
        rows.append(
            '<div class="rule-mini-item">'
            f'<div class="rule-mini-label">{html.escape(str(label))}</div>'
            f'<div class="rule-mini-value">{html.escape(value)}</div>'
            '</div>'
        )
    if rows:
        st.markdown(f'<div class="rule-mini-grid">{"".join(rows)}</div>', unsafe_allow_html=True)


def render_chip_list(title, values):
    values = clean_display_value(values)
    if not values:
        return
    chips = []
    for item in re.split(r"[,|]", values):
        item = item.strip()
        if item:
            chips.append(f'<span class="rule-chip">{html.escape(item)}</span>')
    if chips:
        st.markdown(
            '<div class="rule-doc-card accent-blue">'
            f'<div class="rule-doc-title">{html.escape(str(title))}</div>'
            f'<div class="rule-chip-row">{"".join(chips)}</div>'
            '</div>',
            unsafe_allow_html=True
        )


def show_json_rule_doc(rule_doc, selected_gid, selected_sid):
    """Render rule information from the preprocessed JSON dataset in a clean, card-based layout."""
    if not load_rule_docs_json():
        st.error(
            "The preprocessed JSON file was not found. Expected path: "
            f"`{RULE_DOC_JSON_FILE}`"
        )
        return

    if not rule_doc:
        st.warning(f"No JSON documentation entry was found for rule `{selected_gid}:{selected_sid}`.")
        return

    st.markdown(
        '<div class="rule-doc-notice">Rule details loaded from <code>data/json/rule_docs_preprocessed_by_sid.json</code>.</div>',
        unsafe_allow_html=True
    )

    doc_gid = rule_doc.get("gid", selected_gid)
    doc_sid = rule_doc.get("sid", selected_sid)
    doc_rev = rule_doc.get("rev", "N/A")
    doc_found = "Yes" if str(rule_doc.get("doc_found", "")).strip() == "1" else "No"

    render_kv_cards([
        ("GID", doc_gid),
        ("SID", doc_sid),
        ("REV", doc_rev),
        ("Documentation", doc_found),
    ])

    doc_url = clean_display_value(rule_doc.get("doc_url"))
    if doc_url:
        st.markdown(f"**Documentation URL:** {doc_url}")

    render_rule_card("Alert Message", rule_doc.get("msg") or rule_doc.get("alert_message_doc"), accent="blue")
    render_rule_card("Rule Category", rule_doc.get("rule_category"), accent="green")

    render_mini_grid([
        ("Classification", rule_doc.get("classtype")),
        ("Protocol", rule_doc.get("protocol")),
        ("Service", rule_doc.get("service")),
        ("Flow", rule_doc.get("flow")),
    ])

    render_rule_card("Rule Explanation", rule_doc.get("rule_explanation"), accent="blue")
    render_rule_card("What To Look For", rule_doc.get("what_to_look_for"), accent="orange")
    render_rule_card("Known Usage", rule_doc.get("known_usage"), accent="orange")
    render_rule_card("False Positives", rule_doc.get("false_positives"), accent="orange")
    render_rule_card("Vulnerability / Impact", rule_doc.get("rule_vulnerability"), accent="orange")

    render_chip_list("CVE References", rule_doc.get("cve_ids"))

    mitre_id = clean_display_value(rule_doc.get("mitre_id"))
    if mitre_id:
        mitre_text = mitre_id
        tactic = clean_display_value(rule_doc.get("mitre_tactic"))
        technique = clean_display_value(rule_doc.get("mitre_technique"))
        if tactic or technique:
            mitre_text += f" — {tactic} / {technique}"
        render_rule_card("MITRE ATT&CK Mapping", mitre_text, accent="green")

    with st.expander("Rule Metadata from Preprocessed JSON"):
        source = f"{clean_display_value(rule_doc.get('src_net'))}:{clean_display_value(rule_doc.get('src_port'))}".strip(":")
        destination = f"{clean_display_value(rule_doc.get('dst_net'))}:{clean_display_value(rule_doc.get('dst_port'))}".strip(":")
        render_mini_grid([
            ("Action", rule_doc.get("action")),
            ("Source", source),
            ("Direction", rule_doc.get("direction_label")),
            ("Destination", destination),
            ("Content Matches", rule_doc.get("content_matches")),
            ("Metadata", rule_doc.get("metadata")),
            ("References", rule_doc.get("references_text")),
            ("Rule Groups", rule_doc.get("rule_groups")),
            ("Contributors", rule_doc.get("contributors")),
        ])

    if clean_display_value(rule_doc.get("rule_text")):
        with st.expander("Original Rule Text from JSON Dataset"):
            st.code(rule_doc.get("rule_text", ""), language="text")

RULES_FILE = Path("/usr/local/etc/snort/rules/snort3-community.rules")

@st.cache_data(ttl=60)
def get_snort_version():
    try:
        result = subprocess.run(
            ["snort", "-V"],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout + result.stderr

        # Prefer lines like: Snort++ 3.12.2.0
        version_match = re.search(r"Snort\+\+\s+([0-9]+(?:\.[0-9]+)+)", output)
        if version_match:
            return f"Snort++ {version_match.group(1)}"

        # Fallback for lines like: Version 3.12.2.0
        version_match = re.search(r"Version\s+([0-9]+(?:\.[0-9]+)+)", output, re.IGNORECASE)
        if version_match:
            return f"Snort++ {version_match.group(1)}"

        return "Unable to parse Snort version"

    except Exception as e:
        return f"Unable to read Snort version: {e}"

@st.cache_data(ttl=60)
def get_ruleset_status():
    status = {
        "rules_file": str(RULES_FILE),
        "exists": RULES_FILE.exists(),
        "file_size": "N/A",
        "last_modified": "N/A",
        "sha256": "N/A",
        "enabled_alert_rules": 0,
        "disabled_alert_rules": 0,
        "total_alert_rules": 0,
    }

    if not RULES_FILE.exists():
        return status

    try:
        file_stat = RULES_FILE.stat()
        status["file_size"] = f"{file_stat.st_size / (1024 * 1024):.2f} MB"
        status["last_modified"] = datetime.fromtimestamp(
            file_stat.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")

        sha256_hash = hashlib.sha256()

        with RULES_FILE.open("rb") as file:
            for chunk in iter(lambda: file.read(8192), b""):
                sha256_hash.update(chunk)

        status["sha256"] = sha256_hash.hexdigest()

        enabled_alert_rules = 0
        disabled_alert_rules = 0

        with RULES_FILE.open("r", errors="ignore") as file:
            for line in file:
                stripped = line.strip()

                if stripped.startswith("alert "):
                    enabled_alert_rules += 1

                elif stripped.startswith("#") and "alert " in stripped:
                    disabled_alert_rules += 1

        status["enabled_alert_rules"] = enabled_alert_rules
        status["disabled_alert_rules"] = disabled_alert_rules
        status["total_alert_rules"] = enabled_alert_rules + disabled_alert_rules

    except Exception:
        pass

    return status

@st.cache_data(ttl=60)
def load_snort_rules_file():
    """
    Load the local Snort Community rules file.
    This does not use the internet. It reads the rules that Snort is already using.
    """
    if not RULES_FILE.exists():
        return ""

    try:
        return RULES_FILE.read_text(errors="ignore")
    except Exception:
        return ""


def find_rule_by_sid(sid):
    """
    Find the original Snort rule from snort3-community.rules using the SID.
    """
    if sid is None or pd.isna(sid):
        return None

    rules_text = load_snort_rules_file()

    if not rules_text:
        return None

    sid_text = str(int(sid)) if str(sid).replace(".0", "").isdigit() else str(sid)

    for line in rules_text.splitlines():
        clean_line = line.strip()

        if not clean_line or clean_line.startswith("#"):
            continue

        if f"sid:{sid_text};" in clean_line:
            return clean_line

    return None


def extract_rule_option(rule_text, option_name):
    """
    Extract a simple option value from a Snort rule.
    Example: msg:"PROTOCOL-ICMP Echo Reply";
    """
    if not rule_text:
        return None

    pattern = rf'{option_name}\s*:\s*"([^"]+)"'
    match = re.search(pattern, rule_text)

    if match:
        return match.group(1)

    pattern = rf'{option_name}\s*:\s*([^;]+);'
    match = re.search(pattern, rule_text)

    if match:
        return match.group(1).strip()

    return None


def priority_meaning(priority):
    try:
        priority = int(priority)
    except Exception:
        return "Unknown priority"

    meanings = {
        1: "High severity. This usually means serious or high-confidence suspicious activity.",
        2: "Medium severity. This usually means suspicious activity, probing, or possible information gathering.",
        3: "Low severity. This is usually informational, miscellaneous, or lower-risk activity.",
        4: "Very low/informational severity."
    }

    return meanings.get(priority, "Unknown priority level.")


def classification_meaning(classification):
    if not classification:
        return "No classification was provided for this alert."

    c = str(classification).lower()

    if "information leak" in c:
        return "This alert suggests that traffic may be trying to discover or expose system/service information."
    if "recon" in c:
        return "This alert suggests reconnaissance activity, such as scanning or probing."
    if "misc" in c:
        return "This is miscellaneous network activity. It may not be malicious by itself, but it is useful for visibility."
    if "web" in c:
        return "This alert is related to suspicious web or HTTP activity."
    if "attempted-dos" in c or "denial" in c:
        return "This alert may indicate traffic related to denial-of-service behavior."
    if "bad-unknown" in c:
        return "This alert indicates suspicious or unusual traffic that does not fit a more specific category."
    if "policy" in c:
        return "This alert indicates traffic that may violate a policy rather than a confirmed exploit."

    return "This classification groups the alert into a general Snort activity category."


def protocol_meaning(row):
    proto = str(row.get("Protocol", row.get("protocol", ""))).upper()
    service = row.get("Service", row.get("service", ""))
    tcp_flags = row.get("TCP Flags", row.get("tcp_flags", ""))
    icmp_type = row.get("ICMP Type", row.get("icmp_type", None))
    icmp_code = row.get("ICMP Code", row.get("icmp_code", None))

    if proto == "ICMP":
        if icmp_type == 0 or str(icmp_type) == "0":
            return "This is ICMP Echo Reply traffic. It usually means the target responded to a ping request."
        if icmp_type == 8 or str(icmp_type) == "8":
            return "This is ICMP Echo Request traffic. It usually means a host is being pinged or probed."
        return f"This is ICMP traffic. ICMP type={icmp_type}, code={icmp_code}."

    if proto == "TCP":
        if tcp_flags and str(tcp_flags).lower() not in ["none", "nan"]:
            return f"This is TCP traffic. TCP flags are `{tcp_flags}`, which can help identify scans or connection behavior."
        return "This is TCP traffic. TCP is used by services such as HTTP, SSH, FTP, and many application protocols."

    if proto == "UDP":
        return "This is UDP traffic. UDP is connectionless and is often used by DNS, SNMP, DHCP, and scanning activity."

    if service and str(service).lower() != "unknown":
        return f"Snort identified the service as `{service}`."

    return "This protocol/service combination does not have a specific explanation available."


def signature_plain_english(row):
    """
    Build a human-readable description using alert fields.
    """
    msg = row.get("Alert Message", row.get("msg", row.get("rule", "Unknown alert")))
    classification = row.get("Classification", row.get("classification", None))
    priority = row.get("Priority", row.get("priority", None))
    protocol = row.get("Protocol", row.get("protocol", None))
    service = row.get("Service", row.get("service", None))
    src_ip = row.get("Source IP", row.get("src_addr", row.get("src", None)))
    src_port = row.get("Source Port", row.get("src_port", None))
    dst_ip = row.get("Destination IP", row.get("dst_addr", row.get("dst", None)))
    dst_port = row.get("Destination Port", row.get("dst_port", None))
    direction = row.get("Direction", row.get("direction", None))

    parts = []

    parts.append(f"**Alert meaning:** `{msg}` was triggered because the observed traffic matched a Snort Community rule/signature.")

    if src_ip and dst_ip:
        src_text = f"{src_ip}"
        dst_text = f"{dst_ip}"

        if src_port and str(src_port) != "nan":
            src_text += f":{src_port}"

        if dst_port and str(dst_port) != "nan":
            dst_text += f":{dst_port}"

        parts.append(f"**Traffic path:** `{src_text}` → `{dst_text}`.")

    if protocol:
        parts.append(f"**Protocol:** `{protocol}`.")

    if service and str(service).lower() not in ["unknown", "nan", "none", ""]:
        parts.append(f"**Detected service:** `{service}`.")

    if direction and str(direction).lower() not in ["nan", "none", ""]:
        if direction == "C2S":
            parts.append("**Direction:** Client-to-server traffic.")
        elif direction == "S2C":
            parts.append("**Direction:** Server-to-client traffic.")
        else:
            parts.append(f"**Direction:** `{direction}`.")

    if classification:
        parts.append(f"**Classification:** `{classification}`. {classification_meaning(classification)}")

    if priority:
        parts.append(f"**Priority:** `{priority}`. {priority_meaning(priority)}")

    return "\n\n".join(parts)


# =========================
# Dashboard Header
# =========================

st.markdown(
    f"""
    <div style="display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
        <h1 style="margin-bottom: 0;">Network Intrusion Prevention and Detection System</h1>
        <span class="version-pill">{DASHBOARD_VERSION}</span>
    </div>
    """,
    unsafe_allow_html=True
)

st.caption("Live packet monitoring and Snort alert visualization")

st.sidebar.markdown(
    f"""
    <div class="sidebar-card">
        <div class="sidebar-title">IDPS Dashboard</div>
        <div class="sidebar-subtitle">
            Real-time Snort alerting, packet visibility, and rule explanation.
        </div>
        <div style="margin-top: 14px;">
            <span class="version-pill">{DASHBOARD_VERSION}</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

try:
    page_key = st.query_params.get("page", "alerts")
except Exception:
    page_key = st.experimental_get_query_params().get("page", ["alerts"])[0]

if isinstance(page_key, list):
    page_key = page_key[0]

if page_key not in ["alerts", "traffic", "ips"]:
    page_key = "alerts"

page_names = {
    "alerts": "Alert Dashboard",
    "traffic": "Network Traffic Dashboard",
    "ips": "IPS Control",
}
page = page_names[page_key]
alert_active = "active" if page_key == "alerts" else ""
traffic_active = "active" if page_key == "traffic" else ""
ips_active = "active" if page_key == "ips" else ""

st.sidebar.markdown(
    f"""
    <div class="sidebar-section-label">Pages</div>
    <div class="sidebar-nav">
        <a class="sidebar-nav-item {alert_active}" href="?page=alerts" target="_self">
            <span class="sidebar-nav-icon">▦</span>
            <span>Alert Dashboard</span>
        </a>
        <a class="sidebar-nav-item {traffic_active}" href="?page=traffic" target="_self">
            <span class="sidebar-nav-icon">▤</span>
            <span>Network Traffic Dashboard</span>
        </a>
        <a class="sidebar-nav-item {ips_active}" href="?page=ips" target="_self">
            <span class="sidebar-nav-icon">🛡</span>
            <span>IPS Control</span>
        </a>
    </div>
    <div class="sidebar-note">
        Use the alert page for Snort detections and rule documentation.<br><br>
        Use the traffic page for packet, protocol, service, and host visibility.
    </div>
    """,
    unsafe_allow_html=True
)

if not DB_FILE.exists():
    st.error("Database not found. Please run init_db.py first.")
    st.stop()

packets = load_table("packets")
alerts = load_table("alerts")

# =========================
# Top Metrics
# =========================

total_packets = len(packets)
recent_alerts_stored = len(alerts)
total_raw_alerts = count_raw_alert_lines()

alert_ratio = 0
alert_percentage = 0
packets_per_alert = 0

if PCAP_TOTAL_PACKETS > 0:
    alert_ratio = total_raw_alerts / PCAP_TOTAL_PACKETS
    alert_percentage = alert_ratio * 100

if total_raw_alerts > 0:
    packets_per_alert = PCAP_TOTAL_PACKETS / total_raw_alerts

active_hosts = 0

if not packets.empty:

    hosts = set()

    for ip in packets["src"].dropna():
        if str(ip).startswith("192.168.56."):
            hosts.add(ip)

    for ip in packets["dst"].dropna():
        if str(ip).startswith("192.168.56."):
            hosts.add(ip)

    active_hosts = len(hosts)

tcp_count = 0
icmp_count = 0
udp_count = 0
http_count = 0
ssh_count = 0

if not packets.empty:
    http_count = len(packets[packets["protocol"] == "HTTP"])
    ssh_count = len(packets[packets["protocol"] == "SSH"])
    tcp_count = len(packets[packets["protocol"] == "TCP"])
    icmp_count = len(packets[packets["protocol"] == "ICMP"])
    udp_count = len(packets[packets["protocol"] == "UDP"])

if page == "Alert Dashboard":
    st.subheader("Alert Dashboard")
    st.caption(
        "This page focuses on Snort alerts, alert severity, signatures, enriched alert JSON, "
        "and rule documentation details."
    )

    # =========================
    # Ruleset Status
    # =========================

    with st.expander("Snort Ruleset Status", expanded=False):
        snort_version = get_snort_version()
        ruleset_status = get_ruleset_status()

        st.caption(
            "This panel shows which local Snort engine and Community Rules file are being used. "
            "It helps make alert results reproducible because different rule versions may detect traffic differently."
        )

        r1, r2, r3, r4 = st.columns(4)

        r1.metric("Enabled Alert Rules", ruleset_status["enabled_alert_rules"])
        r2.metric("Disabled Alert Rules", ruleset_status["disabled_alert_rules"])
        r3.metric("Total Alert Rules", ruleset_status["total_alert_rules"])
        r4.metric("Rules File Size", ruleset_status["file_size"])

        st.markdown("#### Ruleset Details")

        ruleset_details = pd.DataFrame([
            {"Field": "Snort Version", "Value": snort_version},
            {"Field": "Rules File", "Value": ruleset_status["rules_file"]},
            {"Field": "Rules File Exists", "Value": ruleset_status["exists"]},
            {"Field": "Last Modified", "Value": ruleset_status["last_modified"]},
            {"Field": "SHA-256 Hash", "Value": ruleset_status["sha256"]},
        ])

        st.dataframe(
            ruleset_details,
            use_container_width=True,
            hide_index=True
        )

        if not ruleset_status["exists"]:
            st.warning(
                "The Snort Community Rules file was not found at the expected path. "
                "Rule lookup and signature explanation may not work until the path is corrected."
            )

    # =========================
    # Alerts
    # =========================

    st.divider()
    st.subheader("Snort Alert Analysis")

    # Alert metrics
    critical_alerts = 0
    medium_alerts = 0
    low_alerts = 0
    unique_alert_types = 0

    if not alerts.empty and "priority" in alerts.columns:
        critical_alerts = len(alerts[alerts["priority"] == 1])
        medium_alerts = len(alerts[alerts["priority"] == 2])
        low_alerts = len(alerts[alerts["priority"] == 3])

    if not alerts.empty:
        if "msg" in alerts.columns:
            unique_alert_types = alerts["msg"].fillna(alerts.get("rule", "")).nunique()
        elif "rule" in alerts.columns:
            unique_alert_types = alerts["rule"].nunique()

    a1, a2, a3, a4, a5 = st.columns(5)

    with a1:
        metric_card("Total Raw Alerts", total_raw_alerts, "red")
    with a2:
        metric_card("Alert Types", unique_alert_types, "purple")
    with a3:
        metric_card("High Priority", critical_alerts, "red")
    with a4:
        metric_card("Medium Priority", medium_alerts, "orange")
    with a5:
        metric_card("Low Priority", low_alerts, "green")

    st.info(
        f"Total Raw Alerts is counted from `{SNORT_ALERT_LOG_FILE}`. "
        "The dashboard database keeps only the most recent 10000 alerts, so detailed tables, charts, "
        "priority counts, and alert-type counts are based on the recent alerts stored in `ids_live.db`."
    )

    st.subheader("PCAP Replay & Alert Generation Statistics")
    st.caption(
        "This table summarizes the controlled PCAP replay test and the Snort alerts generated from it."
    )

    pcap_stats_df = pd.DataFrame([
        {
            "Metric": "Packets Replayed",
            "Value": f"{PCAP_TOTAL_PACKETS:,}",
            "Meaning": "Packets successfully sent by tcpreplay from the PCAP."
        },
        {
            "Metric": "Replay Speed",
            "Value": f"{PCAP_REPLAY_PPS} pps",
            "Meaning": "Configured tcpreplay sending rate."
        },
        {
            "Metric": "Replay Duration",
            "Value": f"{PCAP_REPLAY_DURATION_SECONDS:.2f} seconds",
            "Meaning": "Time taken by tcpreplay to replay the PCAP once."
        },
        {
            "Metric": "Replay Data Size",
            "Value": f"{PCAP_TOTAL_BYTES / (1024 * 1024):.2f} MB",
            "Meaning": "Total replayed payload/data size reported by tcpreplay."
        },
        {
            "Metric": "Raw Alerts Generated",
            "Value": f"{total_raw_alerts:,}",
            "Meaning": "Snort JSON alerts counted from alert_json.txt."
        },
        {
            "Metric": "Alert Percentage",
            "Value": f"{alert_percentage:.2f}%",
            "Meaning": "Raw alerts divided by replayed packets."
        },
        {
            "Metric": "Packets per Alert",
            "Value": f"{packets_per_alert:.1f}",
            "Meaning": "Average replayed packets per generated Snort alert."
        },
        {
            "Metric": "DB Alerts Stored",
            "Value": f"{recent_alerts_stored:,}",
            "Meaning": "Alert records currently stored in ids_live.db."
        },
        {
            "Metric": "Packet Rows Captured",
            "Value": f"{total_packets:,}",
            "Meaning": "Packet rows inserted by live_packet_collector.py; this is not the same as packets replayed."
        },
    ])

    st.dataframe(
        pcap_stats_df,
        use_container_width=True,
        hide_index=True,
        height=355
    )

    st.info(
        f"Summary: {PCAP_TOTAL_PACKETS:,} packets were replayed at {PCAP_REPLAY_PPS} pps in "
        f"{PCAP_REPLAY_DURATION_SECONDS:.2f} seconds. Snort generated {total_raw_alerts:,} raw alerts, "
        f"which is {alert_percentage:.2f}% of the replayed packets. Packet table count is collected separately "
        "by live_packet_collector.py and may be lower if the collector was stopped or the database was locked."
    )

    alert_col1, alert_col2 = st.columns(2)

    with alert_col1:
        alert_rules_df = load_query("""
            SELECT
                COALESCE(NULLIF(msg, ''), rule) AS signature,
                COUNT(*) AS alerts
            FROM alerts
            GROUP BY signature
            ORDER BY alerts DESC
            LIMIT 10
        """)

        if not alert_rules_df.empty:
            fig = px.bar(
                alert_rules_df,
                x="alerts",
                y="signature",
                orientation="h",
                title="Top Alert Messages"
            )
            fig.update_layout(
                yaxis={"categoryorder": "total ascending"},
                xaxis_title="Alerts",
                yaxis_title="Snort Alert Message"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No Snort alert signatures available yet.")

    with alert_col2:
        priority_df = load_query("""
            SELECT
                CASE
                    WHEN priority = 1 THEN 'High'
                    WHEN priority = 2 THEN 'Medium'
                    WHEN priority = 3 THEN 'Low'
                    ELSE 'Unknown'
                END AS priority_level,
                COUNT(*) AS alerts
            FROM alerts
            GROUP BY priority
            ORDER BY priority
        """)

        if not priority_df.empty:
            fig = px.pie(
                priority_df,
                names="priority_level",
                values="alerts",
                title="Alert Priority Distribution",
                hole=0.35
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert priority data yet.")

    # Alert timeline
    alert_timeline_df = load_query("""
        SELECT timestamp, COUNT(*) AS alerts
        FROM alerts
        GROUP BY timestamp
        ORDER BY timestamp
    """)

    if not alert_timeline_df.empty:
        fig = px.line(
            alert_timeline_df,
            x="timestamp",
            y="alerts",
            title="Alert Timeline",
            markers=True
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert timeline available yet.")

    # Extra JSON feature charts
    feature_col1, feature_col2 = st.columns(2)

    with feature_col1:
        protocol_alerts_df = load_query("""
            SELECT protocol, COUNT(*) AS alerts
            FROM alerts
            WHERE protocol IS NOT NULL AND protocol != ''
            GROUP BY protocol
            ORDER BY alerts DESC
        """)

        if not protocol_alerts_df.empty:
            fig = px.bar(
                protocol_alerts_df,
                x="alerts",
                y="protocol",
                orientation="h",
                title="Alert Protocol Distribution"
            )
            fig.update_layout(
                yaxis={"categoryorder": "total ascending"},
                height=300,
                margin=dict(l=10, r=10, t=50, b=35)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert protocol data available yet.")

    with feature_col2:
        src_alerts_df = load_query("""
            SELECT COALESCE(NULLIF(src_addr, ''), src) AS source_ip, COUNT(*) AS alerts
            FROM alerts
            WHERE COALESCE(NULLIF(src_addr, ''), src) IS NOT NULL
              AND COALESCE(NULLIF(src_addr, ''), src) != ''
            GROUP BY source_ip
            ORDER BY alerts DESC
            LIMIT 10
        """)

        if not src_alerts_df.empty:
            fig = px.bar(
                src_alerts_df,
                x="alerts",
                y="source_ip",
                orientation="h",
                title="Top Alert Source IPs"
            )
            fig.update_layout(
                yaxis={"categoryorder": "total ascending"},
                height=300,
                margin=dict(l=10, r=10, t=50, b=35)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert source IP data available yet.")

    port_col1, port_col2 = st.columns(2)

    with port_col1:
        dst_port_df = load_query("""
            SELECT dst_port, COUNT(*) AS alerts
            FROM alerts
            WHERE dst_port IS NOT NULL
            GROUP BY dst_port
            ORDER BY alerts DESC
            LIMIT 10
        """)

        if not dst_port_df.empty:
            dst_port_df["dst_port"] = dst_port_df["dst_port"].astype(str)

            fig = px.bar(
                dst_port_df,
                x="alerts",
                y="dst_port",
                orientation="h",
                title="Top Alert Destination Ports"
            )
            fig.update_layout(
                yaxis={"categoryorder": "total ascending"},
                height=280,
                margin=dict(l=10, r=10, t=50, b=35)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No destination port data yet. This is normal for ICMP alerts.")

    # Recent detailed alert table with row selection
    st.subheader("Detailed Recent Snort Alerts")
    st.caption(
        "Click a row in the table to load the combined enriched JSON from "
        "`data/json/enriched_snort_alerts_with_rule_docs.json`."
    )

    recent_alerts = load_query("""
        SELECT
            id AS "Alert ID",
            timestamp AS "Time",
            COALESCE(NULLIF(msg, ''), rule) AS "Alert Message",
            snort_rule AS "Rule ID",
            classification AS "Classification",
            priority AS "Priority",
            protocol AS "Protocol",
            service AS "Service",
            COALESCE(NULLIF(src_addr, ''), src) AS "Source IP",
            src_port AS "Source Port",
            COALESCE(NULLIF(dst_addr, ''), dst) AS "Destination IP",
            dst_port AS "Destination Port",
            direction AS "Direction",
            pkt_len AS "Packet Length",
            ttl AS "TTL",
            tcp_flags AS "TCP Flags",
            icmp_type AS "ICMP Type",
            icmp_code AS "ICMP Code",
            client_pkts AS "Client Packets",
            client_bytes AS "Client Bytes",
            server_pkts AS "Server Packets",
            server_bytes AS "Server Bytes",
            gid AS "GID",
            sid AS "SID",
            rev AS "REV",
            raw_json AS "Raw JSON"
        FROM alerts
        ORDER BY id DESC
        LIMIT 100
    """)

    selected = None

    if not recent_alerts.empty:
        def priority_label(p):
            if p == 1:
                return "High"
            elif p == 2:
                return "Medium"
            elif p == 3:
                return "Low"
            return "Unknown"

        recent_alerts["Priority Level"] = recent_alerts["Priority"].apply(priority_label)

        table_columns = [
            "Time",
            "Alert Message",
            "Rule ID",
            "Classification",
            "Priority",
            "Priority Level",
            "Protocol",
            "Service",
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Direction",
            "Packet Length",
            "TTL",
            "TCP Flags",
            "ICMP Type",
            "ICMP Code",
            "Client Packets",
            "Client Bytes",
            "Server Packets",
            "Server Bytes",
        ]

        existing_columns = [col for col in table_columns if col in recent_alerts.columns]
        display_alerts = recent_alerts[existing_columns]

        selected_row_positions = []

        try:
            table_event = st.dataframe(
                display_alerts,
                use_container_width=True,
                height=420,
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key="recent_snort_alerts_selectable_table"
            )

            if hasattr(table_event, "selection") and table_event.selection:
                selected_row_positions = table_event.selection.rows

        except TypeError:
            st.dataframe(
                display_alerts,
                use_container_width=True,
                height=420,
                hide_index=True
            )
            st.warning(
                "Interactive row selection is not available in this Streamlit version. "
                "Showing the latest alert by default."
            )

        if selected_row_positions:
            selected = recent_alerts.iloc[selected_row_positions[0]]
        else:
            selected = recent_alerts.iloc[0]
            st.info("No row selected yet. The latest alert is shown below by default.")

        st.caption(
            "Each alert is generated when packet contents match a Snort rule signature. "
            "Priority indicates severity, where 1 is high, 2 is medium, and 3 is low. "
            "JSON alert fields add protocol, service, packet length, TTL, ICMP, TCP, and flow information."
        )
    else:
        st.info("No recent Snort alerts yet.")

    # =========================
    # Selected Alert Explanation
    # =========================

    st.subheader("Selected Enriched Alert JSON")

    if selected is None:
        st.info("Select an alert row from the table above to view the combined enriched alert JSON.")
    else:
        selected_alert_id = selected.get("Alert ID")
        enriched_alert = find_enriched_alert_by_id(selected_alert_id)

        if enriched_alert is None:
            st.warning(
                "This selected alert was not found in the enriched JSON file. "
                "Run `python3 scripts/export_enriched_alerts_json.py` to refresh the combined JSON."
            )

            st.markdown("### Selected Alert from Database")
            st.caption(
                "Fallback view: this is the selected alert directly from `ids_live.db`, "
                "not the combined enriched JSON."
            )
            st.json(selected.to_dict())

        else:
            alert_info = enriched_alert.get("alert", {})
            rule_doc_found = enriched_alert.get("rule_documentation_found", False)

            selected_message = alert_info.get("alert_message", "Unknown alert")
            selected_rule = alert_info.get("rule_id", "N/A")
            selected_gid = alert_info.get("gid", "N/A")
            selected_sid = alert_info.get("sid", "N/A")
            selected_rev = alert_info.get("rev", "N/A")

            st.markdown(
                f"""
                <div class="selected-alert-card">
                    <div class="small-muted">Selected Enriched Alert</div>
                    <h4 style="margin: 4px 0 8px 0;">{html.escape(str(selected_message))}</h4>
                    <div class="small-muted">
                        Alert ID: <code>{html.escape(str(selected_alert_id))}</code> &nbsp; | &nbsp;
                        Rule: <code>{html.escape(str(selected_rule))}</code> &nbsp; | &nbsp;
                        GID: <code>{html.escape(str(selected_gid))}</code> &nbsp; | &nbsp;
                        SID: <code>{html.escape(str(selected_sid))}</code> &nbsp; | &nbsp;
                        REV: <code>{html.escape(str(selected_rev))}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            if rule_doc_found:
                st.success("Rule documentation is included in the combined enriched JSON.")
            else:
                st.warning("No matching rule documentation was found for this alert in the enriched JSON.")

            st.caption(
                "This JSON combines the selected alert from `ids_live.db` with its matching "
                "rule description from `rule_docs_preprocessed_by_sid.json`."
            )

            with st.expander("Combined Enriched Alert JSON", expanded=True):
                st.json(enriched_alert)

    with st.expander("Snort JSON Feature Meaning"):
        feature_meaning = pd.DataFrame([
            {"Feature": "Alert Message", "Meaning": "The Snort rule message explaining what was detected."},
            {"Feature": "Rule ID", "Meaning": "Snort rule identifier in gid:sid:rev format."},
            {"Feature": "Classification", "Meaning": "The general category of the alert."},
            {"Feature": "Priority", "Meaning": "Severity level. Lower number means more serious."},
            {"Feature": "Protocol", "Meaning": "Network protocol, such as TCP, UDP, or ICMP."},
            {"Feature": "Service", "Meaning": "Detected application/service, such as HTTP, FTP, SNMP, or unknown."},
            {"Feature": "Source/Destination IP", "Meaning": "The endpoints involved in the alert."},
            {"Feature": "Source/Destination Port", "Meaning": "The TCP/UDP ports involved. ICMP alerts usually do not have ports."},
            {"Feature": "Direction", "Meaning": "C2S means client-to-server. S2C means server-to-client."},
            {"Feature": "Packet Length", "Meaning": "Size of the packet that triggered the alert."},
            {"Feature": "TTL", "Meaning": "Time To Live value from the IP header."},
            {"Feature": "TCP Flags", "Meaning": "TCP control flags, useful for SYN/FIN/NULL/Xmas scan analysis."},
            {"Feature": "ICMP Type/Code", "Meaning": "ICMP message details. Type 8 is Echo Request; type 0 is Echo Reply."},
            {"Feature": "Client/Server Packets and Bytes", "Meaning": "Flow counters showing traffic volume in each direction."},
        ])

        st.dataframe(feature_meaning, use_container_width=True, hide_index=True)

elif page == "Network Traffic Dashboard":
    st.subheader("Network Traffic Dashboard")
    st.caption(
        "This page focuses on normal/live network traffic visibility, protocol distribution, "
        "top hosts, services, and recent captured packets."
    )

    # =========================
    # Network Traffic Metrics
    # =========================

    n1, n2, n3, n4, n5, n6, n7 = st.columns(7)

    with n1:
        metric_card("Total Packets", total_packets, "blue")
    with n2:
        metric_card("Active Hosts", active_hosts, "green")
    with n3:
        metric_card("TCP Packets", tcp_count, "blue")
    with n4:
        metric_card("UDP Packets", udp_count, "purple")
    with n5:
        metric_card("ICMP Packets", icmp_count, "orange")
    with n6:
        metric_card("HTTP Requests", http_count, "green")
    with n7:
        metric_card("SSH Connections", ssh_count, "purple")

    st.divider()

    # =========================
    # Traffic Overview
    # =========================

    st.subheader("Network Traffic Overview")

    left, right = st.columns(2)

    with left:
        protocol_df = load_query("""
            SELECT protocol, COUNT(*) AS count
            FROM packets
            GROUP BY protocol
            ORDER BY count DESC
        """)

        if not protocol_df.empty:
            fig = px.pie(
                protocol_df,
                names="protocol",
                values="count",
                title="Protocol Distribution",
                hole=0.35
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No packet data available yet.")

    with right:
        timeline_df = load_query("""
            SELECT timestamp, COUNT(*) AS packets
            FROM packets
            GROUP BY timestamp
            ORDER BY timestamp
        """)

        if not timeline_df.empty:
            fig = px.line(
                timeline_df,
                x="timestamp",
                y="packets",
                title="Packets Over Time",
                markers=True
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No timeline data available yet.")

    # =========================
    # Top Talkers
    # =========================

    st.subheader("Top Network Hosts")

    col_a, col_b = st.columns(2)

    with col_a:
        src_df = load_query("""
            SELECT src, COUNT(*) AS packets
            FROM packets
            WHERE src != 'unknown'
            GROUP BY src
            ORDER BY packets DESC
            LIMIT 10
        """)

        if not src_df.empty:
            fig = px.bar(
                src_df,
                x="packets",
                y="src",
                orientation="h",
                title="Top Source IPs"
            )
            fig.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No source IP data available.")

    with col_b:
        dst_df = load_query("""
            SELECT dst, COUNT(*) AS packets
            FROM packets
            WHERE dst != 'unknown'
            GROUP BY dst
            ORDER BY packets DESC
            LIMIT 10
        """)

        if not dst_df.empty:
            fig = px.bar(
                dst_df,
                x="packets",
                y="dst",
                orientation="h",
                title="Top Destination IPs"
            )
            fig.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No destination IP data available.")

    # =========================
    # Service Distribution
    # =========================

    st.subheader("Service Distribution")

    service_df = load_query("""
        SELECT protocol AS service, COUNT(*) AS packets
        FROM packets
        WHERE protocol IN ('HTTP', 'SSH', 'ICMP', 'DNS', 'HTTPS')
        GROUP BY protocol
        ORDER BY packets DESC
    """)

    if not service_df.empty:
        service_chart_col, service_table_col = st.columns([2, 1])

        with service_chart_col:
            fig = px.bar(
                service_df,
                x="packets",
                y="service",
                orientation="h",
                title="Observed Network Services"
            )
            fig.update_layout(
                yaxis={"categoryorder": "total ascending"},
                xaxis_title="Packets",
                yaxis_title="Service",
                height=320,
                margin=dict(l=10, r=10, t=50, b=35)
            )
            st.plotly_chart(fig, use_container_width=True)

        with service_table_col:
            st.dataframe(
                service_df,
                use_container_width=True,
                hide_index=True,
                height=220
            )
    else:
        st.info("No service traffic available yet. Generate HTTP, SSH, ICMP, or DNS traffic.")

    # =========================
    # Recent Packets
    # =========================

    st.divider()
    st.subheader("Recent Network Packets")

    recent_packets = load_query("""
        SELECT timestamp, src, dst, protocol, src_port, dst_port, size
        FROM packets
        ORDER BY id DESC
        LIMIT 100
    """)

    if not recent_packets.empty:
        st.dataframe(recent_packets, use_container_width=True, height=300)
    else:
        st.info("No recent packet records yet.")

elif page == "IPS Control":
    import sys
    from pathlib import Path

    SRC_DIR = str(Path(__file__).resolve().parent)
    if SRC_DIR not in sys.path:
        sys.path.insert(0, SRC_DIR)

    import ips_controller

    st.title("🛡️ IPS Control")
    st.caption(
        "Manage inbound IPv4 blocking on this Kali host. "
        "This does not block traffic forwarded through another device."
    )

    try:
        status = ips_controller.get_status()
        if status["ready"]:
            st.success(status["message"])
        else:
            st.warning(status["message"])
    except Exception as exc:
        status = {"ready": False, "blocked_ips": []}
        st.error(f"Could not read firewall status: {exc}")

    st.subheader("Block an IPv4 address")
    with st.form("ips_block_form"):
        block_address = st.text_input(
            "IPv4 address",
            placeholder="Example: 192.168.18.50",
        )
        block_submit = st.form_submit_button(
            "Block IP",
            disabled=not status["ready"],
        )

    if block_submit:
        try:
            ips_controller.block_ip(block_address)
            st.success("Block-list updated.")
            st.rerun()
        except Exception as exc:
            st.error(f"Block failed: {exc}")

    st.divider()
    st.subheader("Unblock an IPv4 address")
    blocked_ips = status.get("blocked_ips", [])

    if blocked_ips:
        with st.form("ips_unblock_form"):
            selected_ip = st.selectbox(
                "Select blocked IP",
                options=blocked_ips,
            )
            unblock_submit = st.form_submit_button("Unblock IP")

        if unblock_submit:
            try:
                ips_controller.unblock_ip(selected_ip)
                st.success("IP removed from the block list.")
                st.rerun()
            except Exception as exc:
                st.error(f"Unblock failed: {exc}")
    else:
        st.info("No IP addresses are currently blocked.")

    st.caption(
        "Safety: blocking applies to traffic destined for this Kali host, "
        "not traffic forwarded to another machine."
    )
