# 🛡️ Real-Time Network Intrusion Detection System Dashboard

A real-time Network Intrusion Detection System (NIDS) built using **Snort 3, Scapy, SQLite, and Streamlit**.

The system captures live network traffic, detects suspicious activity using Snort signature-based detection, stores packet and alert data in SQLite, and visualizes network activity through an interactive Streamlit dashboard.

The project also includes a **preprocessed Snort rule documentation dataset**, enriched alert JSON generation, and a custom multi-attack PCAP replay workflow for repeatable IDS testing and future LLM/RAG-based alert explanation.

---

## Features

- Real-time network traffic monitoring
- Live packet capture using Scapy
- Signature-based intrusion detection using Snort 3
- Snort JSON alert parsing
- SQLite backend for packet and alert storage
- Interactive Streamlit dashboard
- Automatic dashboard refresh
- Dashboard version indicator
- Two-page dashboard navigation
- Alert Dashboard and Network Traffic Dashboard
- Protocol and service distribution charts
- HTTP, SSH, ICMP, TCP, UDP, DNS, and ARP traffic monitoring
- Snort alert visualization
- Alert severity and signature analysis
- Suspicious source IP monitoring
- Total raw Snort alert counting from `alert_json.txt`
- Snort ruleset status display
- Rolling-window database storage
- Alert retention increased to latest 10,000 alerts
- Preprocessed Snort rule documentation dataset
- Normalized rule database exports
- JSON rule lookup dataset for future LLM/RAG integration
- Enriched alert JSON export using GID/SID lookup
- Selected enriched alert JSON display in dashboard
- Custom multi-attack PCAP replay testing
- PCAP replay and alert generation statistics section

---

## System Architecture

```text
                     Host-Only Lab Network
                     (192.168.56.0/24)

           Kali VM                     Ubuntu Victim VM
      (Traffic Generator)             (Target Services)
       192.168.56.10                   192.168.56.20
                │                              │
                └──────────────┬───────────────┘
                               │
                               ▼
                        Ubuntu Snort VM
                         192.168.56.30
                ┌──────────────────────────────┐
                │         Snort 3 IDS          │
                │                              │
                │ Live Packet Collector        │
                │ Live Alert Collector         │
                │ SQLite Database              │
                │ Streamlit Dashboard          │
                │ Snort Rule Dataset           │
                │ Enriched Alert JSON Export   │
                └──────────────────────────────┘
```

---

## Working Pipeline

```text
                    Network Traffic
                           │
                           ▼
                 Monitoring Interface
                        (enp0s8)
                           │
          ┌────────────────┴────────────────┐
          │                                 │
          ▼                                 ▼
     Scapy Collector                  Snort 3 IDS
          │                                 │
          ▼                                 ▼
 SQLite packets table              Snort JSON Alerts
 Latest 5,000 packets              alert_json.txt
                                            │
                                            ▼
                                  Live Alert Collector
                                            │
                                            ▼
                                  SQLite alerts table
                                  Latest 10,000 alerts
                                            │
                                            ▼
                                  Streamlit Dashboard
```

---

## PCAP Replay and Live Detection Flow

A custom multi-attack PCAP was created for repeatable IDS testing. The actual PCAP file is **not included in this repository** because of its large size. The replay process, commands, and results are documented instead.

```text
Kali tcpreplay
        │
        ▼
multi_attack_demo_mtu1500.pcap
        │
        ▼
Kali eth1 interface
        │
        ▼
Host-only lab network
        │
        ▼
Ubuntu Victim receives traffic
        │
        ▼
Ubuntu Snort/Dashboard VM monitors enp0s8
        │
        ▼
Snort compares packets with Community Rules
        │
        ▼
Matching traffic generates JSON alerts
        │
        ▼
/home/maheen/snort_logs/alert_json.txt
        │
        ▼
live_alert_collector.py
        │
        ▼
ids_live.db alerts table
        │
        ▼
export_enriched_alerts_json.py
        │
        ▼
enriched_snort_alerts_with_rule_docs.json
        │
        ▼
Streamlit Dashboard
```

In parallel, `live_packet_collector.py` captures packet metadata from `enp0s8` and stores it in the `packets` table.

Simple flow:

```text
PCAP replay → Snort rule matching → alert_json.txt → alerts table → enriched JSON → dashboard
```

---

## Remote Dashboard Access

The Streamlit dashboard runs inside the Ubuntu Snort/Dashboard VM.

For private lab access, the dashboard can be exposed through the Windows host machine using VirtualBox NAT forwarding and Windows portproxy.

Current working access structure:

```text
Client Device / Mentor System
        │
        ▼
Windows Host IP:8501
        │
        ▼
Windows portproxy
        │
        ▼
127.0.0.1:8501
        │
        ▼
VirtualBox NAT Port Forwarding
        │
        ▼
Ubuntu VM Streamlit Dashboard
```

The dashboard is **hosted inside the Ubuntu VM**. The Windows host acts as a gateway/forwarding layer to make the dashboard accessible to other reachable systems.

Example URL:

```text
http://<windows-host-ip>:8501
```

The dashboard is accessible only while:

- Windows host is powered on
- Ubuntu VM is running
- Streamlit dashboard is running
- VirtualBox NAT forwarding is active
- Windows portproxy rule is active

Previously captured data can still be viewed from SQLite even if live attacks are not running, but the VM and Streamlit dashboard must still be online.

---

## Repository Structure

```text
Real-Time-Network-IDPS-Dashboard/

├── README.md
├── requirements.txt
├── .gitignore
│
├── dashboard.py
├── init_db.py
├── live_packet_collector.py
├── live_alert_collector.py
│
├── data/
│   ├── README.md
│   ├── raw/
│   │   └── rule_docs_review.xlsx
│   │
│   ├── preprocessed/
│   │   └── rule_docs_preprocessed.xlsx
│   │
│   ├── normalized/
│   │   └── normalized_snort_rule_database.xlsx
│   │
│   └── json/
│       ├── rule_docs_preprocessed_by_sid.json
│       └── enriched_snort_alerts_with_rule_docs.json
│
├── scripts/
│   ├── README.md
│   ├── build_rule_docs_db.py
│   ├── repair_rule_docs_fetch.py
│   ├── export_preprocessed_rules.py
│   ├── create_rule_preprocessed_json.py
│   ├── export_normalized_database_excel.py
│   ├── create_rule_cves_table.py
│   ├── create_rule_mitre_table.py
│   ├── create_rule_references_table.py
│   ├── create_rule_content_matches_table.py
│   ├── get_rule_context.py
│   └── export_enriched_alerts_json.py
│
├── docs/
│   ├── Real-Time_NIDS_Project_Documentation_v4.pdf
│   └── Real-Time_NIDS_Project_Documentation_v4.docx
│
└── screenshots/
    ├── dashboard_network_traffic_v4.png
    ├── dashboard_alert_summary_v4.png
    ├── dashboard_pcap_replay_stats_v4.png
    ├── dashboard_recent_alerts_v4.png
    └── dashboard_selected_alert_json_v4.png
```

The custom PCAP file is not committed to the repository because of size. Only its replay command, statistics, and results are documented.

Optional PCAP location if the file is stored locally:

```text
data/pcaps/
└── multi_attack_demo_mtu1500.pcap
```

---

## Technologies Used

| Component | Technology |
|---|---|
| IDS | Snort 3 |
| Packet Capture | Scapy |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Database | SQLite |
| Programming Language | Python |
| Operating System | Ubuntu |
| Attacker Machine | Kali Linux |
| Victim Machine | Ubuntu + DVWA |
| Virtualization | Oracle VirtualBox |
| Traffic Replay | tcpreplay |
| Dataset Processing | Python, SQLite, Pandas, OpenPyXL |

---

## Network Configuration

| Machine | Role | IP |
|---|---|---|
| Kali Linux | Attacker / Traffic Generator | `192.168.56.10` |
| Ubuntu Victim | Target / Victim | `192.168.56.20` |
| Ubuntu Snort VM | IDS + Dashboard VM | `192.168.56.30` |
| Windows Host | Dashboard Access Gateway | Depends on active network |

---

## Dashboard Overview

The Streamlit dashboard is organized into two main pages.

### Alert Dashboard

The Alert Dashboard focuses on Snort detections and rule-based alert investigation.

It includes:

- Total raw alerts counted from `/home/maheen/snort_logs/alert_json.txt`
- Alert types
- High, medium, and low priority alert counts
- Snort ruleset status panel
- PCAP replay and alert generation statistics
- Detailed recent Snort alerts table
- Alert message, rule ID, classification, priority, protocol, service, source IP, source port, destination IP, and destination port
- Selected enriched alert JSON
- Fallback selected alert display from `ids_live.db` if the enriched JSON has not been refreshed

Example v4 dashboard metrics from the final test:

| Metric | Value |
|---|---:|
| Total Raw Alerts | 807 |
| Alert Types | 61 |
| High Priority Alerts | 485 |
| Medium Priority Alerts | 306 |
| Low Priority Alerts | 11 |

### Network Traffic Dashboard

The Network Traffic Dashboard focuses on packet-level visibility and normal traffic monitoring.

It includes:

- Total packets
- Active hosts
- TCP packets
- UDP packets
- ICMP packets
- HTTP requests
- SSH connections
- Protocol distribution
- Packets over time
- Top source IPs
- Recent packet table

Example v4 dashboard metrics from the final test:

| Metric | Value |
|---|---:|
| Total Packets | 1,707 |
| Active Hosts | 2 |
| HTTP Requests | 1,697 |
| TCP Packets | 0 |
| UDP Packets | 0 |
| ICMP Packets | 0 |
| SSH Connections | 0 |

---

## Dataset Overview

This project includes Snort rule documentation data collected and preprocessed for future rule explanation and retrieval-based analysis.

### Dataset Files

| Folder | Purpose |
|---|---|
| `data/raw/` | Raw or review-stage rule documentation exports |
| `data/preprocessed/` | Cleaned single-table preprocessed rule documentation dataset |
| `data/normalized/` | Multi-table normalized Snort rule database export |
| `data/json/` | JSON datasets for rule lookup and enriched alert explanation |

### Included Dataset Versions

| File | Description |
|---|---|
| `rule_docs_review.xlsx` | Review-stage Snort rule documentation export |
| `rule_docs_preprocessed.xlsx` | Cleaned preprocessed rule documentation dataset |
| `normalized_snort_rule_database.xlsx` | Normalized multi-table rule database export |
| `rule_docs_preprocessed_by_sid.json` | JSON rule lookup dataset keyed by SID |
| `enriched_snort_alerts_with_rule_docs.json` | Latest enriched alert snapshot generated from DB alerts and rule documentation |

---

## Normalized Rule Database

The normalized Snort rule database separates rule data into multiple related tables.

| Table | Description |
|---|---|
| `rules` | Core Snort rule metadata |
| `rule_documentation` | Snort documentation fields |
| `rule_cves` | CVE mappings |
| `rule_mitre` | MITRE ATT&CK mappings |
| `rule_references` | External references such as CVE, URL, Bugtraq, and Nessus |
| `rule_content_matches` | Snort content match patterns |

Final normalized row counts:

| Table | Rows |
|---|---:|
| `rules` | 4017 |
| `rule_documentation` | 4017 |
| `rule_cves` | 2278 |
| `rule_mitre` | 207 |
| `rule_references` | 6735 |
| `rule_content_matches` | 7413 |

---

## Scripts Overview

The `scripts/` folder contains helper scripts used for dataset collection, cleaning, normalization, export, retrieval, and enriched alert generation.

| Script | Purpose |
|---|---|
| `build_rule_docs_db.py` | Scrapes Snort rule documentation and stores rule metadata in SQLite |
| `repair_rule_docs_fetch.py` | Repairs failed or incomplete documentation fetches |
| `export_preprocessed_rules.py` | Exports cleaned preprocessed rules to Excel |
| `create_rule_preprocessed_json.py` | Converts preprocessed Excel data into JSON keyed by SID |
| `export_normalized_database_excel.py` | Exports normalized tables to a multi-sheet Excel workbook |
| `create_rule_cves_table.py` | Creates normalized CVE mapping table |
| `create_rule_mitre_table.py` | Creates normalized MITRE mapping table |
| `create_rule_references_table.py` | Creates normalized rule reference table |
| `create_rule_content_matches_table.py` | Creates normalized content match table |
| `get_rule_context.py` | Retrieves full rule context using GID and SID |
| `export_enriched_alerts_json.py` | Joins stored Snort alerts with rule documentation and exports enriched alert JSON |

---

## Installation

### Clone Repository

```bash
git clone https://github.com/MaheenN31/Real-Time-Network-IDPS-Dashboard.git
cd Real-Time-Network-IDPS-Dashboard
```

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Initialize Database

```bash
python3 init_db.py
```

### Install Snort 3

Install and configure:

- Snort 3
- Snort 3 Community Rules
- DAQ
- LuaJIT

Make sure the monitoring interface is configured correctly.

In this project, the Snort monitoring interface is:

```text
enp0s8
```

---

## Running the Project

Use separate terminal windows for each process.

### 1. Start Snort

```bash
mkdir -p /home/maheen/snort_logs
touch /home/maheen/snort_logs/alert_json.txt
sudo chown maheen:maheen /home/maheen/snort_logs/alert_json.txt

sudo snort -q \
-c /usr/local/etc/snort/snort.lua \
-R /usr/local/etc/snort/rules/snort3-community.rules \
-i enp0s8 \
-A alert_json \
--lua "HOME_NET='192.168.56.20/32'; EXTERNAL_NET='192.168.56.10/32'; alert_json={fields='timestamp iface proto service src_addr src_port dst_addr dst_port dir pkt_len action msg class priority rule gid sid rev'}" \
2>/tmp/snort_json_errors.txt | tee -a /home/maheen/snort_logs/alert_json.txt
```

### 2. Start the Packet Collector

```bash
cd /home/maheen/ids_streamlit_dashboard
sudo python3 live_packet_collector.py
```

### 3. Start the Alert Collector

```bash
cd /home/maheen/ids_streamlit_dashboard
python3 live_alert_collector.py
```

### 4. Start the Dashboard

```bash
cd /home/maheen/ids_streamlit_dashboard
streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501 --server.headless true
```

Open locally:

```text
http://127.0.0.1:8501
```

Or through the Windows forwarding setup:

```text
http://<windows-host-ip>:8501
```

---

## Generating Live Traffic

Run these commands from the Kali VM against the Ubuntu victim VM.

### ICMP

```bash
ping -c 10 192.168.56.20
```

### HTTP

```bash
curl http://192.168.56.20
```

### SSH

```bash
nc -vz 192.168.56.20 22
```

### Nmap Scan

```bash
sudo nmap -sS -Pn -p 1-1000 192.168.56.20
```

or:

```bash
sudo nmap -Pn -A 192.168.56.20
```

---

## Custom Multi-Attack PCAP Testing

A custom PCAP was generated because many public IDS datasets were too large for the lab setup.

The custom PCAP includes traffic from:

- Gobuster directory enumeration
- Nikto vulnerability scanning
- DVWA attacks
- sqlmap SQL injection testing
- XSS payloads
- File inclusion and path traversal attempts
- Command injection payloads
- Brute-force login attempts
- curl and manual HTTP traffic

### PCAP File

```text
multi_attack_demo_mtu1500.pcap
```

The PCAP file is **not committed to this repository** because of file size. The replay process and measured results are documented for reproducibility.

### PCAP Replay Results

| Metric | Value | Meaning |
|---|---:|---|
| Packets Replayed | 135,292 | Packets successfully sent by tcpreplay from the PCAP |
| Replay Speed | 800 pps | Configured tcpreplay sending rate |
| Replay Duration | 169.11 seconds | Time taken to replay the PCAP once |
| Replay Data Size | 37.46 MB | Total replayed payload/data size reported by tcpreplay |
| Raw Alerts Generated | 807 | Snort JSON alerts counted from `alert_json.txt` in the final dashboard test |
| Alert Percentage | 0.60% | Raw alerts divided by replayed packets |
| Packets per Alert | 167.6 | Average replayed packets per generated Snort alert |
| DB Alerts Stored | 802 | Alert records currently stored in `ids_live.db` |
| Packet Rows Captured | 1,707 | Packet rows inserted by `live_packet_collector.py`; not the same as packets replayed |

Earlier clean measurement produced 786 raw alerts. The final dashboard screenshot shows 807 raw alerts because additional alerts were generated after the first clean replay. The README reports the final dashboard state.

### Replay Command

Run this from the Kali VM:

```bash
sudo tcpreplay -i eth1 --loop=1 --pps=800 ~/nids-pcaps/scanner-test/clean/multi_attack_demo_mtu1500.pcap
```

Packets are not equal to alerts. Most packets are TCP handshakes, ACKs, responses, and normal traffic. Snort only generates alerts when traffic matches an enabled rule.

---

## Top Alerts Observed

| Alert Signature | Count | Explanation |
|---|---:|---|
| `SERVER-WEBAPP Compaq Insight directory traversal` | 320 | Directory traversal style web request; likely caused by web scanning probes |
| `SERVER-WEBAPP iChat directory traversal attempt` | 215 | Directory traversal attempt against a known legacy web path |
| `OS-MOBILE Apple iPhone User-Agent detected` | 50 | Mobile User-Agent string detected during scanner/random-agent traffic |
| `OS-MOBILE Android User-Agent detected` | 33 | Android User-Agent string detected during scanner/random-agent traffic |
| `SERVER-WEBAPP remote include path attempt` | 15 | Possible remote file inclusion or suspicious web parameter attempt |

These alerts came mainly from web scanning, directory traversal attempts, User-Agent variation, DVWA-style attacks, and suspicious web payloads.

---

## Enriched Alert JSON Export

The enriched alert JSON is generated by joining:

```text
ids_live.db alerts table
+
data/json/rule_docs_preprocessed_by_sid.json
```

The output file is:

```text
data/json/enriched_snort_alerts_with_rule_docs.json
```

Run:

```bash
cd /home/maheen/ids_streamlit_dashboard
python3 scripts/export_enriched_alerts_json.py
```

This file contains selected alert fields with matching rule documentation. It is a latest snapshot, not permanent full alert history.

If the dashboard shows:

```text
This selected alert was not found in the enriched JSON file.
```

run the export script again to refresh the combined JSON.

---

## Database Management

The system uses a rolling-window storage strategy.

### Packets

- Captured using Scapy
- Stored in SQLite
- Latest 5,000 packets retained

### Alerts

- Generated by Snort
- Parsed from Snort JSON alert logs
- Stored in SQLite
- Latest 10,000 alerts retained

This prevents unlimited database growth while preserving recent monitoring information for the dashboard.

Raw Snort alerts are also saved separately in:

```text
/home/maheen/snort_logs/alert_json.txt
```

---

## Snort Log Rotation

Snort alert logs can be managed using `logrotate`.

Recommended behavior:

- Rotate after 5 MB
- Keep the latest 5 rotated logs
- Compress old logs automatically
- Continue logging without restarting Snort

Example log files:

```text
alert_json.txt
alert_json.txt.1
alert_json.txt.2.gz
alert_json.txt.3.gz
```

---

## Versioning

This project uses Git tags for dashboard version history.

| Version | Description |
|---|---|
| `dashboard-v1.0` | First complete Streamlit IDS dashboard release with live packet capture, Snort alert parsing, SQLite storage, and basic traffic/alert visualizations |
| `dashboard-v2.0` | Added expanded Snort rule documentation dataset, dataset exports, helper scripts, normalized rule database, and JSON rule lookup support |
| `dashboard-v3.0` | Added page-based dashboard navigation, separated Alert Dashboard and Network Traffic Dashboard, improved sidebar layout, metric cards, clickable alert-row rule details, and cleaner rule documentation display |
| `dashboard-v4.0` | Added Total Raw Alerts metric, increased alert retention to 10,000, added enriched alert JSON export, selected enriched alert JSON display, PCAP replay statistics, custom multi-attack PCAP evaluation, updated screenshots, and updated documentation |

To view a previous version:

```bash
git checkout dashboard-v1.0
```

To return to the latest version:

```bash
git checkout main
```

To create the v4.0 tag:

```bash
git tag -a dashboard-v4.0 -m "Dashboard version 4.0 - enriched alert JSON, PCAP replay statistics, screenshots, and 10000 alert retention"
git push origin dashboard-v4.0
```

---

## Dashboard Preview

Updated v4 dashboard screenshots are available in the `screenshots/` folder.

| Screenshot | Description |
|---|---|
| `image1.png` | Network Traffic Dashboard with packet metrics, active hosts, HTTP requests, and traffic charts |
| `image2.png` | Alert Dashboard summary cards showing total raw alerts, alert types, and priority counts |
| `image3.png` | PCAP Replay and Alert Generation Statistics table |
| `image4.png` | Detailed Recent Snort Alerts table with selected alert row |
| `image5.png` | Selected alert JSON/fallback database view |

The dashboard includes:

- Main traffic metrics
- Protocol distribution
- Service distribution
- Snort alert analysis
- Recent packet view
- Recent alert view
- Selected enriched alert JSON
- Snort ruleset status
- PCAP replay statistics

---

## Troubleshooting

### Dashboard not updating

Ensure:

- Packet collector is running
- Alert collector is running
- Snort is running
- Streamlit dashboard is running
- Browser/dashboard refresh is enabled

### No packets captured

Check:

- Correct interface is configured
- Host-only adapter is connected
- Kali, victim, and Snort VM are on the same network
- Scapy collector is running with `sudo`

### No Snort alerts

Check:

- Snort community rules are loaded
- Snort is monitoring the correct interface
- Traffic matches enabled Snort signatures
- Alert collector is reading the correct JSON alert log

### Selected alert not found in enriched JSON

Run:

```bash
cd /home/maheen/ids_streamlit_dashboard
python3 scripts/export_enriched_alerts_json.py
```

Then refresh the dashboard.

### Kali cannot reach victim

Check Kali IP and route:

```bash
ip -br addr
ip route
```

Expected Kali host-only IP:

```text
192.168.56.10/24
```

Test victim connectivity:

```bash
ping -c 4 192.168.56.20
```

### SQLite database growing too large

The project automatically limits:

```text
Packets → Latest 5,000
Alerts  → Latest 10,000
```

Snort logs are managed separately using log rotation.

### Dashboard accessible locally but not from other systems

Check:

- Windows host IP
- Windows firewall rule
- VirtualBox NAT port forwarding
- Windows portproxy rule
- Whether the other system can route to the Windows host IP

### DNS not working inside Ubuntu VM

If `ping 8.8.8.8` works but `ping google.com` fails, DNS is the issue.

```bash
sudo rm -f /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

---

## Files Not Committed

The following runtime or large files are intentionally not committed:

```text
ids_live.db
alert_json.txt
multi_attack_demo_mtu1500.pcap
__pycache__/
*.log
```

Reason:

- `ids_live.db` is runtime database output
- `alert_json.txt` is generated Snort alert output
- `multi_attack_demo_mtu1500.pcap` is large test traffic data
- Logs and cache files are generated during execution

---

## Future Improvements

- LLM/RAG-based Snort alert explanation
- Automated rule context retrieval from the JSON dataset
- Alert notifications for high-priority events
- Multi-sensor monitoring
- Better packet-to-alert correlation
- PostgreSQL or Elasticsearch backend
- Historical trend analysis
- Authentication for shared dashboard access
- Deployment on a dedicated lab-accessible server

---

## License

This project is released under the MIT License.

---

## Author

**Maheen Nadeem**  
BS Computer Science  
Real-Time Network Intrusion Detection System Internship Project