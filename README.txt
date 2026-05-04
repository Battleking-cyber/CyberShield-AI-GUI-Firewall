================================================================
  CYBER FIREWALL — Enhanced Cross-Platform Edition v2.0
  Works on: Windows 10/11 & Kali Linux
================================================================

WHAT'S NEW IN v2.0
------------------
  Malicious packet detection (SYN Flood, Port Scan, DDoS, Bad Ports)
  Auto IP blocking via netsh (Windows) / iptables (Linux)
  Blocked packet log: ~/FirewallLogs/blocked_packets.txt
  Full activity log:  ~/FirewallLogs/firewall_logs.txt
  Last Destination IP shown live on dashboard
  Threat counter on dashboard
  Red highlighting for blocked/malicious traffic
  Export logs from File menu
  Cross-platform — same main.py file runs on both OS


================================================================
HOW TO RUN ON WINDOWS
================================================================

STEP 1 — Install Python 3.8+
  https://www.python.org/downloads/
  Check "Add Python to PATH"

STEP 2 — Install Npcap (required for packet capture)
  https://npcap.com/#download
  Enable "WinPcap API-compatible Mode" during install

STEP 3 — Open CMD as Administrator, install packages
  pip install PyQt5 scapy

STEP 4 — Run (must be Administrator)
  python main.py

COMMON ERRORS:
  "No module PyQt5/scapy"     -> pip install PyQt5 scapy
  "Sniff returns nothing"     -> Install Npcap, run as Admin
  "netsh access denied"       -> Run CMD as Administrator


================================================================
HOW TO RUN ON KALI LINUX
================================================================

STEP 1 — Install packages
  sudo apt update
  sudo apt install python3-pyqt5 -y
  sudo pip3 install scapy --break-system-packages

STEP 2 — Run as root (required for raw sockets + iptables)
  sudo python3 main.py

STEP 3 — If display error (SSH users):
  Use ssh -X for X forwarding, or run in desktop session

COMMON ERRORS:
  "Permission denied"          -> sudo python3 main.py
  "iptables: command not found"-> sudo apt install iptables
  PyQt5 not found              -> sudo apt install python3-pyqt5


================================================================
HOW THE CODE WORKS
================================================================

1. PACKET CAPTURE
   Scapy's sniff() runs in a background daemon thread.
   Every IP packet passes through _process_packet().

2. THREAT DETECTION (4 types)

   a) SYN FLOOD
      Counts TCP SYN-only flags per IP.
      Threshold: 50 SYNs from same IP.
      How: Attacker sends SYNs without completing handshake.

   b) PORT SCAN
      Tracks how many distinct ports each IP probes.
      Threshold: 15 different ports.
      How: Attacker maps open services on a host.

   c) DDoS / HIGH RATE
      Counts packets/second per IP (resets every 1 sec).
      Threshold: 100 pkt/sec.
      How: Floods target with traffic.

   d) SUSPICIOUS PORTS
      Known dangerous ports: 4444 (Metasploit), 3389 (RDP),
      445 (SMB), 22/23 (brute force), 3306 (MySQL), etc.
      Flagged when IP sends 20+ packets to these ports.

3. BLOCKING
   Windows:  netsh advfirewall firewall add rule ...
   Linux:    iptables -I INPUT -s <IP> -j DROP

4. LOG FILES (saved to ~/FirewallLogs/)
   firewall_logs.txt      -> All traffic events
   blocked_packets.txt    -> Malicious/blocked events only

   Example log line:
   [2025-01-01 14:30:00] BLOCKED | TCP 192.168.1.5:53421 -> 10.0.0.1:4444 | Port Scan (18 ports)

5. TABS
   Dashboard      Live stats: packets, blocked IPs, threats, last dst IP
   All Logs       Every packet event (red=blocked)
   Blocked Pkts   Malicious events with full packet details
   Connections    Live connection table with src/dst/port/protocol
   Risky IPs      IPs with 10+ packets, sortable
   Firewall Rules Manually add block/allow rules


================================================================
IS REAL-TIME POSSIBLE?
================================================================

YES — The app already works in real-time.
Scapy captures packets live, PyQt5 signals update the UI
immediately for every packet.

LIMITATIONS:
  - At very high traffic (>10,000 pkt/sec), UI may lag.
  - Must run as admin/root for raw packet access.
  - For enterprise scale, move detection to a separate process.

DO YOU NEED A WEBSITE?
  - Single machine monitoring  -> This GUI is enough.
  - Multi-machine / remote     -> Add Flask/FastAPI backend
                                  with a web dashboard.
  - Team collaboration         -> A web dashboard makes sense.


================================================================
ADJUSTABLE THRESHOLDS (in main.py)
================================================================

PACKET_RATE_THRESHOLD = 100   # pkt/sec triggers DDoS alert
SYN_FLOOD_THRESHOLD   = 50    # SYN count triggers flood alert
PORT_SCAN_THRESHOLD   = 15    # distinct ports triggers scan alert


================================================================
QUICK START
================================================================

Windows (CMD as Admin):
  pip install PyQt5 scapy
  python main.py

Kali Linux:
  sudo apt install python3-pyqt5 -y
  sudo pip3 install scapy --break-system-packages
  sudo python3 main.py

================================================================
