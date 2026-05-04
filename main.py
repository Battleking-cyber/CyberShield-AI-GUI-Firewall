"""
Windows Cyber Firewall - Enhanced Edition
Cross-platform: Windows & Kali Linux
Features:
  - Malicious packet detection (port scans, DDoS, SYN flood, bad ports)
  - Auto-blocking of malicious IPs
  - Log file export (firewall_logs.txt, blocked_packets.txt)
  - Last Destination IP tracking
  - Works on Windows (netsh) and Linux (iptables)
"""

import sys
import os
import platform
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QLineEdit, QComboBox, QMessageBox, QAction, QFileDialog, QHeaderView
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QColor

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── OS Detection ──────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

LOG_DIR          = os.path.join(os.path.expanduser("~"), "FirewallLogs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE         = os.path.join(LOG_DIR, "firewall_logs.txt")
BLOCKED_LOG_FILE = os.path.join(LOG_DIR, "blocked_packets.txt")

# ── Threat Thresholds ─────────────────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    22, 23, 3389, 445, 135, 137, 138, 139,
    4444, 5555, 6666, 7777, 9001, 9002,
    1433, 3306, 5432, 6379, 27017,
}
PACKET_RATE_THRESHOLD = 100   # packets/sec
SYN_FLOOD_THRESHOLD   = 50
PORT_SCAN_THRESHOLD   = 15


def write_log(path, line):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


class WindowsCyberFirewall(QMainWindow):
    log_signal   = pyqtSignal(str, str, str, str)
    conn_signal  = pyqtSignal(tuple)
    risk_signal  = pyqtSignal()
    alert_signal = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Firewall — Enhanced Cross-Platform Edition")
        self.setGeometry(150, 80, 1350, 780)

        self.packet_count = 0
        self.ip_frequency = defaultdict(int)
        self.ip_rate      = defaultdict(int)
        self.ip_syn_count = defaultdict(int)
        self.ip_ports     = defaultdict(set)
        self.blocked_ips  = set()
        self.safe_ips     = {"127.0.0.1", "::1", "localhost"}
        self.log_id       = 1
        self.last_dst_ip  = "—"
        self.threat_count = 0
        self.monitoring   = False

        self.rate_timer = QTimer()
        self.rate_timer.timeout.connect(self._reset_rates)
        self.rate_timer.start(1000)

        self._init_ui()
        self._init_menu()

        self.log_signal.connect(self._add_log)
        self.conn_signal.connect(self._add_connection)
        self.risk_signal.connect(self._update_risky)
        self.alert_signal.connect(self._add_blocked_alert)

        write_log(LOG_FILE, f"\n{'='*60}")
        write_log(LOG_FILE, f"Session Started: {datetime.now()}")
        write_log(LOG_FILE, f"OS: {platform.system()} {platform.release()}")
        write_log(LOG_FILE, f"{'='*60}")

    def _init_menu(self):
        mb = self.menuBar()
        file_menu = mb.addMenu("File")
        exp = QAction("Export Logs…", self)
        exp.triggered.connect(self._export_logs)
        opn = QAction("Open Log Folder", self)
        opn.triggered.connect(self._open_log_folder)
        file_menu.addAction(exp)
        file_menu.addAction(opn)
        help_menu = mb.addMenu("Help")
        about = QAction("About", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _open_log_folder(self):
        if IS_WINDOWS:
            os.startfile(LOG_DIR)
        else:
            subprocess.Popen(["xdg-open", LOG_DIR])

    def _show_about(self):
        QMessageBox.information(self, "About",
            "Cyber Firewall — Enhanced Cross-Platform Edition v2.0\n\n"
            f"Running on: {platform.system()} {platform.release()}\n\n"
            "Features:\n"
            "  • Malicious packet detection (SYN flood, port scan, DDoS)\n"
            "  • Auto IP blocking via netsh / iptables\n"
            "  • Log files saved to ~/FirewallLogs/\n"
            "  • Last Destination IP tracking\n"
            "  • Works on Windows & Kali Linux\n\n"
            "Educational use only."
        )

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        hdr = QHBoxLayout()
        title = QLabel("🔥 Cyber Firewall — Enhanced")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#00ff9c;")
        self.os_lbl = QLabel(f"  {platform.system()} {platform.release()}")
        self.os_lbl.setStyleSheet("color:#aaa;font-size:11px;")
        hdr.addWidget(title)
        hdr.addWidget(self.os_lbl)
        hdr.addStretch()
        root.addLayout(hdr)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        self._init_dashboard()
        self._init_logs()
        self._init_blocked()
        self._init_connections()
        self._init_risky()
        self._init_rules()

        self.setStyleSheet("""
            QMainWindow,QWidget{background:#0b0f14;}
            QLabel{color:#00ff9c;font-family:Consolas;}
            QPushButton{background:#020617;border:1px solid #00ff9c;padding:6px 14px;color:#00ff9c;border-radius:3px;}
            QPushButton:hover{background:#00ff9c;color:black;}
            QTabBar::tab{background:#020617;color:#00ff9c;padding:9px 16px;}
            QTabBar::tab:selected{background:#00ff9c;color:black;font-weight:bold;}
            QTableWidget{background:#020617;color:#00ff9c;gridline-color:#1a2a1a;}
            QHeaderView::section{background:#051005;color:#00ff9c;border:1px solid #00ff9c;padding:4px;}
            QLineEdit,QComboBox{background:#020617;color:#00ff9c;border:1px solid #00ff9c;padding:4px;}
        """)

    def _stat_box(self, label_text):
        box = QWidget()
        box.setStyleSheet("background:#051005;border:1px solid #00ff9c;border-radius:4px;padding:8px;min-width:160px;")
        v = QVBoxLayout(box)
        v.setContentsMargins(8,8,8,8)
        lbl = QLabel(label_text)
        lbl.setStyleSheet("color:#aaa;font-size:11px;")
        val = QLabel("0")
        val.setStyleSheet("color:#00ff9c;font-size:20px;font-weight:bold;")
        v.addWidget(lbl)
        v.addWidget(val)
        box._val = val
        return box

    def _init_dashboard(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        stats = QHBoxLayout()
        self.sb_pkts    = self._stat_box("Packets Captured")
        self.sb_blocked = self._stat_box("Blocked IPs")
        self.sb_threats = self._stat_box("Threats Detected")
        self.sb_lastdst = self._stat_box("Last Destination IP")
        self.sb_lastdst._val.setStyleSheet("color:#00ff9c;font-size:13px;font-weight:bold;")
        for sb in [self.sb_pkts, self.sb_blocked, self.sb_threats, self.sb_lastdst]:
            stats.addWidget(sb)
        lay.addLayout(stats)

        ctrl = QHBoxLayout()
        self.start_btn = QPushButton("▶  Start Monitoring")
        self.start_btn.clicked.connect(self._start_monitoring)
        self.stop_btn = QPushButton("⏹  Stop")
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.stop_btn.setEnabled(False)

        # Interface selector (critical for Windows)
        iface_lbl = QLabel("Interface:")
        iface_lbl.setStyleSheet("color:#aaa;font-size:11px;")
        self.iface_box = QComboBox()
        self.iface_box.setMinimumWidth(220)
        self.iface_box.setToolTip("Select the network adapter to capture packets from")
        self._populate_interfaces()

        refresh_btn = QPushButton("⟳")
        refresh_btn.setFixedWidth(30)
        refresh_btn.setToolTip("Refresh interface list")
        refresh_btn.clicked.connect(self._populate_interfaces)

        ctrl.addWidget(self.start_btn)
        ctrl.addWidget(self.stop_btn)
        ctrl.addSpacing(20)
        ctrl.addWidget(iface_lbl)
        ctrl.addWidget(self.iface_box)
        ctrl.addWidget(refresh_btn)
        ctrl.addStretch()
        lay.addLayout(ctrl)

        log_lbl = QLabel(f"📁 Logs: {LOG_DIR}")
        log_lbl.setStyleSheet("color:#aaa;font-size:11px;")
        lay.addWidget(log_lbl)

        if not SCAPY_AVAILABLE:
            warn = QLabel("⚠  Scapy not installed!  Run:  pip install scapy")
            warn.setStyleSheet("color:#ff4444;font-size:13px;font-weight:bold;")
            lay.addWidget(warn)

        lay.addStretch()
        self.tabs.addTab(tab, "Dashboard")

    def _init_logs(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        row = QHBoxLayout()
        clr = QPushButton("Clear")
        clr.clicked.connect(lambda: self.log_table.setRowCount(0))
        row.addStretch(); row.addWidget(clr)
        lay.addLayout(row)
        self.log_table = QTableWidget(0, 6)
        self.log_table.setHorizontalHeaderLabels(["#","Time","IP","Type","Action","Reason"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.log_table)
        self.tabs.addTab(tab, "All Logs")

    def _init_blocked(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        info = QLabel("⚠  Malicious packets blocked automatically. Full details saved to blocked_packets.txt")
        info.setStyleSheet("color:#ff9900;font-size:11px;")
        lay.addWidget(info)
        self.blocked_table = QTableWidget(0, 7)
        self.blocked_table.setHorizontalHeaderLabels(
            ["Time","Src IP","Dst IP","Protocol","Port","Reason","Full Packet Info"]
        )
        self.blocked_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.blocked_table)
        self.tabs.addTab(tab, "🚫 Blocked Packets")

    def _init_connections(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        self.conn_table = QTableWidget(0, 7)
        self.conn_table.setHorizontalHeaderLabels(
            ["Src IP","Dst IP","Src Port","Dst Port","Protocol","Time","Status"]
        )
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.conn_table)
        self.tabs.addTab(tab, "Connections")

    def _init_risky(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        self.risky_table = QTableWidget(0, 4)
        self.risky_table.setHorizontalHeaderLabels(
            ["IP Address","Total Packets","Distinct Ports Scanned","Status"]
        )
        self.risky_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        btn_row = QHBoxLayout()
        blk = QPushButton("🚫  Block Selected IP")
        blk.setStyleSheet("border-color:#ff4444;color:#ff4444;")
        ublk = QPushButton("✅  Unblock Selected IP")
        blk.clicked.connect(self._block_selected)
        ublk.clicked.connect(self._unblock_selected)
        btn_row.addWidget(blk); btn_row.addWidget(ublk); btn_row.addStretch()
        lay.addWidget(self.risky_table)
        lay.addLayout(btn_row)
        self.tabs.addTab(tab, "Risky IPs")

    def _init_rules(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.addWidget(QLabel("Add Custom Firewall Rule:"))
        form = QHBoxLayout()
        self.ip_input  = QLineEdit(); self.ip_input.setPlaceholderText("IP Address")
        self.prt_input = QLineEdit(); self.prt_input.setPlaceholderText("Port (e.g. 22)")
        self.pro_box   = QComboBox(); self.pro_box.addItems(["TCP","UDP","ANY"])
        self.act_box   = QComboBox(); self.act_box.addItems(["BLOCK","ALLOW"])
        add_btn = QPushButton("+ Add Rule")
        add_btn.clicked.connect(self._add_rule)
        for w in [self.ip_input, self.prt_input, self.pro_box, self.act_box, add_btn]:
            form.addWidget(w)
        lay.addLayout(form)
        note = QLabel(
            f"Rules applied via: {'netsh (Windows)' if IS_WINDOWS else 'iptables (Linux)'}  •  Requires Administrator / root"
        )
        note.setStyleSheet("color:#aaa;font-size:11px;margin-top:8px;")
        lay.addWidget(note)
        lay.addStretch()
        self.tabs.addTab(tab, "Firewall Rules")

    def _populate_interfaces(self):
        """Load available network interfaces into the dropdown."""
        self.iface_box.clear()
        if not SCAPY_AVAILABLE:
            self.iface_box.addItem("Scapy not installed")
            return
        try:
            ifaces = get_if_list()
            default = str(conf.iface)
            selected_idx = 0
            for i, iface in enumerate(ifaces):
                self.iface_box.addItem(iface)
                if default in iface or iface in default:
                    selected_idx = i
            if ifaces:
                self.iface_box.setCurrentIndex(selected_idx)
            else:
                self.iface_box.addItem("No interfaces found — install Npcap")
        except Exception as e:
            self.iface_box.addItem(f"Error: {e}")

    # ── Monitoring ────────────────────────────────────────────────────────────
    def _start_monitoring(self):
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Scapy Missing",
                "Scapy is not installed.\n\nInstall it:\n  pip install scapy\n\nOn Linux also run as root/sudo.")
            return
        self.monitoring = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        threading.Thread(target=self._sniff_thread, daemon=True).start()

    def _stop_monitoring(self):
        self.monitoring = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _sniff_thread(self):
        iface = self.iface_box.currentText()
        # Fallback to scapy default if nothing valid selected
        if not iface or "Error" in iface or "No interfaces" in iface or "not installed" in iface:
            iface = None
        try:
            sniff(iface=iface, prn=self._process_packet, store=False,
                  stop_filter=lambda _: not self.monitoring)
        except Exception as e:
            # Show error in UI thread safely
            self.log_signal.emit("SYSTEM", "ERROR", "STOPPED", f"Sniff error: {e}")

    def _reset_rates(self):
        self.ip_rate.clear()

    # ── Packet Processing ─────────────────────────────────────────────────────
    def _process_packet(self, pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "OTHER"; sp = dp = "-"
        if TCP in pkt:
            proto = "TCP"; sp = str(pkt[TCP].sport); dp = str(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"; sp = str(pkt[UDP].sport); dp = str(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"

        if src in self.safe_ips:
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.packet_count += 1
        self.ip_frequency[src] += 1
        self.ip_rate[src] += 1
        self.last_dst_ip = dst

        if dp.isdigit():
            self.ip_ports[src].add(int(dp))

        threat, reason = self._detect_threat(pkt, src, proto, dp)
        action = "BLOCKED" if threat else "OBSERVED"
        pkt_info = f"{proto} {src}:{sp} → {dst}:{dp}"

        self.log_signal.emit(src, proto, action, reason if reason else "Normal traffic")
        self.conn_signal.emit((src, dst, sp, dp, proto, now, action))

        if threat:
            if src not in self.blocked_ips:
                self.blocked_ips.add(src)
                self._apply_block(src)
            self.alert_signal.emit(src, reason, pkt_info)
            write_log(BLOCKED_LOG_FILE,
                f"[{now}] BLOCKED | SRC={src} DST={dst} PROTO={proto} PORT={dp} | Reason: {reason} | {pkt_info}")

        self.risk_signal.emit()
        write_log(LOG_FILE, f"[{now}] {action} | {pkt_info} | {reason or 'Normal'}")

    def _detect_threat(self, pkt, src, proto, dp):
        if src in self.blocked_ips:
            return True, "Previously blocked IP"
        if TCP in pkt and int(pkt[TCP].flags) == 0x002:
            self.ip_syn_count[src] += 1
            if self.ip_syn_count[src] > SYN_FLOOD_THRESHOLD:
                return True, f"SYN Flood detected ({self.ip_syn_count[src]} SYNs)"
        if len(self.ip_ports[src]) > PORT_SCAN_THRESHOLD:
            return True, f"Port Scan detected ({len(self.ip_ports[src])} ports)"
        if self.ip_rate[src] > PACKET_RATE_THRESHOLD:
            return True, f"DDoS / High rate ({self.ip_rate[src]} pkt/s)"
        if dp.isdigit() and int(dp) in SUSPICIOUS_PORTS and self.ip_frequency[src] > 20:
            return True, f"Repeated access to suspicious port {dp}"
        return False, ""

    # ── UI Updates ────────────────────────────────────────────────────────────
    def _add_log(self, ip, typ, action, reason):
        r = self.log_table.rowCount()
        self.log_table.insertRow(r)
        for c, v in enumerate([self.log_id, datetime.now().strftime("%H:%M:%S"), ip, typ, action, reason]):
            item = QTableWidgetItem(str(v))
            if action == "BLOCKED":
                item.setForeground(QColor("#ff4444"))
            self.log_table.setItem(r, c, item)
        self.log_id += 1
        self.log_table.scrollToBottom()

    def _add_connection(self, data):
        r = self.conn_table.rowCount()
        self.conn_table.insertRow(r)
        for i, v in enumerate(data):
            item = QTableWidgetItem(str(v))
            if data[6] == "BLOCKED":
                item.setForeground(QColor("#ff4444"))
            self.conn_table.setItem(r, i, item)
        self.conn_table.scrollToBottom()

    def _add_blocked_alert(self, ip, reason, pkt_info):
        self.threat_count += 1
        self.sb_threats._val.setText(str(self.threat_count))
        parts = pkt_info.split()
        proto    = parts[0] if len(parts) > 0 else "?"
        src_part = parts[1] if len(parts) > 1 else "?:?"
        dst_part = parts[3] if len(parts) > 3 else "?:?"
        src_ip   = src_part.rsplit(":", 1)[0]
        dst_ip, dst_port = (dst_part.rsplit(":", 1) + ["?"])[:2] if ":" in dst_part else (dst_part, "?")

        r = self.blocked_table.rowCount()
        self.blocked_table.insertRow(r)
        now = datetime.now().strftime("%H:%M:%S")
        for c, v in enumerate([now, src_ip, dst_ip, proto, dst_port, reason, pkt_info]):
            item = QTableWidgetItem(str(v))
            item.setForeground(QColor("#ff4444"))
            self.blocked_table.setItem(r, c, item)
        self.blocked_table.scrollToBottom()

    def _update_risky(self):
        self.sb_pkts._val.setText(str(self.packet_count))
        self.sb_blocked._val.setText(str(len(self.blocked_ips)))
        self.sb_lastdst._val.setText(self.last_dst_ip)

        self.risky_table.setRowCount(0)
        for ip, count in sorted(self.ip_frequency.items(), key=lambda x: -x[1])[:100]:
            if count < 10:
                continue
            r = self.risky_table.rowCount()
            self.risky_table.insertRow(r)
            ports = len(self.ip_ports[ip])
            status = "BLOCKED" if ip in self.blocked_ips else ("HIGH RISK" if count > 100 else "Watching")
            for c, v in enumerate([ip, count, ports, status]):
                item = QTableWidgetItem(str(v))
                if status == "BLOCKED":
                    item.setForeground(QColor("#ff4444"))
                elif status == "HIGH RISK":
                    item.setForeground(QColor("#ff9900"))
                self.risky_table.setItem(r, c, item)

    # ── Blocking Helpers ──────────────────────────────────────────────────────
    def _apply_block(self, ip):
        try:
            if IS_WINDOWS:
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="CyberFW_Block_{ip}" '
                    f'dir=in action=block remoteip={ip}',
                    shell=True, capture_output=True
                )
            elif IS_LINUX:
                subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True)
        except Exception as e:
            print(f"Block error: {e}")

    def _apply_unblock(self, ip):
        try:
            if IS_WINDOWS:
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="CyberFW_Block_{ip}"',
                    shell=True, capture_output=True
                )
            elif IS_LINUX:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True)
        except Exception as e:
            print(f"Unblock error: {e}")

    def _block_selected(self):
        r = self.risky_table.currentRow()
        if r < 0:
            QMessageBox.warning(self, "Select IP", "Please select a row first.")
            return
        ip = self.risky_table.item(r, 0).text()
        self.blocked_ips.add(ip)
        self._apply_block(ip)
        write_log(BLOCKED_LOG_FILE, f"[{datetime.now()}] MANUAL BLOCK | IP: {ip}")
        QMessageBox.information(self, "Blocked", f"{ip} has been blocked.")
        self._update_risky()

    def _unblock_selected(self):
        r = self.risky_table.currentRow()
        if r < 0:
            return
        ip = self.risky_table.item(r, 0).text()
        self.blocked_ips.discard(ip)
        self.ip_syn_count.pop(ip, None)
        self.ip_rate.pop(ip, None)
        self._apply_unblock(ip)
        write_log(LOG_FILE, f"[{datetime.now()}] UNBLOCKED | IP: {ip}")
        QMessageBox.information(self, "Unblocked", f"{ip} has been unblocked.")
        self._update_risky()

    # ── Custom Rules ──────────────────────────────────────────────────────────
    def _add_rule(self):
        ip     = self.ip_input.text().strip()
        port   = self.prt_input.text().strip()
        proto  = self.pro_box.currentText()
        action = self.act_box.currentText().lower()
        if not ip or not port:
            QMessageBox.warning(self, "Missing Fields", "IP and Port are required.")
            return
        try:
            if IS_WINDOWS:
                p_flag = "" if proto == "ANY" else f"protocol={proto.lower()} localport={port} "
                cmd = (f'netsh advfirewall firewall add rule name="CyberFW_{ip}_{port}" '
                       f'dir=in action={action} {p_flag}remoteip={ip}')
                subprocess.run(cmd, shell=True, capture_output=True)
            elif IS_LINUX:
                flag = "ACCEPT" if action == "allow" else "DROP"
                args = ["iptables", "-I", "INPUT", "-s", ip]
                if proto != "ANY":
                    args += ["-p", proto.lower(), "--dport", port]
                args += ["-j", flag]
                subprocess.run(args, capture_output=True)
            write_log(LOG_FILE, f"[{datetime.now()}] RULE ADDED | {action.upper()} {ip}:{port} {proto}")
            QMessageBox.information(self, "Rule Added",
                f"Rule created successfully!\nAction: {action.upper()}  IP: {ip}  Port: {port}  Proto: {proto}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ── Export ────────────────────────────────────────────────────────────────
    def _export_logs(self):
        dest, _ = QFileDialog.getSaveFileName(self, "Export Logs", "firewall_export.txt", "Text (*.txt)")
        if dest:
            import shutil
            shutil.copy(LOG_FILE, dest)
            QMessageBox.information(self, "Exported", f"Logs exported to:\n{dest}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = WindowsCyberFirewall()
    win.show()
    sys.exit(app.exec_())
