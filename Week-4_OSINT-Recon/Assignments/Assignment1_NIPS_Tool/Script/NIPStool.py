import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import scapy.all as scapy
import threading
import queue
import time
import subprocess
import re
from collections import defaultdict
import platform
import os

# --- IPS Detection Thresholds ---
ICMP_LIMIT = 10          # ICMP pings per 3 seconds
SYN_LIMIT = 30           # TCP SYNs per 10 seconds per IP
PORTSCAN_WINDOW = 8      # Different ports in 3 seconds
HTTP_VIOLATION_LIMIT = 2 # HTTP violations before blocking
TIME_WINDOW_ICMP = 3     # ICMP tracking window (seconds)
TIME_WINDOW_SYN = 10     # SYN tracking window (seconds)
TIME_WINDOW_SCAN = 3     # Port scan tracking window (seconds)

# --- Pattern Matching ---
HTTP_SUSPICIOUS_REGEX = re.compile(
    r"(union\s+select|[\';]+or[\s\d]+=|1=1--|<script>|alert\(|onerror=|"
    r"\bselect.+from\b|drop\s+table|insert\s+into|update.+set)",
    re.IGNORECASE
)

SQL_INJECTION_PATTERNS = [
    b'SELECT', b'UNION', b'INSERT', b'DROP', b'UPDATE', b'DELETE',
    b'--', b"'", b'OR 1=1', b'UNION SELECT'
]

XSS_PATTERNS = [
    b'<script>', b'alert(', b'onerror=', b'javascript:', b'onload='
]

# --- Global Tracking Dictionaries ---
icmp_counts = defaultdict(list)
syn_counts = defaultdict(list)
scan_ports = defaultdict(lambda: defaultdict(list))
http_violations = defaultdict(int)
blocked_ips = set()

class IPS:
    """
    Enhanced Intrusion Prevention System with GUI - Detects and blocks malicious traffic
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced IPS | Intrusion Prevention System")
        self.root.geometry("1800x1200")
        self.root.minsize(1400, 900)
        
        # Enable high DPI support
        try:
            self.root.tk.call('tk', 'scaling', 1.0)
        except:
            pass

        self.current_theme = "dark"
        self._define_themes()

        self.sniffing = False
        self.blocking_enabled = True
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.is_admin = self._check_admin_privileges()
        
        # Data storage
        self.packet_count = 0
        self.threat_count = 0
        self.blocked_count = 0
        self.packet_data_storage = {}
        self.blocked_threats = []  # Store blocked threats separately
        
        self._create_widgets()
        self._apply_theme()
        
        self.root.after(100, self.update_gui)
        self._show_admin_warning()

    def _check_admin_privileges(self):
        """Check if the application has admin privileges for blocking"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    def _show_admin_warning(self):
        """Show warning if not running with admin privileges"""
        if not self.is_admin:
            messagebox.showwarning(
                "Administrator Required",
                "IPS requires administrator privileges to block IPs.\n"
                "Some blocking features may not work properly.\n\n"
                "On Windows: Run as Administrator\n"
                "On Linux/Mac: Run with sudo"
            )

    def _define_themes(self):
        """Define color palettes for light and dark themes with better contrast"""
        self.themes = {
            "dark": {
                "bg": "#1a1a1a", "text": "#e0e0e0", "frame_bg": "#2d2d2d",
                "button_bg": "#0e639c", "button_active_bg": "#1177bb", "button_fg": "#ffffff",
                "button_danger_bg": "#d32f2f", "button_danger_active": "#b71c1c",
                "button_success_bg": "#388e3c", "button_success_active": "#2e7d32",
                "tree_bg": "#2d2d2d", "tree_field_bg": "#2d2d2d", "tree_heading_bg": "#404040",
                "tree_selected_bg": "#404040", "text_bg": "#1a1a1a", "separator": "#555555",
                "sash": "#555555", "warning": "#ff9800", "danger": "#f44336", "success": "#4caf50",
                "insert_bg": "#ffffff", "select_bg": "#0078d4", "select_fg": "#ffffff"
            },
            "light": {
                "bg": "#f5f5f5", "text": "#212121", "frame_bg": "#ffffff",
                "button_bg": "#1976d2", "button_active_bg": "#1565c0", "button_fg": "#ffffff",
                "button_danger_bg": "#d32f2f", "button_danger_active": "#c62828",
                "button_success_bg": "#388e3c", "button_success_active": "#2e7d32",
                "tree_bg": "#ffffff", "tree_field_bg": "#ffffff", "tree_heading_bg": "#e3f2fd",
                "tree_selected_bg": "#bbdefb", "text_bg": "#ffffff", "separator": "#e0e0e0",
                "sash": "#bdbdbd", "warning": "#ff9800", "danger": "#d32f2f", "success": "#388e3c",
                "insert_bg": "#000000", "select_bg": "#0078d4", "select_fg": "#ffffff"
            }
        }

    def _apply_theme(self):
        """Apply the currently selected theme to all GUI elements with improved clarity"""
        theme = self.themes[self.current_theme]
        self.root.configure(bg=theme["bg"])

        style = ttk.Style()
        style.theme_use('clam')

        # Configure styles with better fonts and contrast
        style.configure("TFrame", background=theme["frame_bg"])
        style.configure("Main.TFrame", background=theme["bg"])
        style.configure("TLabel", background=theme["frame_bg"], foreground=theme["text"], 
                       font=("Segoe UI", 10))
        style.configure("Title.TLabel", background=theme["bg"], foreground=theme["text"], 
                       font=("Segoe UI", 16, "bold"))
        style.configure("Status.TLabel", background=theme["bg"], foreground=theme["text"], 
                       font=("Segoe UI", 9))
        style.configure("Stats.TLabel", background=theme["frame_bg"], foreground=theme["text"], 
                       font=("Segoe UI", 10, "bold"))
        style.configure("Section.TLabel", background=theme["frame_bg"], foreground=theme["text"], 
                       font=("Segoe UI", 12, "bold"))
        style.configure("TPanedwindow", background=theme["sash"], sashwidth=6)
        style.configure("TSeparator", background=theme["separator"])
        
        # Button styles with better visibility
        style.configure("TButton", background=theme["button_bg"], foreground=theme["button_fg"], 
                       font=("Segoe UI", 9, "bold"), borderwidth=1, padding=(12, 6))
        style.map("TButton", background=[('active', theme["button_active_bg"])])
        
        style.configure("Danger.TButton", background=theme["button_danger_bg"], foreground="white")
        style.map("Danger.TButton", background=[('active', theme["button_danger_active"])])
        
        style.configure("Success.TButton", background=theme["button_success_bg"], foreground="white")
        style.map("Success.TButton", background=[('active', theme["button_success_active"])])

        # TreeView styles with better readability
        style.configure("Treeview", background=theme["tree_bg"], foreground=theme["text"], 
                       fieldbackground=theme["tree_field_bg"], rowheight=30, 
                       font=("Consolas", 9))
        style.map("Treeview", background=[('selected', theme["tree_selected_bg"])],
                 foreground=[('selected', theme["text"])])
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), 
                       background=theme["tree_heading_bg"], foreground=theme["text"])

        # Text widgets with improved contrast and selectability
        text_widgets = []
        if hasattr(self, 'details_text'):
            text_widgets.append(self.details_text)
        if hasattr(self, 'logs_text'):
            text_widgets.append(self.logs_text)
        if hasattr(self, 'blocked_text'):
            text_widgets.append(self.blocked_text)
            
        for widget in text_widgets:
            widget.configure(
                bg=theme["text_bg"], 
                fg=theme["text"], 
                insertbackground=theme["insert_bg"],
                selectbackground=theme["select_bg"],
                selectforeground=theme["select_fg"],
                font=("Consolas", 10),
                relief="solid",
                borderwidth=1
            )

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._apply_theme()

    def _create_widgets(self):
        """Create all GUI widgets with enhanced layout"""
        main_frame = ttk.Frame(self.root, padding="15", style="Main.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with better spacing
        header_frame = ttk.Frame(main_frame, style="Main.TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = ttk.Label(header_frame, text="🛡️ Enhanced IPS | Intrusion Prevention System", 
                               style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(header_frame, text="Status: Idle", style="Status.TLabel")
        self.status_label.pack(side=tk.RIGHT, anchor='s')

        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=(0, 10))

        # Control Panel with better organization
        control_frame = ttk.Frame(main_frame, style="Main.TFrame")
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Left controls
        left_controls = ttk.Frame(control_frame, style="Main.TFrame")
        left_controls.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.start_button = ttk.Button(left_controls, text="🚀 Start Protection", 
                                      command=self.start_protection, style="Success.TButton")
        self.start_button.pack(side=tk.LEFT, padx=(0, 8))
        
        self.stop_button = ttk.Button(left_controls, text="⏹️ Stop Protection", 
                                     command=self.stop_protection, style="Danger.TButton", 
                                     state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 8))
        
        self.blocking_var = tk.BooleanVar(value=True)
        self.blocking_check = ttk.Checkbutton(left_controls, text="Enable IP Blocking", 
                                            variable=self.blocking_var, command=self.toggle_blocking)
        self.blocking_check.pack(side=tk.LEFT, padx=20)
        
        # Right controls
        right_controls = ttk.Frame(control_frame, style="Main.TFrame")
        right_controls.pack(side=tk.RIGHT)
        
        self.clear_button = ttk.Button(right_controls, text="🗑️ Clear Logs", 
                                      command=self.clear_logs)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 8))
        
        self.unblock_button = ttk.Button(right_controls, text="🔓 Unblock All", 
                                        command=self.unblock_all_ips)
        self.unblock_button.pack(side=tk.LEFT, padx=(0, 8))
        
        self.theme_button = ttk.Button(right_controls, text="🎨 Toggle Theme", 
                                      command=self.toggle_theme)
        self.theme_button.pack(side=tk.LEFT)

        # Enhanced Stats Panel
        stats_frame = ttk.Frame(main_frame, padding="15")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.packets_label = ttk.Label(stats_frame, text="Packets Analyzed: 0", style="Stats.TLabel")
        self.packets_label.pack(side=tk.LEFT, padx=(0, 30))
        
        self.threats_label = ttk.Label(stats_frame, text="Threats Detected: 0", style="Stats.TLabel")
        self.threats_label.pack(side=tk.LEFT, padx=(0, 30))
        
        self.blocked_label = ttk.Label(stats_frame, text="IPs Blocked: 0", style="Stats.TLabel")
        self.blocked_label.pack(side=tk.LEFT, padx=(0, 30))
        
        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=10)

        # Main content area with enhanced layout
        self.main_paned = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True)

        # Top section: Real-time threats and blocked IPs side by side
        top_paned = ttk.PanedWindow(self.main_paned, orient=tk.HORIZONTAL)
        self.main_paned.add(top_paned, weight=3)

        # Real-time Threat Detection Table (Left)
        threats_frame = ttk.Frame(top_paned, padding="10")
        ttk.Label(threats_frame, text="🚨 Real-time Threat Detection", 
                 style="Section.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        threat_cols = ("Time", "Source IP", "Threat Type", "Severity", "Action", "Details")
        self.threats_tree = ttk.Treeview(threats_frame, columns=threat_cols, show='headings', height=10)
        
        # Configure columns with better widths
        col_widths = {"Time": 80, "Source IP": 130, "Threat Type": 140, 
                     "Severity": 80, "Action": 90, "Details": 350}
        for col in threat_cols:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=col_widths.get(col, 100), 
                                   anchor='center' if col not in ["Details"] else 'w')
        
        # Create frame for tree and scrollbars
        tree_container = ttk.Frame(threats_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars for threats tree
        threat_scroll_y = ttk.Scrollbar(tree_container, orient="vertical", command=self.threats_tree.yview)
        threat_scroll_x = ttk.Scrollbar(tree_container, orient="horizontal", command=self.threats_tree.xview)
        self.threats_tree.configure(yscrollcommand=threat_scroll_y.set, xscrollcommand=threat_scroll_x.set)
        
        # Pack the tree and scrollbars
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        threat_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        threat_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        top_paned.add(threats_frame, weight=2)

        # Blocked Threats & IPs Section (Right)
        blocked_frame = ttk.Frame(top_paned, padding="10")
        ttk.Label(blocked_frame, text="🔴 Blocked Threats & Source IPs", 
                 style="Section.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        # Create text widget for blocked threats with better formatting
        self.blocked_text = scrolledtext.ScrolledText(
            blocked_frame, 
            wrap=tk.WORD,
            font=("Consolas", 10),
            relief="solid",
            borderwidth=1,
            state=tk.DISABLED
        )
        self.blocked_text.pack(fill=tk.BOTH, expand=True)
        
        top_paned.add(blocked_frame, weight=1)

        # Bottom section: Packet details and system logs
        bottom_paned = ttk.PanedWindow(self.main_paned, orient=tk.HORIZONTAL)
        self.main_paned.add(bottom_paned, weight=2)

        # Packet Analysis Details (Left)
        details_frame = ttk.Frame(bottom_paned, padding="10")
        ttk.Label(details_frame, text="📋 Packet Analysis Details", 
                 style="Section.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame, 
            wrap=tk.WORD,
            font=("Consolas", 10),
            relief="solid",
            borderwidth=1,
            state=tk.DISABLED
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)
        bottom_paned.add(details_frame, weight=1)

        # System Logs (Right)
        logs_frame = ttk.Frame(bottom_paned, padding="10")
        ttk.Label(logs_frame, text="📝 System Logs", 
                 style="Section.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        self.logs_text = scrolledtext.ScrolledText(
            logs_frame, 
            wrap=tk.WORD,
            font=("Consolas", 10),
            relief="solid",
            borderwidth=1,
            state=tk.DISABLED
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        bottom_paned.add(logs_frame, weight=1)

        # Event bindings
        self.threats_tree.bind('<<TreeviewSelect>>', self.show_threat_details)
        
        self._log("Enhanced IPS System initialized. Ready to protect your network.")
        self._update_blocked_display()

    def _log(self, message):
        """Add message to system logs with better formatting"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.insert(tk.END, log_entry)
        self.logs_text.see(tk.END)
        self.logs_text.config(state=tk.DISABLED)

    def _update_blocked_display(self):
        """Update the blocked threats display"""
        self.blocked_text.config(state=tk.NORMAL)
        self.blocked_text.delete(1.0, tk.END)
        
        if not self.blocked_threats:
            self.blocked_text.insert(tk.END, "No threats blocked yet.\n\nBlocked IPs will appear here when threats are detected and blocked.")
        else:
            self.blocked_text.insert(tk.END, f"{'='*60}\n")
            self.blocked_text.insert(tk.END, f"BLOCKED THREATS SUMMARY ({len(self.blocked_threats)} total)\n")
            self.blocked_text.insert(tk.END, f"{'='*60}\n\n")
            
            # Group by IP
            ip_threats = defaultdict(list)
            for threat in self.blocked_threats:
                ip_threats[threat['ip']].append(threat)
            
            for ip, threats in ip_threats.items():
                self.blocked_text.insert(tk.END, f"🚫 BLOCKED IP: {ip}\n")
                self.blocked_text.insert(tk.END, f"   Total Threats: {len(threats)}\n")
                self.blocked_text.insert(tk.END, f"   First Blocked: {threats[0]['timestamp']}\n")
                self.blocked_text.insert(tk.END, f"   Last Activity: {threats[-1]['timestamp']}\n")
                
                # Show threat breakdown
                threat_types = defaultdict(int)
                for threat in threats:
                    threat_types[threat['type']] += 1
                
                self.blocked_text.insert(tk.END, "   Threat Breakdown:\n")
                for threat_type, count in threat_types.items():
                    self.blocked_text.insert(tk.END, f"     • {threat_type}: {count} incidents\n")
                
                self.blocked_text.insert(tk.END, "\n" + "-"*50 + "\n\n")
        
        self.blocked_text.config(state=tk.DISABLED)

    def block_ip(self, ip, reason="Malicious activity detected"):
        """Block an IP address using system firewall and track the threat"""
        if ip in blocked_ips:
            return False
            
        if not self.blocking_enabled:
            self._log(f"Blocking disabled - Would block {ip}: {reason}")
            return False
            
        try:
            system = platform.system()
            if system == "Linux":
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], 
                              check=True, capture_output=True)
            elif system == "Windows":
                rule_name = f"IPS_Block_{ip.replace('.', '_')}"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
                ], check=True, capture_output=True)
            
            blocked_ips.add(ip)
            self.blocked_count += 1
            
            # Add to blocked threats list
            threat_info = {
                'ip': ip,
                'reason': reason,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'type': reason.split(':')[0] if ':' in reason else reason
            }
            self.blocked_threats.append(threat_info)
            
            self._log(f"🚫 BLOCKED IP: {ip} - {reason}")
            self._update_stats()
            self._update_blocked_display()
            return True
            
        except subprocess.CalledProcessError as e:
            self._log(f"❌ Failed to block {ip}: {e}")
            return False
        except Exception as e:
            self._log(f"❌ Error blocking {ip}: {e}")
            return False

    def unblock_all_ips(self):
        """Remove all blocked IPs and clear blocked threats"""
        try:
            system = platform.system()
            unblocked = 0
            
            for ip in blocked_ips.copy():
                try:
                    if system == "Linux":
                        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], 
                                      check=True, capture_output=True)
                    elif system == "Windows":
                        rule_name = f"IPS_Block_{ip.replace('.', '_')}"
                        subprocess.run([
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={rule_name}"
                        ], check=True, capture_output=True)
                    
                    blocked_ips.remove(ip)
                    unblocked += 1
                except:
                    pass
            
            self.blocked_count = len(blocked_ips)
            self.blocked_threats.clear()  # Clear blocked threats list
            self._update_stats()
            self._update_blocked_display()
            self._log(f"✅ Unblocked {unblocked} IP addresses and cleared threat history")
            
        except Exception as e:
            self._log(f"❌ Error unblocking IPs: {e}")

    def toggle_blocking(self):
        """Toggle IP blocking on/off"""
        self.blocking_enabled = self.blocking_var.get()
        status = "enabled" if self.blocking_enabled else "disabled"
        self._log(f"IP blocking {status}")

    def clear_logs(self):
        """Clear all logs and reset counters (but keep blocked IPs)"""
        self.threats_tree.delete(*self.threats_tree.get_children())
        self.packet_data_storage.clear()
        
        # Clear text widgets
        for widget in [self.details_text, self.logs_text]:
            widget.config(state=tk.NORMAL)
            widget.delete(1.0, tk.END)
            widget.config(state=tk.DISABLED)
        
        # Reset counters but keep blocked IPs and their history
        self.packet_count = 0
        self.threat_count = 0
        self._update_stats()
        self._log("Logs cleared (blocked IPs preserved)")

    def start_protection(self):
        """Start packet sniffing and threat detection"""
        if self.sniffing:
            return
            
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: 🛡️ Active Protection")
        
        # Clear tracking dictionaries
        icmp_counts.clear()
        syn_counts.clear()
        scan_ports.clear()
        http_violations.clear()
        
        self._log("🚀 Enhanced IPS Protection started - Monitoring network traffic...")
        
        # Start packet sniffing in a separate thread
        self.sniffer_thread = threading.Thread(target=self.packet_sniffer, daemon=True)
        self.sniffer_thread.start()

    def stop_protection(self):
        """Stop packet sniffing"""
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: ⏹️ Stopped")
        self._log("⏹️ IPS Protection stopped")

    def packet_sniffer(self):
        """Main packet sniffing loop"""
        try:
            scapy.sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing, store=False)
        except Exception as e:
            self._log(f"❌ Sniffing error: {e}")

    def process_packet(self, packet):
        """Process each captured packet"""
        self.packet_queue.put(packet)

    def analyze_and_block(self, packet):
        """Analyze packet for threats and block if necessary"""
        if not packet.haslayer(scapy.IP):
            return None
            
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        now = time.time()
        
        # Skip analysis for already blocked IPs
        if src_ip in blocked_ips:
            return None

        # ICMP Ping Flood Detection
        if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 8:
            icmp_counts[src_ip] = [t for t in icmp_counts[src_ip] if now - t < TIME_WINDOW_ICMP]
            icmp_counts[src_ip].append(now)
            
            if len(icmp_counts[src_ip]) > ICMP_LIMIT:
                if self.block_ip(src_ip, f"ICMP Flood: {len(icmp_counts[src_ip])} pings in {TIME_WINDOW_ICMP}s"):
                    return {
                        "type": "ICMP Flood Attack",
                        "severity": "HIGH",
                        "action": "BLOCKED",
                        "details": f"Detected {len(icmp_counts[src_ip])} ICMP pings in {TIME_WINDOW_ICMP} seconds"
                    }

        # TCP SYN Flood Detection
        if packet.haslayer(scapy.TCP):
            flags = packet[scapy.TCP].flags
            dport = packet[scapy.TCP].dport
            
            # SYN Flood (SYN without ACK)
            if flags & 0x02 and not (flags & 0x10):  # SYN flag set, ACK not set
                syn_counts[src_ip] = [t for t in syn_counts[src_ip] if now - t < TIME_WINDOW_SYN]
                syn_counts[src_ip].append(now)
                
                if len(syn_counts[src_ip]) > SYN_LIMIT:
                    if self.block_ip(src_ip, f"SYN Flood: {len(syn_counts[src_ip])} SYNs in {TIME_WINDOW_SYN}s"):
                        return {
                            "type": "SYN Flood Attack",
                            "severity": "HIGH", 
                            "action": "BLOCKED",
                            "details": f"Detected {len(syn_counts[src_ip])} SYN packets in {TIME_WINDOW_SYN} seconds"
                        }
            
            # Port Scan Detection (SYN, NULL, FIN)
            if flags in [0x02, 0x00, 0x01]:  # SYN, NULL, FIN scans
                scan_ports[src_ip][dport] = [t for t in scan_ports[src_ip][dport] if now - t < TIME_WINDOW_SCAN]
                scan_ports[src_ip][dport].append(now)
                
                # Count unique ports accessed recently
                recent_ports = sum(1 for port_times in scan_ports[src_ip].values() if port_times)
                
                if recent_ports > PORTSCAN_WINDOW:
                    scan_type = {0x02: "SYN", 0x00: "NULL", 0x01: "FIN"}.get(flags, "Unknown")
                    if self.block_ip(src_ip, f"{scan_type} Port Scan: {recent_ports} ports in {TIME_WINDOW_SCAN}s"):
                        return {
                            "type": f"{scan_type} Port Scan",
                            "severity": "HIGH",
                            "action": "BLOCKED", 
                            "details": f"Scanned {recent_ports} ports in {TIME_WINDOW_SCAN} seconds"
                        }

        # HTTP Payload Analysis for SQLi/XSS
        if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in [80, 8080, 443]:
            try:
                payload = bytes(packet[scapy.Raw].load)
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Check for SQL injection patterns
                sql_detected = any(pattern in payload for pattern in SQL_INJECTION_PATTERNS)
                xss_detected = any(pattern in payload for pattern in XSS_PATTERNS)
                regex_match = HTTP_SUSPICIOUS_REGEX.search(payload_str)
                
                if sql_detected or xss_detected or regex_match:
                    http_violations[src_ip] += 1
                    
                    if http_violations[src_ip] > HTTP_VIOLATION_LIMIT:
                        attack_type = "SQL Injection" if sql_detected else ("XSS Attack" if xss_detected else "Web Attack")
                        if self.block_ip(src_ip, f"{attack_type}: {http_violations[src_ip]} violations"):
                            return {
                                "type": attack_type,
                                "severity": "CRITICAL",
                                "action": "BLOCKED",
                                "details": f"Malicious HTTP payload detected ({http_violations[src_ip]} violations)"
                            }
                    else:
                        # Log warning but don't block yet
                        return {
                            "type": "Suspicious HTTP",
                            "severity": "MEDIUM",
                            "action": "WARNED",
                            "details": f"Suspicious HTTP payload ({http_violations[src_ip]}/{HTTP_VIOLATION_LIMIT + 1})"
                        }
                        
            except Exception as e:
                pass  # Ignore payload decode errors
        
        return None

    def update_gui(self):
        """Update GUI with new packets and threats"""
        try:
            while not self.packet_queue.empty():
                packet = self.packet_queue.get_nowait()
                self.packet_count += 1
                
                # Analyze packet for threats
                threat_info = self.analyze_and_block(packet)
                
                if threat_info:
                    self.threat_count += 1
                    timestamp = time.strftime("%H:%M:%S")
                    src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
                    
                    # Insert into threats tree with better formatting
                    item = self.threats_tree.insert("", "end", values=(
                        timestamp,
                        src_ip,
                        threat_info["type"],
                        threat_info["severity"],
                        threat_info["action"],
                        threat_info["details"]
                    ))
                    
                    # Color code by severity (add tags for styling)
                    severity = threat_info["severity"]
                    if severity == "CRITICAL":
                        self.threats_tree.set(item, "Severity", "🔴 CRITICAL")
                    elif severity == "HIGH":
                        self.threats_tree.set(item, "Severity", "🟠 HIGH")
                    elif severity == "MEDIUM":
                        self.threats_tree.set(item, "Severity", "🟡 MEDIUM")
                    else:
                        self.threats_tree.set(item, "Severity", "🟢 LOW")
                    
                    # Store packet data separately using item ID
                    self.packet_data_storage[item] = packet.show(dump=True)
                    
                    # Auto-scroll to latest threat
                    self.threats_tree.yview_moveto(1)
                
                # Update stats every 50 packets to reduce overhead
                if self.packet_count % 50 == 0:
                    self._update_stats()
                    
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.update_gui)

    def _update_stats(self):
        """Update the statistics display with better formatting"""
        self.packets_label.config(text=f"Packets Analyzed: {self.packet_count:,}")
        self.threats_label.config(text=f"Threats Detected: {self.threat_count:,}")
        self.blocked_label.config(text=f"IPs Blocked: {self.blocked_count}")

    def show_threat_details(self, event):
        """Show detailed packet information when threat is selected"""
        selected_item = self.threats_tree.selection()
        if not selected_item:
            return
            
        item = selected_item[0]
        packet_data = self.packet_data_storage.get(item, "No packet data available")
        
        # Get threat details from the tree
        values = self.threats_tree.item(item, 'values')
        if len(values) >= 6:
            timestamp, src_ip, threat_type, severity, action, details = values
            
            # Format the details display
            formatted_details = f"""
THREAT ANALYSIS REPORT
{'='*60}

Time: {timestamp}
Source IP: {src_ip}
Threat Type: {threat_type}
Severity Level: {severity}
Action Taken: {action}
Details: {details}

{'='*60}
PACKET DETAILS:
{'='*60}

{packet_data}
"""
        else:
            formatted_details = packet_data
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, formatted_details)
        self.details_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = IPS(root)
    root.mainloop()