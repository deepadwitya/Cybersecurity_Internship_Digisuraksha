import tkinter as tk
from tkinter import ttk, scrolledtext
import scapy.all as scapy
import threading
import queue
import time
from collections import defaultdict

# --- Intrusion Detection Logic ---
# this tool captures packets and then uses keywords to scope out the potential threats, for betterments more keywords can be added and its scope can be enhance
SUSPICIOUS_KEYWORDS = [
    b'SELECT', b'UNION', b'INSERT', b'DROP', b'--', b'<script>', b'alert(', b'onerror='
]
BLACKLISTED_IPS = {'192.168.1.101', '10.0.0.5'}

# --- Port Scanning Detection ---
PORT_SCAN_TRACKER = defaultdict(set)
PORT_SCAN_TIMESTAMPS = {}
PORT_SCAN_PORT_COUNT = 15
PORT_SCAN_TIME_WINDOW = 60


class NIDS:
    """
    This class encapsulates the entire Network Intrusion Detection System,
    including the GUI and the packet sniffing/analysis logic.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS Threat Monitor")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 700)

        self.current_theme = "dark"
        self._define_themes()

        self.sniffing = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()

        self._create_widgets()
        self._apply_theme()

        self.root.after(100, self.update_gui)

    def _define_themes(self):
        """Defines the color palettes for light and dark themes."""
        self.themes = {
            "dark": {
                "bg": "#1e1e1e", "text": "#d4d4d4", "frame_bg": "#252526",
                "button_bg": "#0e639c", "button_active_bg": "#1177bb", "button_fg": "#ffffff",
                "tree_bg": "#252526", "tree_field_bg": "#252526", "tree_heading_bg": "#333333",
                "tree_selected_bg": "#37373d", "details_bg": "#1e1e1e", "separator": "#444444",
                "sash": "#444444"
            },
            "light": {
                "bg": "#f0f2f5", "text": "#2c3e50", "frame_bg": "#ffffff",
                "button_bg": "#3498db", "button_active_bg": "#2980b9", "button_fg": "#ffffff",
                "tree_bg": "#ffffff", "tree_field_bg": "#ffffff", "tree_heading_bg": "#eaf1f8",
                "tree_selected_bg": "#aed6f1", "details_bg": "#ecf0f1", "separator": "#d0d0d0",
                "sash": "#bdc3c7"
            }
        }

    def _apply_theme(self):
        """Applies the currently selected theme to all GUI elements."""
        theme = self.themes[self.current_theme]
        self.root.configure(bg=theme["bg"])

        style = ttk.Style()
        style.theme_use('clam')

        style.configure("TFrame", background=theme["frame_bg"])
        style.configure("Main.TFrame", background=theme["bg"])
        style.configure("TLabel", background=theme["frame_bg"], foreground=theme["text"], font=("Segoe UI", 11))
        style.configure("Title.TLabel", background=theme["bg"], foreground=theme["text"], font=("Segoe UI Semibold", 16))
        style.configure("Status.TLabel", background=theme["bg"], foreground=theme["text"], font=("Segoe UI", 10, "italic"))
        style.configure("Intel.TLabel", background=theme["frame_bg"], foreground=theme["text"], font=("Segoe UI", 10))
        style.configure("Intel.Header.TLabel", background=theme["frame_bg"], foreground=theme["text"], font=("Segoe UI Semibold", 11))
        style.configure("TPanedwindow", background=theme["sash"], sashwidth=8) # Set sash width in the style
        style.configure("TSeparator", background=theme["separator"])
        
        style.configure("TButton", background=theme["button_bg"], foreground=theme["button_fg"], font=("Segoe UI", 10, "bold"), borderwidth=0, padding=(10, 6), relief='flat')
        style.map("TButton", background=[('active', theme["button_active_bg"])])

        style.configure("Treeview", background=theme["tree_bg"], foreground=theme["text"], fieldbackground=theme["tree_field_bg"], rowheight=28, font=("Segoe UI", 10))
        style.map("Treeview", background=[('selected', theme["tree_selected_bg"])])
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background=theme["tree_heading_bg"], foreground=theme["text"], relief='flat')
        style.map("Treeview.Heading", relief=[('active','flat')])

        self.details_text.configure(bg=theme["details_bg"], fg=theme["text"], insertbackground=theme["text"])
        
    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self._apply_theme()

    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10 10 10 0", style="Main.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        header_frame = ttk.Frame(main_frame, style="Main.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=(0,5))
        title_label = ttk.Label(header_frame, text="NIDS | Threat Monitor", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        self.status_label = ttk.Label(header_frame, text="Status: Idle", style="Status.TLabel")
        self.status_label.pack(side=tk.RIGHT, anchor='s')

        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, padx=10, pady=5)

        control_frame = ttk.Frame(main_frame, style="Main.TFrame")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        self.start_button = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=(0,5))
        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.theme_button = ttk.Button(control_frame, text="Toggle Theme", command=self.toggle_theme)
        self.theme_button.pack(side=tk.RIGHT)

        # FIXED: Removed sashwidth argument from widget creation
        self.paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

        all_packets_frame = ttk.Frame(self.paned_window, padding="10")
        ttk.Label(all_packets_frame, text="Live Packet Stream", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0,10))
        cols = ("No.", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info")
        self.all_packets_tree = ttk.Treeview(all_packets_frame, columns=cols, show='headings')
        for col in cols: self.all_packets_tree.heading(col, text=col); self.all_packets_tree.column(col, width=100, anchor='center')
        self.all_packets_tree.column("Info", width=400, anchor='w')
        self.all_packets_tree.pack(fill=tk.BOTH, expand=True)
        self.paned_window.add(all_packets_frame, weight=3)

        malicious_packets_frame = ttk.Frame(self.paned_window, padding="10")
        ttk.Label(malicious_packets_frame, text="Threat Detections", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0,10))
        mal_cols = ("No.", "Time", "Source IP", "Destination IP", "Protocol", "Threat Score", "Reason")
        self.malicious_packets_tree = ttk.Treeview(malicious_packets_frame, columns=mal_cols, show='headings')
        for col in mal_cols: self.malicious_packets_tree.heading(col, text=col); self.malicious_packets_tree.column(col, width=120, anchor='center')
        self.malicious_packets_tree.column("Reason", width=400, anchor='w')
        self.malicious_packets_tree.pack(fill=tk.BOTH, expand=True)
        self.paned_window.add(malicious_packets_frame, weight=2)

        # --- Bottom Paned Window for Details and Threat Intel ---
        # FIXED: Removed sashwidth argument from widget creation
        bottom_pane = ttk.PanedWindow(self.paned_window, orient=tk.HORIZONTAL)
        self.paned_window.add(bottom_pane, weight=2)

        details_frame = ttk.Frame(bottom_pane, padding="10")
        ttk.Label(details_frame, text="Packet Analysis", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0,10))
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, font=("Consolas", 10), relief=tk.FLAT, borderwidth=0)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        bottom_pane.add(details_frame, weight=1)

        # --- NEW: Threat Intel Frame ---
        intel_frame = ttk.Frame(bottom_pane, padding="10")
        ttk.Label(intel_frame, text="Threat Intel & Mitigation", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, pady=(0,10))
        
        self.threat_type_label = ttk.Label(intel_frame, text="Threat Type: N/A", style="Intel.Header.TLabel")
        self.threat_type_label.pack(anchor='w', pady=2)
        
        self.threat_details_label = ttk.Label(intel_frame, text="Details: N/A", style="Intel.TLabel", wraplength=400)
        self.threat_details_label.pack(anchor='w', pady=2)
        
        ttk.Separator(intel_frame, orient='horizontal').pack(fill=tk.X, pady=10)

        ttk.Label(intel_frame, text="Recommended Actions:", style="Intel.Header.TLabel").pack(anchor='w', pady=2)
        self.mitigation_label = ttk.Label(intel_frame, text="No threat selected.", style="Intel.TLabel", wraplength=400)
        self.mitigation_label.pack(anchor='w', pady=2)
        
        bottom_pane.add(intel_frame, weight=1)

        self.all_packets_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        self.malicious_packets_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        self.packets_data = {}

    def start_sniffing(self):
        if self.sniffing: return
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED); self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Sniffing...")
        self.all_packets_tree.delete(*self.all_packets_tree.get_children())
        self.malicious_packets_tree.delete(*self.malicious_packets_tree.get_children())
        self.packets_data.clear(); PORT_SCAN_TRACKER.clear(); PORT_SCAN_TIMESTAMPS.clear()
        self.sniffer_thread = threading.Thread(target=self.packet_sniffer, daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL); self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped")

    def packet_sniffer(self):
        scapy.sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing, store=False)

    def process_packet(self, packet):
        self.packet_queue.put(packet)

    def analyze_packet(self, packet):
        score, threats = 0, []
        if not packet.haslayer(scapy.IP): return 0, {"summary": "Non-IP Packet"}
        src_ip, dst_ip = packet[scapy.IP].src, packet[scapy.IP].dst
        
        if src_ip in BLACKLISTED_IPS:
            score += 90
            threats.append({
                "type": "Blacklisted IP",
                "summary": f"Blacklisted IP ({src_ip})",
                "details": f"The source IP address {src_ip} is on a known list of malicious actors.",
                "mitigation": "1. Block this IP address at your firewall.\n2. Investigate any successful connections from this IP.\n3. Ensure your threat intelligence feeds are up-to-date."
            })
        
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in payload:
                    score += 75
                    threats.append({
                        "type": "Suspicious Keyword",
                        "summary": "Suspicious keyword found",
                        "details": f"Detected the keyword '{keyword.decode(errors='ignore')}' in the packet payload. This could be an indicator of an SQL injection, XSS, or other web application attack.",
                        "mitigation": "1. If this is web traffic, inspect your web application firewall (WAF) logs.\n2. Analyze the full payload to understand the context.\n3. Consider strengthening input validation on your servers."
                    })
                    break
        
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
            ip_pair = (src_ip, dst_ip)
            current_time = time.time()
            if ip_pair not in PORT_SCAN_TIMESTAMPS or current_time - PORT_SCAN_TIMESTAMPS[ip_pair] > PORT_SCAN_TIME_WINDOW:
                PORT_SCAN_TIMESTAMPS[ip_pair] = current_time
                PORT_SCAN_TRACKER[ip_pair].clear()
            PORT_SCAN_TRACKER[ip_pair].add(packet[scapy.TCP].dport)
            if len(PORT_SCAN_TRACKER[ip_pair]) > PORT_SCAN_PORT_COUNT:
                score += 85
                threats.append({
                    "type": "Port Scan",
                    "summary": "Port Scan detected",
                    "details": f"The IP address {src_ip} has rapidly connected to {len(PORT_SCAN_TRACKER[ip_pair])} unique ports on {dst_ip}, which is indicative of a port scan to find open services.",
                    "mitigation": "1. Monitor the source IP for further suspicious activity.\n2. Consider a temporary firewall block if the activity continues.\n3. Ensure no unintended ports are open on the destination machine."
                })
                PORT_SCAN_TRACKER[ip_pair].clear()
        
        summary = ", ".join([t['summary'] for t in threats]) or "OK"
        return min(100, score), {"summary": summary, "details": threats}

    def update_gui(self):
        try:
            while not self.packet_queue.empty():
                packet = self.packet_queue.get_nowait()
                malicious_score, threat_info = self.analyze_packet(packet)
                
                packet_id = len(self.packets_data) + 1
                self.packets_data[packet_id] = (packet, threat_info)
                
                timestamp = time.strftime("%H:%M:%S")
                info = packet.summary()
                if packet.haslayer(scapy.IP):
                    src_ip, dst_ip = packet[scapy.IP].src, packet[scapy.IP].dst
                    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                    protocol = proto_map.get(packet[scapy.IP].proto, "Other")
                else: src_ip, dst_ip = "N/A", "N/A"
                
                self.all_packets_tree.insert("", "end", iid=f"all_{packet_id}", values=(packet_id, timestamp, src_ip, dst_ip, protocol, len(packet), info))
                self.all_packets_tree.yview_moveto(1)
                
                if malicious_score > 40:
                    self.malicious_packets_tree.insert("", "end", iid=f"mal_{packet_id}", values=(packet_id, timestamp, src_ip, dst_ip, protocol, f"{malicious_score}%", threat_info["summary"]))
                    self.malicious_packets_tree.yview_moveto(1)
        except queue.Empty: pass
        finally: self.root.after(100, self.update_gui)

    def show_packet_details(self, event):
        selected_item = event.widget.selection()
        if not selected_item: return
        
        item_id_str = selected_item[0]
        packet_id = int(item_id_str.split('_')[1])
        packet, threat_info = self.packets_data.get(packet_id)

        if packet:
            details = packet.show(dump=True)
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
            self.details_text.config(state=tk.DISABLED)

        # Update Threat Intel pane ONLY if a malicious packet was clicked
        if item_id_str.startswith("mal_") and threat_info["details"]:
            first_threat = threat_info["details"][0]
            self.threat_type_label.config(text=f"Threat Type: {first_threat['type']}")
            self.threat_details_label.config(text=f"Details: {first_threat['details']}")
            self.mitigation_label.config(text=first_threat['mitigation'])
        else:
            self.threat_type_label.config(text="Threat Type: N/A")
            self.threat_details_label.config(text="Details: Select a packet from the 'Threat Detections' list to see details.")
            self.mitigation_label.config(text="No threat selected.")

if __name__ == "__main__":
    root = tk.Tk()
    app = NIDS(root)
    root.mainloop()


# Credits to this tool goes to Adwitya Deep Verma and Harini Porumamilla as thier work, working as interns under Digisuraksha Parhari Foundation.