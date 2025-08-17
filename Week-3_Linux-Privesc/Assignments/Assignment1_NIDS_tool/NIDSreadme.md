
***

#  NIDS Threat Monitor

A simple, GUI-based **Network Intrusion Detection System (NIDS)** built with **Python**, **Tkinter**, and **Scapy**.  
This tool captures live network traffic, analyzes it for common threats in real-time, and presents the findings in a **clean, user-friendly interface** with **dual theme support**.

***

##  Overview

**NIDS Threat Monitor** provides an effective way to monitor your **local network traffic in real-time**.  
It is designed as both an:

-  **Educational resource** for those learning about cybersecurity  
-  **Lightweight monitoring tool** for small home or lab environments  

The application helps identify **suspicious activities** that could indicate attacks or compromised hosts on your network.

***

## ✨ Features

-  **Live Packet Sniffing** – Captures and displays network packets in real-time using **Scapy**  
-  **Modern Graphical User Interface (GUI)** – Clean, intuitive interface built with Tkinter  
-  **Dual Theme Support** – Easily switch between a **Dark Mode** and **Light Mode**  
-  **Real-time Threat Detection** – Flags suspicious traffic as it is captured  
-  **Multi-faceted Threat Analysis**:  
  -  **Blacklisted IP Detection** – Flags traffic from known malicious IPs  
  -  **Suspicious Payload Scanning** – Detects SQL Injection, XSS, and attack patterns  
  -  **Port Scan Detection** – Tracks rapid multi-port probes  
-  **Detailed Packet Analysis** – Click packets to view headers and payloads  
-  **Threat Intelligence & Mitigation** – Provides threat descriptions + recommended actions  

***

## 🔬 How It Works

- **Packet Capture** – Runs via **Scapy** inside a **background thread** (keeps GUI responsive)  
- **Analysis Engine** – Inspects each captured packet:  
  - Checks against **blacklisted IPs**  
  - Scans payload for keywords like `SELECT`, ``  
  - Detects **port scanning** patterns  
- **Threat Scoring & Display** – Packets with high threat scores are flagged and shown in the **Threat Detections Panel**  

***

##  Getting Started

###  Prerequisites

- Python **3.x**  
- `pip` (Python package manager)  

###  Installation

**Clone this repository:**

```bash
git clone https://github.com/yourusername/nids-threat-monitor.git
cd nids-threat-monitor
```

**Install the required libraries:**

```bash
pip install scapy
```

>  Tkinter comes pre-installed with most Python distributions.

***

## ▶ Running the Tool

 **Important:** Packet sniffing requires **root/administrator privileges**.  

### On Linux/macOS:
```bash
sudo python3 NIDStool.py
```

### On Windows:
Open **Command Prompt** or **PowerShell** as Administrator and run:
```bash
python NIDStool.py
```

***

##  Using the Application

1. Click **Start Sniffing** → Begin capturing network packets  
2. View **Live Packet Stream** → See all network traffic in real-time  
3. Check **Threat Detections** → Automatically flagged suspicious packets  
4. Select a packet → Inspect its headers and payload  
5. Review **Threat Intel & Mitigation** → Learn about detected threats + suggested fixes  
6. Click **Stop Sniffing** → End the capture  

***

##  Credits

This tool was created by:  
- **Adwitya Deep Verma**  
- **Harini Porumamilla**  

 Developed during their internship with the **Digisuraksha Parhari Foundation**.  

***