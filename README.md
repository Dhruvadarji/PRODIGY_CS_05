## Task-05: Network Packet Analyzer

### Overview
This project demonstrates a simple packet sniffer built in Python using the `scapy` library.  
It captures network packets and displays source/destination IPs, protocols, and payload data.

⚠️ Ethical Note: Packet sniffers must only be used in controlled environments with explicit permission.

### Features
- Real-time packet capture
- Displays source and destination IP addresses
- Identifies protocols (TCP, UDP, etc.)
- Shows payload data (limited for readability)

### Usage
1. Install dependencies: `pip install scapy`
2. Run the script with administrator/root privileges:  
   `sudo python packet/packet_analyzer.py`
3. Stop with `Ctrl+C`.
