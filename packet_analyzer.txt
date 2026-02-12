from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Identify protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = str(proto)

        print(f"[+] Source: {ip_src} --> Destination: {ip_dst} | Protocol: {protocol}")

        # Show payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload: {payload[:50]}")  # Limit to first 50 bytes

# Capture packets (Ctrl+C to stop)
sniff(prn=packet_callback, count=0)