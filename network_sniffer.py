# CodeAlpha - Basic Network Sniffer
# Author: Muzammil
# Internship: CodeAlpha Cyber Security Internship
# Task 1: Basic Network Sniffer

from scapy.all import sniff, IP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[+] Source: {ip_layer.src} --> Destination: {ip_layer.dst}")
        print(f"    Protocol: {ip_layer.proto}")
        print("-" * 60)

print("=== CodeAlpha - Basic Network Sniffer ===")
print("Capturing packets... Press Ctrl+C to stop.\n")

# Capture 10 packets for testing
sniff(prn=packet_callback, count=10)
