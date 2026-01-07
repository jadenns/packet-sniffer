#!/usr/bin/env python3
import datetime
import sys
from scapy.all import sniff, IP, TCP, UDP, wrpcap
from datetime import datetime
import subprocess

captured_packets = []


def packet_handler(packet):
    captured_packets.append(packet)

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            print(f"[TCP] {ip_src}:{port_src} -> {ip_dst}:{port_dst}\n")

        elif packet.haslayer(UDP):
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            print(f"[UDP] {ip_src}:{port_src} -> {ip_dst}:{port_dst}\n")


def main():
    if len(sys.argv) < 1:
        print("USAGE: python sniffer.py <interface>")
        sys.exit(0)

    print("Packet Sniffer Starting")
    print("-----------------------")
    sniff(iface=sys.argv[1], prn=packet_handler, store=0)

    if captured_packets:
        date_regex = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        filename = f"traffic_{sys.argv[1]}_{date_regex}.pcap"

        wrpcap(filename, captured_packets)
        print("Saved!")

    sys.exit(0)


if __name__ == "__main__":
    main()
