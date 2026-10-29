
import json
import os
import sys
import time
from datetime import datetime

from scapy.all import (
    sniff,
    wrpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ARP,
    ICMP,
    get_if_list
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PCAP_FILE = os.path.join(BASE_DIR, "packet_capture.pcap")
JSON_FILE = os.path.join(BASE_DIR, "packet_results.json")


def analyze_packet(packet):
    source_ip = "Unknown"
    destination_ip = "Unknown"
    source_port = None
    destination_port = None
    protocol = "Other"

    if ARP in packet:
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        protocol = "ARP"

    elif IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    if TCP in packet:
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)

    elif UDP in packet:
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)

    elif ICMP in packet:
        protocol = "ICMP"

    elif ARP in packet:
        protocol = "ARP"

    elif IPv6 in packet and packet[IPv6].nh == 58:
        protocol = "ICMPv6"

    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "length": len(packet),
        "summary": packet.summary()
    }


def main():
    duration = 10

    # A specific interface can optionally be supplied as an argument.
    interface = sys.argv[1] if len(sys.argv) > 1 else None

    results = {
        "status": "error",
        "message": "",
        "capture_start": None,
        "capture_end": None,
        "duration": duration,
        "packet_count": 0,
        "protocol_counts": {},
        "packets": [],
        "pcap_file": "packet_capture.pcap"
    }

    try:
        print("SecureAuth packet capture starting...")
        print("Duration:", duration, "seconds")
        print("Interface:", interface or "Default interface")

        start_time = time.time()
        results["capture_start"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        packets = sniff(
            iface=interface,
            timeout=duration,
            store=True
        )

        end_time = time.time()
        results["capture_end"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        results["duration"] = round(end_time - start_time, 2)

        # Save the real captured packets.
        wrpcap(PCAP_FILE, packets)

        analyzed = [analyze_packet(p) for p in packets]

        protocol_counts = {}
        for packet_info in analyzed:
            protocol = packet_info["protocol"]
            protocol_counts[protocol] = (
                protocol_counts.get(protocol, 0) + 1
            )

        results["status"] = "success"
        results["message"] = "Packet capture completed."
        results["packet_count"] = len(packets)
        results["protocol_counts"] = protocol_counts

        # Keep the report manageable for the web page.
        results["packets"] = analyzed[:500]

        print("Packets captured:", len(packets))
        print("Capture saved:", PCAP_FILE)

    except Exception as error:
        results["message"] = str(error)
        print("Capture error:", error)

    # Always write a report for PHP to read.
    with open(JSON_FILE, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print("Report saved:", JSON_FILE)


if __name__ == "__main__":
    main()
