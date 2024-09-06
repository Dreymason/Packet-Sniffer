from scapy.all import sniff, hexdump
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.utils import wrpcap

# List to store captured packets
packets = []

def packet_handler(packet):
    packets.append(packet)  # Add packet to the list for saving later

    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"\n[IP] {ip_layer.src} -> {ip_layer.dst}")
        print(f"    Version: {ip_layer.version}")
        print(f"    Header Length: {ip_layer.ihl * 4} bytes")
        print(f"    TTL: {ip_layer.ttl}")
        print(f"    Protocol: {ip_layer.proto}")

    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"[TCP] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        print(f"    Sequence Number: {tcp_layer.seq}")
        print(f"    Acknowledgment Number: {tcp_layer.ack}")
        print(f"    Header Length: {tcp_layer.dataofs * 4} bytes")
        print(f"    Flags: {tcp_layer.flags}")
        if tcp_layer.payload:
            print("    Payload:")
            hexdump(tcp_layer.payload)

    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        print(f"[UDP] {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
        if udp_layer.payload:
            print("    Payload:")
            hexdump(udp_layer.payload)

    elif packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        print(f"[ARP] {arp_layer.psrc} -> {arp_layer.pdst}")
        print(f"    HW src: {arp_layer.hwsrc}")
        print(f"    HW dst: {arp_layer.hwdst}")
        print(f"    Opcode: {arp_layer.op}")
        if arp_layer.payload:
            print("    Payload:")
            hexdump(arp_layer.payload)

# Start sniffing
print("Starting packet capture...")
sniff(prn=packet_handler, store=0)

# Save captured packets to a pcap file
print("Saving captured packets to 'captured_packets.pcap'...")
wrpcap('captured_packets.pcap', packets)
print("Capture complete.")
