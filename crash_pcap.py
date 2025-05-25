#!/usr/bin/env python3
from scapy.all import *
import random

def generate_test_pcap():
    # Set source and destination
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.200" 
    sport = 12345
    dport = 80
    
    # List to collect packets
    packets = []
    
    # 1. Create a basic TCP handshake
    # SYN
    syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=100)
    # SYN-ACK
    synack = IP(dst=src_ip, src=dst_ip)/TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101)
    # ACK
    ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201)
    
    packets.extend([syn, synack, ack])
    
    # 2. Send a bunch of small data packets with gaps and overlaps to create complex reassembly
    seq = 101
    
    # First chunk of normal data with the trigger pattern
    data1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=201)/Raw(load="TRIGGER data part 1")
    seq += len(data1[Raw])
    packets.append(data1)
    
    # Send acknowledgment
    packets.append(IP(dst=src_ip, src=dst_ip)/TCP(sport=dport, dport=sport, flags="A", seq=201, ack=seq))
    
    # Create overlapping segments to force complex reassembly behavior
    for i in range(10):
        # Create some small segments with overlaps
        overlap_seq = seq - 4 if i % 2 == 0 else seq
        data = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                             seq=overlap_seq, ack=201)/Raw(load=f"Data{i+1} overlapping")
        packets.append(data)
        
        # Random delay ACK to create gaps in reassembly
        if i % 3 == 0:
            packets.append(IP(dst=src_ip, src=dst_ip)/TCP(sport=dport, dport=sport, flags="A", seq=201, ack=seq+10))
        seq += len(data[Raw])
    
    # 3. Send out-of-order segments with extreme gaps
    # Big sequence gap to potentially cause issues with reassembly
    gap_data = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                           seq=seq+5000, ack=201)/Raw(load="This packet has a huge gap")
    packets.append(gap_data)
    
    # 4. Send multiple FIN packets to complicate the session state
    fin1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=201)
    fin_ack = IP(dst=src_ip, src=dst_ip)/TCP(sport=dport, dport=sport, flags="A", seq=201, ack=seq+1)
    
    # Another FIN from different sequence point to confuse the state
    fin2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=seq+2000, ack=201)
    
    packets.extend([fin1, fin_ack, fin2])
    
    # 5. Send some RST packets to potentially cause state machine issues
    rst = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="R", seq=seq+1)
    packets.append(rst)
    
    # Write the PCAP file
    wrpcap("tcp_reassembler_crash_test.pcap", packets)
    print(f"Created test PCAP with {len(packets)} packets")

if __name__ == "__main__":
    generate_test_pcap()
