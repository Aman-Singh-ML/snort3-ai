#!/usr/bin/env python3
from scapy.all import *
import random

def generate_stress_test_pcap():
    packets = []
    
    # Create 100 TCP flows with complex patterns
    for flow_id in range(100):
        src_ip = f"10.1.{flow_id//255}.{flow_id%255}"
        dst_ip = f"10.2.{flow_id//255}.{flow_id%255}"
        sport = 10000 + flow_id
        dport = 80
        
        # Basic handshake
        syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
        synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
        ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
        
        packets.extend([syn, synack, ack])
        
        seq = 1001
        server_seq = 2001
        
        # Create complex data patterns
        for i in range(5):
            # Send 20 tiny segments with 1 byte each - forces reassembly
            for j in range(20):
                data = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                                 seq=seq+j, ack=server_seq)/Raw(load=b"X")
                packets.append(data)
            
            seq += 20
            
            # Add ACK from server - updates window
            ack_pkt = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="A", 
                                                seq=server_seq, ack=seq)
            packets.append(ack_pkt)
            
            # Add special segment with unique marker
            marker = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                                seq=seq, ack=server_seq)/Raw(load="TRIGGER_FLUSH")
            packets.append(marker)
            seq += 12
            
            # Overlapping segments
            for j in range(5):
                overlap_seq = seq - 3 + j
                overlap = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                                    seq=overlap_seq, ack=server_seq)/Raw(load=f"OVERLAP{j}")
                packets.append(overlap)
            
            seq += 10
        
        # Half-close the connection to trigger FIN processing
        fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=server_seq)
        packets.append(fin)
        
        fin_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="A", 
                                             seq=server_seq, ack=seq+1)
        packets.append(fin_ack)
    
    # Interleave packet ordering to create maximum processing complexity
    random.shuffle(packets)
    
    wrpcap("tcp_stress_test.pcap", packets)
    print(f"Created stress test PCAP with {len(packets)} packets")

if __name__ == "__main__":
    generate_stress_test_pcap()
