#!/usr/bin/env python3
from scapy.all import *
import random

def create_complex_tcp_pcap():
    packets = []
    
    # Create fewer sessions (30) but with more complex behaviors
    for flow_id in range(30):
        src_ip = f"10.1.{flow_id//255}.{flow_id%255}"
        dst_ip = f"10.2.{flow_id//255}.{flow_id%255}"
        sport = 10000 + flow_id
        dport = 80
        
        # Handshake
        syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
        synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
        ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
        
        packets.extend([syn, synack, ack])
        
        seq = 1001
        server_seq = 2001
        
        # Send the special trigger pattern
        trigger = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                            seq=seq, ack=server_seq)/Raw(load="TRIGGER_FLUSH")
        packets.append(trigger)
        seq += len("TRIGGER_FLUSH")
        
        # Send ACK from server
        server_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="A", 
                                                seq=server_seq, ack=seq)
        packets.append(server_ack)
        
        # Generate complex segment patterns
        
        # Pattern 1: 20 single-byte segments
        for i in range(20):
            data = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                             seq=seq+i, ack=server_seq)/Raw(load=b"X")
            packets.append(data)
        
        seq += 20
        
        # Pattern 2: Overlapping segments
        base_seq = seq
        for i in range(10):
            # Create segments that overlap by 2 bytes
            overlap_seq = base_seq + (i*3)
            data = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                             seq=overlap_seq, ack=server_seq)/Raw(load=f"ABCDE{i}")
            packets.append(data)
        
        seq = base_seq + 40
        
        # Pattern 3: Out-of-sequence delivery
        segments = []
        for i in range(10):
            out_seq = seq + (9-i)*10  # Reversed order
            data = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                             seq=out_seq, ack=server_seq)/Raw(load=f"OUT{i}")
            segments.append(data)
        
        # Add them in reverse
        packets.extend(segments)
        seq += 100
        
        # Server acknowledges
        server_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="A", 
                                                seq=server_seq, ack=seq)
        packets.append(server_ack)
        
        # Pattern 4: Send another trigger with a gap
        trigger2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA", 
                                             seq=seq+50, ack=server_seq)/Raw(load="TRIGGER_FLUSH")
        packets.append(trigger2)
        
        # Pattern 5: Send reset to abruptly end the session
        rst = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="R", seq=seq+100)
        packets.append(rst)
    
    # Interleave all the packets to maximize processing complexity
    random.shuffle(packets)
    
    wrpcap("complex_tcp_test.pcap", packets)
    print(f"Created complex TCP test PCAP with {len(packets)} packets")

if __name__ == "__main__":
    create_complex_tcp_pcap()
