from scapy.all import *

def create_queue_limit_pcap():
    client_ip = "10.1.1.2"
    server_ip = "10.1.1.1"
    client_port = 12345
    server_port = 80
    
    # TCP handshake
    syn = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S", seq=100)
    synack = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=500, ack=101)
    ack = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=101, ack=501)
    
    packets = [syn, synack, ack]
    
    # Create segments with gaps to force queue retention
    base_seq = 101
    for i in range(20):
        # Skip some sequence numbers to create gaps
        base_seq += 10
        data = "Packet-%d-ABCDEFGHIJKLMNOP" % i
        pkt = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, 
                flags="PA", seq=base_seq, ack=501)/data
        packets.append(pkt)
        base_seq += len(data)
    
    wrpcap("tcp_queue_limit.pcap", packets)
    print("Created tcp_queue_limit.pcap")

create_queue_limit_pcap()
