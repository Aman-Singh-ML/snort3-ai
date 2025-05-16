from scapy.all import *

def create_overlapping_segments_pcap():
    # Set up flow identifiers
    client_ip = "10.1.1.2"
    server_ip = "10.1.1.1"
    client_port = 12345
    server_port = 80
    
    # TCP handshake
    syn = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S", seq=100)
    synack = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=500, ack=101)
    ack = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=101, ack=501)
    
    # Create multiple overlapping segments
    # These all cover parts of the same data range
    seg1 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=101, ack=501)/"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    seg2 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=105, ack=501)/"EFGHIJKLMNOPQRSTUVWXYZ1234"
    seg3 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=110, ack=501)/"JKLMNOPQRSTUVWXYZ12345678"
    seg4 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=103, ack=501)/"CDEFGHIJKLMNOPQRSTUVWXYZ12"
    seg5 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=107, ack=501)/"GHIJKLMNOPQRSTUVWXYZ1234"
    seg6 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=115, ack=501)/"OPQRSTUVWXYZ12345678"
    seg7 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=102, ack=501)/"BCDEFGHIJKLMNOPQRSTUVWXY"
    
    # Create a normal closing sequence
    fin = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="FA", seq=130, ack=501)
    finack = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="FA", seq=501, ack=131)
    lastack = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=131, ack=502)
    
    packets = [syn, synack, ack, seg1, seg2, seg3, seg4, seg5, seg6, seg7, fin, finack, lastack]
    wrpcap("tcp_overlap_issue.pcap", packets)
    print("Created tcp_overlap_issue.pcap")

create_overlapping_segments_pcap()
