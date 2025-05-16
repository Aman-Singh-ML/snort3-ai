from scapy.all import *

def create_test_pcap():
    # Create a normal TCP session
    client_ip = "10.1.1.2"
    server_ip = "10.1.1.1"
    client_port = 12345
    server_port = 80
    
    # Regular TCP 3-way handshake
    syn = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S", seq=100)
    synack = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=500, ack=101)
    ack = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=101, ack=501)
    
    # Data transfer
    data1 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=101, ack=501)/"GET / HTTP/1.1\r\n\r\n"
    
    # Create an IP packet with a corrupted TCP header
    # This packet will cause confusion in the TCP state machine
    # It has the basic structure of TCP but will fail deeper validation
    malformed = IP(src=client_ip, dst=server_ip)
    
    # This raw data has a corrupted TCP header structure
    corrupted_header = bytes([
        0x30, 0x39,             # Source port (12345)
        0x00, 0x50,             # Destination port (80)
        0x00, 0x00, 0x00, 0x65, # Sequence number (corrupted)
        0x00, 0x00, 0x01, 0xF5, # ACK number (501)
        0x20, 0x00,             # Data offset (8) + Reserved bits (0)
        0x00, 0x00,             # Window size (0)
        0x00, 0x00,             # Checksum (0)
        0x00, 0x00              # Urgent pointer (0)
    ])
    
    malformed = malformed/Raw(load=corrupted_header + b"AAAA")
    
    # Valid packet after the malformed one - triggers restart
    data2 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=120, ack=501)
    
    # Write the PCAP
    packets = [syn, synack, ack, data1, malformed, data2]
    wrpcap("tcp_restart_issue.pcap", packets)
    print("Created tcp_restart_issue.pcap")

create_test_pcap()
