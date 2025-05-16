from scapy.all import *

def create_malformed_tcp_pcap():
    # Create a normal TCP handshake
    ip1 = IP(src="192.168.1.100", dst="192.168.1.200")
    syn = ip1/TCP(sport=12345, dport=80, flags="S", seq=100)
    synack = IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA", seq=500, ack=101)
    ack = IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="A", seq=101, ack=501)
    
    # Normal data packets
    data1 = IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="PA", seq=101, ack=501)/"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
    data2 = IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="PA", seq=501, ack=130)/"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
    
    # Create a malformed packet that looks like TCP but has issues
    # This is a non-standard packet that might confuse Snort's TCP processing
    malformed = IP(src="192.168.1.100", dst="192.168.1.200")
    
    # Add raw data that looks like a TCP header but is corrupted
    # This is intended to pass basic protocol checks but fail deeper inspection
    corrupted_tcp_data = bytes([0x30, 0x39, 0x00, 0x50,  # Source port, dest port 
                               0x00, 0x00, 0x00, 0x65,  # Sequence number (corrupted)
                               0x00, 0x00, 0x00, 0x00,  # ACK number (zeros)
                               0x50, 0x00, 0x00, 0x00,  # Header length + flags (corrupted)
                               0x00, 0x00, 0x00, 0x00]) # Rest of header zeros
    
    # Packet with corrupted TCP header
    malformed = malformed/Raw(load=corrupted_tcp_data)
    
    # More valid packets after the malformed one 
    # These force Snort to try to reconcile the session
    data3 = IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="A", seq=130, ack=551)
    data4 = IP(src="192.168.1.200", dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="FA", seq=551, ack=130)
    data5 = IP(src="192.168.1.100", dst="192.168.1.200")/TCP(sport=12345, dport=80, flags="FA", seq=130, ack=552)
    
    # Write the PCAP
    packets = [syn, synack, ack, data1, data2, malformed, data3, data4, data5]
    wrpcap("tcp_restart_issue.pcap", packets)
    print("Created tcp_restart_issue.pcap with malformed TCP packet")

create_malformed_tcp_pcap()
