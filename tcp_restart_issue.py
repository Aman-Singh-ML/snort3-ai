from scapy.all import *

def create_advanced_test_pcap():
    # Create a TCP session with specific flow characteristics
    client_ip = "10.1.1.2"
    server_ip = "10.1.1.1"
    client_port = 12345
    server_port = 80
    
    # Regular TCP 3-way handshake
    syn = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S", seq=100)
    synack = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=500, ack=101)
    ack = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=101, ack=501)
    
    # Send some data to establish the session firmly
    data1 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=101, ack=501)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    data2 = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=501, ack=140)/"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
    
    # Create a packet with our TCP session flow identifiers but incorrect IP protocol
    # This should be parsed initially as part of the flow but might fail TCP validation
    weird_proto = IP(src=client_ip, dst=server_ip, proto=253)/Raw(load=b"\x30\x39\x00\x50" + b"\x00"*16)
    
    # Create out-of-order packets to force reassembly
    ooo1 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=160, ack=546)/"THIRD"
    ooo2 = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=140, ack=546)/"SECOND"
    
    # Create a packet that looks like a retransmission but with slightly corrupted flags
    # This specifically targets potential restart() triggers
    retrans = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="AR", seq=101, ack=501)/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    # Create a valid-looking but malformed TCP packet (wrong checksum, unusual flags)
    mal_tcp = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, seq=140, ack=546, flags="FSRPAU", chksum=0xdead)/"MALFORMED"
    
    # Craft a packet that looks like an ICMP error related to our TCP flow
    # This can sometimes be processed in the context of the TCP session
    icmp_error = IP(src=server_ip, dst=client_ip)/ICMP(type=3, code=3)/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=140, ack=546)
    
    # Now create a packet that has the right IP addresses but with a completely malformed TCP header
    # This is more likely to be associated with the flow but fail TCP parsing
    tcp_malformed = IP(src=client_ip, dst=server_ip, proto=6)
    tcp_malformed = tcp_malformed/Raw(load=bytes([
        0x30, 0x39,             # Source port (12345)
        0x00, 0x50,             # Destination port (80)
        0x00, 0x00, 0x00, 0x8C, # Seq number (140)
        0x00, 0x00, 0x02, 0x22, # Ack number (546)
        0x10, 0x00,             # INVALID data offset (0x10 = 16 x 4 = 64 bytes - too large!)
        0xFF, 0xFF,             # Window size (impossible)
        0x00, 0x00,             # Checksum (0)
        0x00, 0x00              # Urgent pointer (0)
    ]) + b"\x00" * 20)          # Some payload to confuse things further
    
    # Valid packet after all the confusion - forces state reconciliation
    # This is the packet most likely to cause restart() to be called
    recovery = IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=165, ack=546)
    
    # Final normal packet to force session state updates
    final = IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="A", seq=546, ack=165)
    
    # Assemble all packets in a sequence designed to maximize chaos and edge cases
    packets = [
        syn, synack, ack,                 # Normal handshake
        data1, data2,                     # Normal data flow
        weird_proto,                      # Strange protocol
        ooo1,                             # Out of order
        tcp_malformed,                    # Malformed TCP with valid IP
        ooo2,                             # More out of order
        retrans,                          # Retransmission-like
        mal_tcp,                          # TCP with bad flags/checksum
        icmp_error,                       # ICMP error related to flow
        recovery,                         # Valid packet to trigger restart()
        final                             # Final packet
    ]
    
    wrpcap("tcp_advanced_restart_issue.pcap", packets)
    print("Created tcp_advanced_restart_issue.pcap with advanced test cases")

create_advanced_test_pcap()
