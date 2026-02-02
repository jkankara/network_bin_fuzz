#!/usr/bin/python3 -tt
# coding=utf-8
#
# Alternative: Create PCAP from hex payload only (no dependencies on bbuzz)

from binascii import unhexlify
import struct
import time

def create_pcap_from_hex(hex_payload, output_file='replay.pcap', 
                         src_ip='192.168.1.1', dst_ip='192.168.1.2',
                         src_port=5000, dst_port=5000, protocol='udp'):
    """
    Create a basic PCAP file from hex payload
    
    Args:
        hex_payload: Hex string of the payload (e.g., '1fda0000e6a7')
        output_file: Output pcap filename
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port (for UDP/TCP)
        dst_port: Destination port (for UDP/TCP)
        protocol: 'udp' or 'tcp' or 'raw' (raw IP)
    """
    
    # Convert hex to bytes
    payload_bytes = unhexlify(hex_payload)
    
    # PCAP Global Header
    pcap_global_header = struct.pack('IHHiIII',
        0xa1b2c3d4,  # Magic number
        2,           # Major version
        4,           # Minor version
        0,           # GMT offset
        0,           # Accuracy of timestamps
        65535,       # Max packet length
        1            # Data link type (Ethernet)
    )
    
    # Build the packet based on protocol
    if protocol.lower() == 'udp':
        packet = build_udp_packet(payload_bytes, src_ip, dst_ip, src_port, dst_port)
    elif protocol.lower() == 'tcp':
        packet = build_tcp_packet(payload_bytes, src_ip, dst_ip, src_port, dst_port)
    else:  # raw
        packet = build_ethernet_frame(payload_bytes)
    
    # PCAP Packet Header
    timestamp = int(time.time())
    pcap_packet_header = struct.pack('IIII',
        timestamp,           # Timestamp seconds
        0,                   # Timestamp microseconds
        len(packet),         # Number of octets saved
        len(packet)          # Actual packet length
    )
    
    # Write PCAP file
    with open(output_file, 'wb') as f:
        f.write(pcap_global_header)
        f.write(pcap_packet_header)
        f.write(packet)
    
    print(f"[+] PCAP created: {output_file}")
    print(f"[+] Payload: {hex_payload}")
    print(f"[+] Length: {len(payload_bytes)} bytes")
    print(f"[+] Protocol: {protocol.upper()}")
    print(f"[+] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    print(f"\n[+] Replay with:")
    print(f"    tcpreplay -i <interface> {output_file}")
    print(f"    or")
    print(f"    tcpreplay --topspeed -i <interface> {output_file}")

def ip_to_bytes(ip):
    """Convert IP string to bytes"""
    return b''.join(int(x).to_bytes(1, 'big') for x in ip.split('.'))

def calculate_checksum(data):
    """Calculate IP/UDP/TCP checksum"""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_ethernet_frame(payload):
    """Build basic Ethernet frame"""
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
    src_mac = b'\x00\x00\x00\x00\x00\x01'
    ethertype = b'\x08\x00'  # IPv4
    return dst_mac + src_mac + ethertype + payload

def build_ip_header(payload_len, protocol, src_ip, dst_ip):
    """Build IPv4 header"""
    version_ihl = 0x45  # Version 4, IHL 5
    tos = 0
    total_len = 20 + payload_len
    identification = 54321
    flags_fragment = 0
    ttl = 64
    
    # Build header without checksum
    header = struct.pack('!BBHHHBBH',
        version_ihl, tos, total_len, identification,
        flags_fragment, ttl, protocol, 0  # checksum=0 for now
    )
    header += ip_to_bytes(src_ip)
    header += ip_to_bytes(dst_ip)
    
    # Calculate and insert checksum
    checksum = calculate_checksum(header)
    header = header[:10] + struct.pack('!H', checksum) + header[12:]
    
    return header

def build_udp_packet(payload, src_ip, dst_ip, src_port, dst_port):
    """Build UDP packet with Ethernet + IP + UDP headers"""
    
    # UDP header
    udp_len = 8 + len(payload)
    udp_header = struct.pack('!HHHH',
        src_port,
        dst_port,
        udp_len,
        0  # Checksum (optional for IPv4, can be 0)
    )
    
    # IP header (protocol 17 = UDP)
    ip_header = build_ip_header(len(udp_header) + len(payload), 17, src_ip, dst_ip)
    
    # Ethernet frame
    ethernet = build_ethernet_frame(ip_header + udp_header + payload)
    
    return ethernet

def build_tcp_packet(payload, src_ip, dst_ip, src_port, dst_port):
    """Build TCP packet with Ethernet + IP + TCP headers"""
    
    # TCP header (simplified - no options)
    tcp_header = struct.pack('!HHIIBBHHH',
        src_port,       # Source port
        dst_port,       # Destination port
        0,              # Sequence number
        0,              # Acknowledgment number
        0x50,           # Data offset (5) + reserved
        0x02,           # Flags (SYN)
        8192,           # Window size
        0,              # Checksum (calculated later)
        0               # Urgent pointer
    )
    
    # IP header (protocol 6 = TCP)
    ip_header = build_ip_header(len(tcp_header) + len(payload), 6, src_ip, dst_ip)
    
    # Ethernet frame
    ethernet = build_ethernet_frame(ip_header + tcp_header + payload)
    
    return ethernet

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python create_pcap.py <hex_payload> [options]")
        print("\nOptions:")
        print("  -o <file>         Output pcap file (default: replay.pcap)")
        print("  --src-ip <ip>     Source IP (default: 192.168.1.1)")
        print("  --dst-ip <ip>     Destination IP (default: 192.168.1.2)")
        print("  --src-port <port> Source port (default: 5000)")
        print("  --dst-port <port> Destination port (default: 5000)")
        print("  --protocol <type> Protocol: udp, tcp, or raw (default: udp)")
        print("\nExample:")
        print("  python create_pcap.py 1fda0000e6a7")
        print("  python create_pcap.py 1fda0000e6a7 -o test.pcap --dst-ip 10.0.0.1 --dst-port 8080")
        sys.exit(1)
    
    hex_payload = sys.argv[1].replace(" ", "").replace("0x", "")
    
    # Parse arguments
    output_file = 'replay.pcap'
    src_ip = '192.168.1.1'
    dst_ip = '192.168.1.2'
    src_port = 5000
    dst_port = 5000
    protocol = 'udp'
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-o':
            output_file = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--src-ip':
            src_ip = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--dst-ip':
            dst_ip = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == '--src-port':
            src_port = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == '--dst-port':
            dst_port = int(sys.argv[i+1])
            i += 2
        elif sys.argv[i] == '--protocol':
            protocol = sys.argv[i+1]
            i += 2
        else:
            i += 1
    
    create_pcap_from_hex(hex_payload, output_file, src_ip, dst_ip, 
                         src_port, dst_port, protocol)
