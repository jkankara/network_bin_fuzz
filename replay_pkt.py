#!/usr/bin/python3 -tt
# coding=utf-8
#
# Replay a specific packet from hex payload

import sys
import os
import json
from binascii import unhexlify

# Add protocols directory to path to import bbuzz
script_dir = os.path.dirname(os.path.abspath(__file__))
protocols_dir = os.path.join(script_dir, 'protocols')
sys.path.insert(0, protocols_dir)

import bbuzz

def replay_packet(hex_payload, config_file='config.json'):
    """
    Replay a packet from hex dump
    
    Args:
        hex_payload: Hex string of the payload (e.g., '1fda0000e6a7')
        config_file: Path to config.json file
    """
    
    # Load configuration
    with open(config_file, 'r') as file:
        config = json.load(file)
    
    # Define the protocol connection (adjust based on your protocol)
    # Example for UDP/IPv4 - modify according to your needs
    proto = bbuzz.protocol.Protocol(
        'raw3',
        {
            "SOURCE_IP": config["srcip4"],
            "DESTINATION_IP": config["dstip4"],
            "IP_VERSION": config["ipver4"],
            "PROTO": config["l4proto_udp_num"],
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"]
        }
    )
    
    proto.create(config["interface"], config["l4proto_udp_num"])
    
    # Convert hex to bytes
    payload_bytes = unhexlify(hex_payload)
    
    print(f"[+] Replaying packet: {hex_payload}")
    print(f"[+] Payload length: {len(payload_bytes)} bytes")
    print(f"[+] Destination: {config['dstip4']}")
    
    # Send the packet
    proto.send(payload_bytes)
    print("[+] Packet sent!")
    
    proto.kill()

def create_pcap_from_hex(hex_payload, output_file='replay.pcap'):
    """
    Create a PCAP file from hex payload using scapy
    
    Args:
        hex_payload: Hex string of the payload
        output_file: Output pcap filename
    """
    try:
        from scapy.all import wrpcap, Raw, IP, UDP
        
        # Convert hex to bytes
        payload_bytes = unhexlify(hex_payload)
        
        # Create packet - adjust layers as needed
        # This is a basic example - modify based on your protocol
        packet = IP()/UDP()/Raw(load=payload_bytes)
        
        # Write to pcap
        wrpcap(output_file, packet)
        print(f"[+] PCAP file created: {output_file}")
        print(f"[+] You can replay with: tcpreplay -i <interface> {output_file}")
        
    except ImportError:
        print("[-] Scapy not installed. Install with: pip install scapy")
        print("[!] Falling back to raw hex replay only")

if __name__ == "__main__":
    if len(sys.argv) < 2 or '--help' in sys.argv or '-h' in sys.argv:
        print("=" * 70)
        print("REPLAY PACKET - Replay network fuzzing payloads")
        print("=" * 70)
        print("\nDESCRIPTION:")
        print("  Replays a specific packet from its hex payload dump.")
        print("  Useful for reproducing issues found during fuzzing.")
        print("  Can also create PCAP files for analysis with Wireshark/tcpreplay.")
        print("\nUSAGE:")
        print("  python replay_packet.py <hex_payload> [config_file] [options]")
        print("\nARGUMENTS:")
        print("  hex_payload    Hexadecimal string of the payload to replay")
        print("                 Spaces and '0x' prefixes are automatically removed")
        print("                 Example: 1fda0000e6a7 or 1f da 00 00 e6 a7")
        print("\n  config_file    Path to JSON config file (default: config.json)")
        print("                 Must contain: srcip4, dstip4, srcmac, dstmac,")
        print("                 interface, ipver4, l4proto_udp_num")
        print("\nOPTIONS:")
        print("  --pcap <file>  Also create a PCAP file with the given filename")
        print("                 Default filename: replay.pcap")
        print("                 Requires scapy: pip install scapy")
        print("\n  --help, -h     Display this help message")
        print("\nEXAMPLES:")
        print("  # Basic replay with default config.json")
        print("  python replay_packet.py 1fda0000e6a7")
        print("\n  # Replay with custom config file")
        print("  python replay_packet.py 1fda0000e6a7 my_config.json")
        print("\n  # Replay and create PCAP file")
        print("  python replay_packet.py 1fda0000e6a7 --pcap issue_packet.pcap")
        print("\n  # With spaces in hex (will be removed automatically)")
        print("  python replay_packet.py \"1f da 00 00 e6 a7\"")
        print("\nWORKFLOW:")
        print("  1. Run fuzzer and observe logs with timestamps:")
        print("     [2026-02-02 23:05:06.102] Payload hex: 1fda0000e6a7")
        print("\n  2. If an issue occurs, copy the hex payload")
        print("\n  3. Replay the exact packet:")
        print("     python replay_packet.py 1fda0000e6a7")
        print("\n  4. Or create PCAP for detailed analysis:")
        print("     python replay_packet.py 1fda0000e6a7 --pcap debug.pcap")
        print("     wireshark debug.pcap")
        print("     tcpreplay -i eth0 debug.pcap")
        print("\nNOTES:")
        print("  - Requires root/admin privileges for raw socket access")
        print("  - Ensure config.json matches your network setup")
        print("  - The protocol type is determined by the config file settings")
        print("  - Currently configured for UDP/IPv4 (modify script for other protocols)")
        print("\nCONFIG FILE FORMAT:")
        print("  {")
        print("    \"srcip4\": \"192.168.1.10\",")
        print("    \"dstip4\": \"192.168.1.100\",")
        print("    \"srcmac\": \"00:11:22:33:44:55\",")
        print("    \"dstmac\": \"aa:bb:cc:dd:ee:ff\",")
        print("    \"interface\": \"eth0\",")
        print("    \"ipver4\": \"4\",")
        print("    \"l4proto_udp_num\": \"17\"")
        print("  }")
        print("=" * 70)
        sys.exit(0 if '--help' in sys.argv or '-h' in sys.argv else 1)
    
    hex_payload = sys.argv[1].replace(" ", "").replace("0x", "")
    config_file = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else 'config.json'
    
    # Check for pcap creation flag
    if '--pcap' in sys.argv:
        pcap_idx = sys.argv.index('--pcap')
        pcap_file = sys.argv[pcap_idx + 1] if len(sys.argv) > pcap_idx + 1 else 'replay.pcap'
        create_pcap_from_hex(hex_payload, pcap_file)
    
    # Replay the packet
    replay_packet(hex_payload, config_file)

