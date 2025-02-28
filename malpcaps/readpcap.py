#!/usr/bin/python3



import pyshark
import sys

def extract_ipv6_headers(packet):
    """
    Function to extract IPv6 (Layer 3) headers from a packet.

    Args:
        packet (pyshark.packet.packet.Packet): A single packet from the pcap file.

    Returns:
        dict: Contains IPv6 header information.
    """
    if hasattr(packet, 'ipv6'):
        ipv6_header = {
            'Source IP': packet.ipv6.src,
            'Destination IP': packet.ipv6.dst,
            'Version': packet.ipv6.version
        }

        if hasattr(packet.ipv6, 'traffic_class'):
            ipv6_header['Traffic Class'] = packet.ipv6.traffic_class
        else:
            ipv6_header['Traffic Class'] = 'N/A'

        if hasattr(packet.ipv6, 'flow_label'):
            ipv6_header['Flow Label'] = packet.ipv6.flow_label
        else:
            ipv6_header['Flow Label'] = 'N/A'

        if hasattr(packet.ipv6, 'payload_length'):
            ipv6_header['Payload Length'] = packet.ipv6.payload_length
        else:
            ipv6_header['Payload Length'] = 'N/A'

        if hasattr(packet.ipv6, 'next_header'):
            ipv6_header['Next Header'] = packet.ipv6.next_header
        else:
            ipv6_header['Next Header'] = 'N/A'

        if hasattr(packet.ipv6, 'hop_limit'):
            ipv6_header['Hop Limit'] = packet.ipv6.hop_limit
        else:
            ipv6_header['Hop Limit'] = 'N/A'
    else:
        ipv6_header = 'N/A'
    return ipv6_header

def main(file_path):
    """
    Main function to read a pcap file and print IPv6 headers in tabular form.

    Args:
        file_path (str): Path to the pcap file.
    """
    cap = pyshark.FileCapture(file_path)

    # Print headers in tabular form
    print("{:<40} {:<40} {:<10} {:<15} {:<12} {:<15} {:<12} {:<10}".format(
        'Source IP', 'Destination IP', 'Version', 'Traffic Class', 'Flow Label',
        'Payload Length', 'Next Header', 'Hop Limit'))
    print("="*160)

    for packet in cap:
        ipv6_header = extract_ipv6_headers(packet)
        if ipv6_header != 'N/A':
            print("{:<40} {:<40} {:<10} {:<15} {:<12} {:<15} {:<12} {:<10}".format(
                ipv6_header['Source IP'],
                ipv6_header['Destination IP'],
                ipv6_header['Version'],
                ipv6_header['Traffic Class'],
                ipv6_header['Flow Label'],
                ipv6_header['Payload Length'],
                ipv6_header['Next Header'],
                ipv6_header['Hop Limit']
            ))
        else:
            print("No IPv6 header found in this packet.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
    else:
        file_path = sys.argv[1]
        main(file_path)
