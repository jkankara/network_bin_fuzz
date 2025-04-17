#!/usr/bin/python3

import pyshark
import sys
import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
limit_pkts = 20000

def extract_ipv4_headers(packet):
    """
    Function to extract IPv4 (Layer 3) headers from a packet.

    Args:
        packet (pyshark.packet.packet.Packet): A single packet from the pcap file.

    Returns:
        dict: Contains IPv4 header information.
    """
    ip_header = "N/A"
    try:
        if hasattr(packet, 'ip'):
            ip_header = {
                'Source IP': packet.ip.src,
                'Destination IP': packet.ip.dst,
                'Version': packet.ip.version,
                'Header Length': packet.ip.hdr_len,
                'Total Length': packet.ip.len,
                'Identification': packet.ip.id,
                'Flags': packet.ip.flags,
                'Fragment Offset': packet.ip.frag_offset,
                'Time to Live': packet.ip.ttl,
                'Protocol': packet.ip.proto,
                'Header Checksum': packet.ip.checksum
            }
        else:
            ip_header = 'N/A'
    except:
        print("not a ethernet packet", packet) 
    return ip_header

def main(file_path):
    """
    Main function to read a pcap file and store IPv4 headers in a DataFrame.

    Args:
        file_path (str): Path to the pcap file.
    """
    global limit_pkts
    cap = pyshark.FileCapture(file_path)
    
    # Create an empty DataFrame
    df = pd.DataFrame(columns=['Source IP', 'Destination IP', 'Version', 'Header Length', 'Total Length',
                               'Identification', 'Flags', 'Fragment Offset', 'Time to Live', 'Protocol', 'Header Checksum'])
    
    # Extract headers and store in DataFrame
    for packet in cap:
        ip_header = extract_ipv4_headers(packet)
        if ip_header != 'N/A':
            df = pd.concat([df, pd.DataFrame([ip_header])], ignore_index=True)
            limit_pkts -= 1
            if limit_pkts == 0: break

    
    # Print the DataFrame
    print(df)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
    else:
        file_path = sys.argv[1]
        main(file_path)

#import pyshark
#import sys
#
#def extract_ipv4_headers(packet):
#    """
#    Function to extract IPv4 (Layer 3) headers from a packet.
#
#    Args:
#        packet (pyshark.packet.packet.Packet): A single packet from the pcap file.
#
#    Returns:
#        dict: Contains IPv4 header information.
#    """
#    if hasattr(packet, 'ip'):
#        ip_header = {
#            'Source IP': packet.ip.src,
#            'Destination IP': packet.ip.dst,
#            'Version': packet.ip.version,
#            'Header Length': packet.ip.hdr_len,
#            'Total Length': packet.ip.len,
#            'Identification': packet.ip.id,
#            'Flags': packet.ip.flags,
#            'Fragment Offset': packet.ip.frag_offset,
#            'Time to Live': packet.ip.ttl,
#            'Protocol': packet.ip.proto,
#            'Header Checksum': packet.ip.checksum
#        }
#    else:
#        ip_header = 'N/A'
#    return ip_header
#
#def main(file_path):
#    """
#    Main function to read a pcap file and print IPv4 headers in tabular form.
#
#    Args:
#        file_path (str): Path to the pcap file.
#    """
#    cap = pyshark.FileCapture(file_path)
#
#    # Print headers in tabular form
#    print("{:<15} {:<15} {:<10} {:<15} {:<12} {:<15} {:<10} {:<18} {:<10} {:<10}".format(
#        'Source IP', 'Destination IP', 'Version', 'Header Length', 'Total Length',
#        'Identification', 'Flags', 'Fragment Offset', 'Time to Live', 'Protocol', 'Header Checksum'))
#    print("="*160)
#
#    for packet in cap:
#        ip_header = extract_ipv4_headers(packet)
#        if ip_header != 'N/A':
#            print("{:<15} {:<15} {:<10} {:<15} {:<12} {:<15} {:<10} {:<18} {:<10} {:<10} {:<15}".format(
#                ip_header['Source IP'],
#                ip_header['Destination IP'],
#                ip_header['Version'],
#                ip_header['Header Length'],
#                ip_header['Total Length'],
#                ip_header['Identification'],
#                ip_header['Flags'],
#                ip_header['Fragment Offset'],
#                ip_header['Time to Live'],
#                ip_header['Protocol'],
#                ip_header['Header Checksum']
#            ))
#        else:
#            print("No IPv4 header found in this packet.")
#
#if __name__ == "__main__":
#    if len(sys.argv) != 2:
#        print("Usage: python script.py <file_path>")
#    else:
#        file_path = sys.argv[1]
#        main(file_path)
